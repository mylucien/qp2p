package com.qp2p

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import org.json.JSONObject

/**
 * 把 VpnService 建出来的接口交给 Rust 内核。
 *
 * 顺序不能颠倒：先 prepare 拿虚拟地址，再用它建接口，最后把 fd 交给 start。
 * 配置（地址、路由、MTU）全在系统侧，Rust 只负责收发 IP 包。
 *
 * 状态是**结构化**的：界面按 `phase` 决定颜色和图标，按 `detail` / `advice`
 * 显示告警正文与建议。不用弹窗——手机被 VPN 掐断时用户往往不在界面上，
 * 弹窗既拦不住问题，也会把正在做的事打断；告警要一直留在界面上直到恢复。
 */
class Qp2pVpnService : VpnService() {

    /** 界面用的一眼可辨的阶段。 */
    enum class Phase {
        /** 没连、也不在连（刚打开 App、或主动断开） */
        IDLE,

        /** 正在注册 / 建隧道 */
        CONNECTING,

        /** 隧道已建好，内核在收发 */
        CONNECTED,

        /** 出错了，`detail` 是原因、`advice` 是接下来该做什么 */
        ERROR,
    }

    companion object {
        const val ACTION_CONNECT = "com.qp2p.CONNECT"
        const val ACTION_DISCONNECT = "com.qp2p.DISCONNECT"
        const val EXTRA_CONFIG = "config"
        private const val CHANNEL = "qp2p-vpn"
        private const val NOTIFICATION_ID = 1

        // 跨线程读写的状态：Service 在后台线程写，界面在主线程每 500ms 读一次。
        // 每个字段各自 @Volatile 就够——它们只用于显示，不参与逻辑判断。
        @Volatile
        var phase: Phase = Phase.IDLE
            private set

        /** 一行摘要：已连接 10.78.0.2 / 正在注册… / 令牌被拒绝…… */
        @Volatile
        var detail: String = "未连接"
            private set

        /** 出错时给用户看的下一步；正常时为空 */
        @Volatile
        var advice: String = ""
            private set

        /** 连上之后填，界面显示地址与网段 */
        @Volatile
        var virtualIp: String = ""
            private set

        @Volatile
        var cidr: String = ""
            private set

        /** 本次连接建立的时刻（毫秒），用于显示在线时长；0 表示没连 */
        @Volatile
        var connectedAt: Long = 0L
            private set

        /** 这次连接用的是哪种省电策略，通知栏和界面都要说清楚 */
        @Volatile
        var keepOnline: Boolean = false
            private set

        @Volatile
        var idleMinutes: Int = 10
            private set

        /** 上次注册拿到的网段（如 10.78.0.0/16），界面用它提示可填的 IP 范围 */
        @Volatile
        var lastCidr: String = ""

        /** 兼容旧调用点：连接中且没有错误才算连上 */
        val connected: Boolean
            get() = phase == Phase.CONNECTED

        private fun setState(p: Phase, text: String, hint: String = "") {
            detail = text
            advice = hint
            phase = p
            if (p != Phase.CONNECTED) {
                connectedAt = 0L
            }
        }

        fun markError(text: String, hint: String) {
            setState(Phase.ERROR, text, hint)
        }

        /** 过渡态（正在断开）：既不是连接中，也不该报错 */
        fun markIdle(text: String) {
            setState(Phase.IDLE, text)
        }
    }

    private var tun: ParcelFileDescriptor? = null
    private var worker: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // 任何异常都要变成界面上的文字，不能让进程崩掉——
        // 崩一次用户就再也不敢点了，而且拿不到原因
        return try {
            handleStart(intent)
        } catch (t: Throwable) {
            setState(
                Phase.ERROR,
                "启动失败：${t.javaClass.simpleName}",
                t.message ?: "详情见 logcat 里 qp2p 标记的日志",
            )
            stopSelf()
            START_NOT_STICKY
        }
    }

    private fun handleStart(intent: Intent?): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                Native.stop()
                return START_NOT_STICKY
            }
        }

        // 「启动连接」可能在 App 重新打开时重复拉起服务；已有会话就别开第二条隧道
        if (intent?.action == ACTION_CONNECT &&
            (phase == Phase.CONNECTED || phase == Phase.CONNECTING)
        ) {
            return START_STICKY
        }

        val config = intent?.getStringExtra(EXTRA_CONFIG)
        if (config.isNullOrBlank()) {
            setState(Phase.ERROR, "缺少配置", "回到 App 里重新点一次连接")
            stopSelf()
            return START_NOT_STICKY
        }

        // 直连保持档位在启动时定下来：改档位要重连才生效，界面会提示
        runCatching {
            val json = JSONObject(config)
            keepOnline = json.optBoolean("keep_online", false)
            idleMinutes = (json.optLong("idle_secs", 600L) / 60L).toInt().coerceAtLeast(1)
        }

        // 前台服务只是"别被系统杀掉"的作用，起不来也不该影响隧道本身
        try {
            ensureChannel()
            startForeground(NOTIFICATION_ID, notification("正在连接…"))
        } catch (t: Throwable) {
            logLine("startForeground 失败: ${t.message}")
        }

        worker = Thread({ runTunnel(config) }, "qp2p-vpn").also { it.start() }
        return START_STICKY
    }

    private fun logLine(message: String) {
        android.util.Log.w("qp2p", message)
    }

    private fun runTunnel(config: String) {
        try {
            // 分阶段报状态：注册和建隧道都可能卡上几秒，只写"正在连接"看不出卡在哪
            setState(Phase.CONNECTING, "正在注册…")
            val prepared = Native.prepare(config)
            val info = JSONObject(prepared)
            if (info.has("error")) {
                val d = diagnose(info.optString("error"))
                setState(Phase.ERROR, d.first, d.second)
                return
            }

            val ip = info.getString("virtual_ip")
            val prefix = info.getInt("prefix")
            val mtu = info.getInt("mtu")
            val cidrText = info.getString("cidr")
            lastCidr = cidrText
            cidr = cidrText
            val cidr = cidrText.substringBefore("/")

            val builder = Builder()
                .setSession("qp2p")
                .setMtu(mtu)
                .addAddress(ip, prefix)
                // 只接管虚拟网段：公网、局域网照旧走系统路由，不会把整机流量带走
                .addRoute(cidr, prefix)
                .setBlocking(true)
            // 自己的信令/打洞流量绝不进隧道，否则会绕成死循环
            try {
                builder.addDisallowedApplication(packageName)
            } catch (_: Exception) {
                // 个别 ROM 上不支持，忽略即可：目标地址不在路由表里，本来也不会进隧道
            }

            setState(Phase.CONNECTING, "正在建立隧道…")
            val pfd = builder.establish() ?: run {
                setState(
                    Phase.ERROR,
                    "系统没批准建 VPN",
                    "可能被别的 VPN 占用，或授权被撤销；在系统设置里关掉其它 VPN 后重试",
                )
                return
            }
            tun = pfd

            virtualIp = ip
            setState(Phase.CONNECTED, "已连接 $ip")
            connectedAt = System.currentTimeMillis()
            updateNotification(onlineText(ip, cidr))

            val err = Native.start(pfd.fd)
            if (err != null) {
                val d = diagnose(err)
                setState(Phase.ERROR, "已断开：${d.first}", d.second)
            } else {
                setState(Phase.IDLE, "已断开")
            }
        } catch (e: Throwable) {
            val d = diagnose(e.message ?: e.javaClass.simpleName)
            setState(Phase.ERROR, d.first, d.second)
        } finally {
            try {
                tun?.close()
            } catch (_: Exception) {
            }
            tun = null
            connectedAt = 0L
            virtualIp = ""
            stopForeground(true)
            stopSelf()
        }
    }

    /** 通知栏那一行：连上之后要说清是"保持在线"还是"空闲多久断"。 */
    private fun onlineText(ip: String, cidr: String): String {
        val power = if (keepOnline) "保持在线" else "空闲 $idleMinutes 分钟断链"
        return "已连接 $ip（$cidr）· $power"
    }

    /**
     * 把内核 / 服务端的错误翻成「原因 + 下一步」。
     *
     * 不认识的错误原样带出去——猜错原因比报原文更误导人。
     */
    private fun diagnose(raw: String): Pair<String, String> = when {
        raw.contains("invalid_token") || raw.contains("401") ->
            "令牌格式不对" to "检查是否复制完整，令牌应以 qp2p1_ 开头"

        raw.contains("wrong_secret") || raw.contains("invalid_join_key") || raw.contains("403") ->
            "令牌被拒绝" to "网络可能已被删除，或密钥已更换；找管理员要新令牌"

        raw.contains("network_not_found") || raw.contains("404") ->
            "网络不存在" to "确认这个令牌属于哪个网络，以及信令地址是否对应"

        raw.contains("virtual_ip_reserved") ->
            "这个虚拟 IP 已被别的节点预留" to "换一个地址，或让管理员在管理页释放该预留"

        raw.contains("virtual_ip_taken") ->
            "这个虚拟 IP 刚被占用" to "再点一次连接，服务端会重新分配"

        raw.contains("virtual_ip_not_in_network") || raw.contains("invalid_virtual_ip") ->
            "虚拟 IP 不合法" to "留空让服务端分配，或填本网络网段内的地址"

        raw.contains("rate_limited") || raw.contains("429") ->
            "请求太频繁" to "等一分钟再试"

        raw.contains("network_full") ->
            "网络成员已满" to "让管理员删掉不用的节点"

        raw.contains("upgrade_required") ->
            "服务端版本不兼容" to "更新部署器和 Worker 到最新版"

        raw.contains("room_unavailable") || raw.contains("503") ->
            "服务端暂时不可用" to "稍后重试；一直这样说明 Worker 没绑定 Durable Object"

        raw.contains("UnknownHost") || raw.contains("dns") ->
            "域名解析失败" to "检查信令地址拼写，以及手机当前网络能否解析这个域名"

        raw.contains("SSL") || raw.contains("certificate") || raw.contains("Handshake") ->
            "TLS 握手失败" to "先校准手机时间；用了代理的话，确认代理没拦截这个域名"

        raw.contains("timed out") || raw.contains("timeout") || raw.contains("连不上") ->
            "连接超时" to "检查手机网络，或换个网络再试"

        raw.contains("Permission") || raw.contains("EPERM") ->
            "没有权限" to "确认系统 VPN 授权还在，没被其它应用顶掉"

        else -> raw to "把这条原文发给管理员排查"
    }

    override fun onDestroy() {
        Native.stop()
        try {
            tun?.close()
        } catch (_: Exception) {
        }
        tun = null
        if (phase == Phase.CONNECTED) {
            setState(Phase.IDLE, "已断开")
        }
        super.onDestroy()
    }

    /** 用户在系统设置里撤销授权 / 被别的 VPN 顶掉 */
    override fun onRevoke() {
        Native.stop()
        setState(
            Phase.ERROR,
            "VPN 授权被撤销",
            "可能是系统设置里关掉了，或另一个 VPN 应用抢占了；回到 App 重新连接",
        )
        super.onRevoke()
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = getSystemService(NotificationManager::class.java) ?: return
        if (manager.getNotificationChannel(CHANNEL) == null) {
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL, "qp2p", NotificationManager.IMPORTANCE_LOW)
            )
        }
    }

    private fun notification(text: String): Notification {
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return builder
            .setContentTitle("qp2p")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(text: String) {
        try {
            val manager = getSystemService(NotificationManager::class.java) ?: return
            manager.notify(NOTIFICATION_ID, notification(text))
        } catch (t: Throwable) {
            logLine("更新通知失败: ${t.message}")
        }
    }
}
