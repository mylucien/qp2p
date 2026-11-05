package com.qp2p

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
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
 */
class Qp2pVpnService : VpnService() {

    companion object {
        const val ACTION_CONNECT = "com.qp2p.CONNECT"
        const val ACTION_DISCONNECT = "com.qp2p.DISCONNECT"
        const val EXTRA_CONFIG = "config"
        private const val CHANNEL = "qp2p-vpn"
        private const val NOTIFICATION_ID = 1

        /** 给界面读的当前状态 */
        @Volatile
        var status: String = ""
        @Volatile
        var connected: Boolean = false
            private set
    }

    private var tun: ParcelFileDescriptor? = null
    private var worker: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                Native.stop()
                return START_NOT_STICKY
            }
        }

        val config = intent?.getStringExtra(EXTRA_CONFIG)
        if (config.isNullOrBlank()) {
            status = "缺少配置"
            stopSelf()
            return START_NOT_STICKY
        }

        ensureChannel()
        startForeground(NOTIFICATION_ID, notification("正在连接…"))

        worker = Thread({ runTunnel(config) }, "qp2p-vpn").also { it.start() }
        return START_STICKY
    }

    private fun runTunnel(config: String) {
        try {
            val prepared = Native.prepare(config)
            val info = JSONObject(prepared)
            if (info.has("error")) {
                finish("注册失败：" + info.optString("error"))
                return
            }

            val ip = info.getString("virtual_ip")
            val prefix = info.getInt("prefix")
            val mtu = info.getInt("mtu")
            val cidr = info.getString("cidr").substringBefore("/")

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

            val pfd = builder.establish() ?: run {
                finish("系统没批准建 VPN（可能被别的 VPN 占用）")
                return
            }
            tun = pfd

            status = "已连接 $ip"
            connected = true
            updateNotification("已连接 $ip（$cidr）")

            val err = Native.start(pfd.fd)
            if (err != null) status = "已断开：$err" else status = "已断开"
        } catch (e: Throwable) {
            status = "出错：" + (e.message ?: e.javaClass.simpleName)
        } finally {
            connected = false
            try {
                tun?.close()
            } catch (_: Exception) {
            }
            tun = null
            stopForeground(true)
            stopSelf()
        }
    }

    private fun finish(message: String) {
        status = message
        connected = false
        stopForeground(true)
        stopSelf()
    }

    override fun onDestroy() {
        Native.stop()
        try {
            tun?.close()
        } catch (_: Exception) {
        }
        tun = null
        connected = false
        super.onDestroy()
    }

    /** 用户在系统设置里撤销授权 / 被别的 VPN 顶掉 */
    override fun onRevoke() {
        Native.stop()
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
        val manager = getSystemService(NotificationManager::class.java) ?: return
        manager.notify(NOTIFICATION_ID, notification(text))
    }
}
