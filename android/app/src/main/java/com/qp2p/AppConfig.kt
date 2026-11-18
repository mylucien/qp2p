package com.qp2p

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * 启动参数的唯一出处。
 *
 * 现在有两条路径会拉起隧道：界面上点「连接」，和开机后 [BootReceiver] 自动拉起。
 * 两条路必须给出**完全一样**的字段，否则会出现"手动能连、开机连不上"这种
 * 只在真机上复现的差异。所以拼 JSON 的活集中在这里，界面只负责把界面上
 * 当前的值传进来。
 */
object AppConfig {
    /** 与界面共用同一个 prefs 文件，别另起一个 */
    const val PREFS = "qp2p"

    /** 与界面一致：移动网络常见 1280 的内层 MTU，保守值 */
    const val MTU_DEFAULT = 1280

    /** 界面上「自动连接」开关的键 */
    private const val KEY_AUTO_CONNECT = "auto_connect"

    /** 高级设置里可改的键；默认值与内核侧的默认行为保持一致 */
    const val KEY_MTU = "mtu"
    const val KEY_BIND_PORT = "bind_port"
    const val KEY_UPNP = "upnp"
    const val KEY_TRANSPORT = "signal_transport"
    const val KEY_STUN = "stun"
    const val KEY_LAN_TARGETS = "lan_targets"
    const val KEY_LAN_ENABLED = "lan_enabled"

    fun build(
        worker: String,
        token: String,
        name: String,
        virtualIp: String,
        dataDir: String,
        keepOnline: Boolean,
        idleMinutes: Int,
        mtu: Int = MTU_DEFAULT,
        bindPort: Int = 0,
        upnp: Boolean = true,
        transport: String = "auto",
        stun: String = "",
        lanEnabled: Boolean = false,
        lanTargets: String = "",
    ): String {
        val json = JSONObject()
        json.put("worker", worker)
        json.put("token", token)
        json.put("name", name)
        // 空字符串表示"让服务端分配"，所以空就不写这个字段
        if (virtualIp.isNotEmpty()) json.put("virtual_ip", virtualIp)
        json.put("data_dir", dataDir)
        json.put("mtu", mtu)
        // 0 = 让系统挑端口；填了固定端口才能让路由器的端口映射规则长期有效
        json.put("bind", "0.0.0.0:$bindPort")
        json.put("keep_online", keepOnline)
        // 保持在线就传 0，内核按"永不休眠"处理
        json.put("idle_secs", if (keepOnline) 0 else idleMinutes * 60)
        json.put("upnp", upnp)
        json.put("signal_transport", transport)
        // 留空就用内核的默认 STUN 列表，别把空数组传下去覆盖掉
        val stunList = lines(stun)
        if (stunList.isNotEmpty()) json.put("stun", JSONArray(stunList))
        // 共享关掉时一条都不传：没有映射就等于不开放
        if (lanEnabled) {
            val targets = JSONArray()
            for (line in lines(lanTargets)) {
                val (listen, target) = parseShareLine(line)
                if (target.isEmpty()) continue
                val item = JSONObject().put("target", target)
                // 0 = 让内核按目标端口自动选，别把 0 当成端口传下去
                if (listen > 0) item.put("listen", listen)
                targets.put(item)
            }
            if (targets.length() > 0) json.put("lan_share", targets)
        }
        return json.toString()
    }

    /**
     * 一行共享配置 → (虚拟端口, 目标地址)。
     *
     * 存储格式是 `[虚拟端口 ]目标 | 备注`：端口可省略（0 = 自动），备注只给人看。
     * 界面上要显示这两样，内核侧要的是这两个字段，所以解析只写这一处。
     */
    fun parseShareLine(line: String): Pair<Int, String> {
        val body = line.substringBefore("|").trim()
        if (body.isEmpty()) return 0 to ""
        val parts = body.split(Regex("\\s+"))
        if (parts.size >= 2) {
            val port = parts[0].toIntOrNull()
            if (port != null && port in 1..65535) return port to parts[1].trim()
        }
        return 0 to body
    }

    /** 取一行的备注部分；没有备注时返回空串 */
    fun shareNote(line: String): String = line.substringAfter("|", "").trim()

    /**
     * 目标端口不填虚拟端口时的默认值：≥1024 就沿用，否则加 10000。
     *
     * 必须和内核 `auto_listen_port` 的规则一致，否则界面显示的端口和实际绑的不是一个。
     */
    fun defaultListenPort(target: String): Int {
        val port = target.substringAfterLast(":", "").toIntOrNull() ?: return 0
        return if (port >= 1024) port else port + 10_000
    }

    /** 多行文本 → 去空行去首尾空格的列表 */
    private fun lines(text: String): List<String> =
        text.lines().map { it.trim() }.filter { it.isNotEmpty() }

    /** 从已保存的配置拼 JSON；必填项缺失时返回 null（开机时没人能帮用户补）。 */
    fun fromPrefs(context: Context): String? {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val worker = prefs.getString("worker", "").orEmpty().trim().trimEnd('/')
        // 令牌是加密存的；这里必须走 Secrets，直接读 prefs 只会拿到 "v1:..." 密文
        val token = Secrets.get(context, Secrets.TOKEN).trim()
        if (worker.isEmpty() || token.isEmpty()) return null
        return build(
            worker = worker,
            token = token,
            name = prefs.getString("name", "").orEmpty().trim(),
            virtualIp = prefs.getString("virtual_ip", "").orEmpty().trim(),
            dataDir = context.filesDir.absolutePath,
            keepOnline = prefs.getBoolean("keep_online", false),
            idleMinutes = prefs.getInt("idle_minutes", 10),
            mtu = prefs.getInt(KEY_MTU, MTU_DEFAULT),
            bindPort = prefs.getInt(KEY_BIND_PORT, 0),
            upnp = prefs.getBoolean(KEY_UPNP, true),
            transport = prefs.getString(KEY_TRANSPORT, "auto").orEmpty(),
            stun = prefs.getString(KEY_STUN, "").orEmpty(),
            lanEnabled = prefs.getBoolean(KEY_LAN_ENABLED, false),
            lanTargets = prefs.getString(KEY_LAN_TARGETS, "").orEmpty(),
        )
    }

    /** 「自动连接」开关：界面打开时自动连，开机时也按它决定要不要拉起隧道。 */
    fun autoConnect(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getBoolean(KEY_AUTO_CONNECT, false)
}
