package com.qp2p

import android.content.Context
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
    private const val MTU = 1280

    /** 界面上「自动连接」开关的键 */
    private const val KEY_AUTO_CONNECT = "auto_connect"

    fun build(
        worker: String,
        token: String,
        name: String,
        virtualIp: String,
        dataDir: String,
        keepOnline: Boolean,
        idleMinutes: Int,
    ): String {
        val json = JSONObject()
        json.put("worker", worker)
        json.put("token", token)
        json.put("name", name)
        // 空字符串表示"让服务端分配"，所以空就不写这个字段
        if (virtualIp.isNotEmpty()) json.put("virtual_ip", virtualIp)
        json.put("data_dir", dataDir)
        json.put("mtu", MTU)
        json.put("bind", "0.0.0.0:0")
        json.put("keep_online", keepOnline)
        // 保持在线就传 0，内核按"永不休眠"处理
        json.put("idle_secs", if (keepOnline) 0 else idleMinutes * 60)
        return json.toString()
    }

    /** 从已保存的配置拼 JSON；必填项缺失时返回 null（开机时没人能帮用户补）。 */
    fun fromPrefs(context: Context): String? {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val worker = prefs.getString("worker", "").orEmpty().trim().trimEnd('/')
        val token = prefs.getString("token", "").orEmpty().trim()
        if (worker.isEmpty() || token.isEmpty()) return null
        return build(
            worker = worker,
            token = token,
            name = prefs.getString("name", "").orEmpty().trim(),
            virtualIp = prefs.getString("virtual_ip", "").orEmpty().trim(),
            dataDir = context.filesDir.absolutePath,
            keepOnline = prefs.getBoolean("keep_online", false),
            idleMinutes = prefs.getInt("idle_minutes", 10),
        )
    }

    /** 「自动连接」开关：界面打开时自动连，开机时也按它决定要不要拉起隧道。 */
    fun autoConnect(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getBoolean(KEY_AUTO_CONNECT, false)
}
