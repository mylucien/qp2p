package com.qp2p

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.util.Log

/**
 * 开机自启：系统启动完成后，如果用户开着「自动连接」且已经授权过 VPN，
 * 就把隧道拉起来。
 *
 * 几个必须处理的现实约束：
 * - Android 8 起后台启动服务要用 `startForegroundService`，否则直接
 *   `IllegalStateException`；服务自己在 `handleStart` 里第一时间 startForeground。
 * - 从来没授权过 VPN 的话，后台弹不出授权框，启动只会得到
 *   "系统没批准建 VPN"。这种情况干脆不启动，等用户自己打开 App 点一次连接。
 * - 国产 ROM（MIUI / EMUI / ColorOS …）默认拦自启动，广播可能根本收不到。
 *   这不是代码能绕的，只能让用户在系统「自启动管理」里放行，USAGE 里写了。
 * - 开机瞬间网络往往还没就绪，注册会失败；服务侧对"开机触发的连接"做了
 *   有限次重试（见 [Qp2pVpnService.prepareTunnel]）。
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        if (action != Intent.ACTION_BOOT_COMPLETED && action != ACTION_QUICKBOOT) return

        if (!AppConfig.autoConnect(context)) {
            Log.i(TAG, "开机自启：未开启「自动连接」，跳过")
            return
        }
        val config = AppConfig.fromPrefs(context)
        if (config == null) {
            Log.w(TAG, "开机自启：配置不完整（缺信令地址或令牌），跳过")
            return
        }
        if (VpnService.prepare(context) != null) {
            Log.w(TAG, "开机自启：还没有 VPN 授权，等用户打开 App 再连")
            return
        }

        val service = Intent(context, Qp2pVpnService::class.java).apply {
            // 显式 setAction：Intent.action 不是可写属性
            setAction(Qp2pVpnService.ACTION_CONNECT)
            putExtra(Qp2pVpnService.EXTRA_CONFIG, config)
            putExtra(Qp2pVpnService.EXTRA_FROM_BOOT, true)
        }
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(service)
            } else {
                context.startService(service)
            }
            Log.i(TAG, "开机自启：已拉起隧道服务")
        } catch (t: Throwable) {
            // 部分 ROM 会直接拒绝后台启动，记下来就够了，别让接收器崩
            Log.w(TAG, "开机自启：拉起服务失败 ${t.javaClass.simpleName}: ${t.message}")
        }
    }

    private companion object {
        const val TAG = "qp2p"

        /** 少数厂商（如旧版 OPPO/vivo）发的快速开机广播 */
        const val ACTION_QUICKBOOT = "android.intent.action.QUICKBOOT_POWERON"
    }
}
