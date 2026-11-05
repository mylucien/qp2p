package com.qp2p

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.Gravity
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import org.json.JSONObject

/**
 * 最简界面：填三个值，连上，断开。
 *
 * 刻意不引入 AndroidX —— 少一个依赖就少一处 CI 上可能挂的地方，
 * 而这里需要的只是一个输入框和一个按钮。
 */
class MainActivity : Activity() {

    private val prefs by lazy { getSharedPreferences("qp2p", MODE_PRIVATE) }
    private val ui = Handler(Looper.getMainLooper())

    private lateinit var workerInput: EditText
    private lateinit var tokenInput: EditText
    private lateinit var nameInput: EditText
    private lateinit var statusText: TextView
    private lateinit var connectButton: Button

    private var pendingConnect = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(buildLayout())
        loadSettings()
        checkNative()

        connectButton.setOnClickListener {
            if (Qp2pVpnService.connected) {
                disconnect()
            } else {
                ensurePermissionThenConnect()
            }
        }

        // 状态在 Service 里更新，这里定时捞一次，省掉跨进程广播的复杂度
        ui.post(object : Runnable {
            override fun run() {
                statusText.text = Qp2pVpnService.status.ifEmpty { "未连接" }
                connectButton.text = if (Qp2pVpnService.connected) "断开" else "连接"
                ui.postDelayed(this, 800)
            }
        })
    }

    private fun buildLayout(): LinearLayout {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 64, 48, 48)
        }

        root.addView(label("信令地址（Worker）"))
        workerInput = field("https://你的-worker.workers.dev", InputType.TYPE_TEXT_VARIATION_URI)
        root.addView(workerInput)

        root.addView(label("加入令牌"))
        tokenInput = field("qp2p1_home_xxxx", InputType.TYPE_CLASS_TEXT)
        root.addView(tokenInput)

        root.addView(label("本机名称（可留空）"))
        nameInput = field("phone", InputType.TYPE_CLASS_TEXT)
        root.addView(nameInput)

        connectButton = Button(this).apply { text = "连接" }
        root.addView(connectButton)

        statusText = TextView(this).apply {
            text = "未连接"
            setTextColor(Color.parseColor("#555555"))
            gravity = Gravity.START
            setPadding(0, 32, 0, 0)
        }
        root.addView(statusText)

        root.addView(
            TextView(this).apply {
                text = "说明：只接管虚拟网段（10.x）的流量，公网照旧走系统网络。\n" +
                    "需要先在有公网的机器上用 qp2p create 建好网络。"
                setTextColor(Color.parseColor("#888888"))
                textSize = 12f
                setPadding(0, 24, 0, 0)
            }
        )
        return root
    }

    private fun label(text: String) = TextView(this).apply {
        this.text = text
        textSize = 13f
        setPadding(0, 24, 0, 8)
    }

    private fun field(hintText: String, type: Int) = EditText(this).apply {
        hint = hintText
        inputType = type
        textSize = 14f
        setSingleLine()
    }

    /** 本地库加载不了的话，后面点什么都没用，先把原因摆出来 */
    private fun checkNative() {
        try {
            Native.isPrepared()
        } catch (t: Throwable) {
            Qp2pVpnService.status = "本地库加载失败：${t.javaClass.simpleName} ${t.message ?: ""}"
        }
    }

    private fun loadSettings() {
        workerInput.setText(prefs.getString("worker", ""))
        tokenInput.setText(prefs.getString("token", ""))
        nameInput.setText(prefs.getString("name", ""))
    }

    private fun saveSettings() {
        prefs.edit()
            .putString("worker", workerInput.text.toString().trim())
            .putString("token", tokenInput.text.toString().trim())
            .putString("name", nameInput.text.toString().trim())
            .apply()
    }

    private fun configJson(): String {
        val json = JSONObject()
        json.put("worker", workerInput.text.toString().trim().trimEnd('/'))
        json.put("token", tokenInput.text.toString().trim())
        json.put("name", nameInput.text.toString().trim())
        json.put("data_dir", filesDir.absolutePath)
        // 移动网络常见 1280 的内层 MTU，先用保守值，跑通再按需调大
        json.put("mtu", 1280)
        json.put("bind", "0.0.0.0:0")
        return json.toString()
    }

    private fun ensurePermissionThenConnect() {
        saveSettings()
        val intent = VpnService.prepare(this)
        if (intent != null) {
            // 第一次用会弹系统授权框
            pendingConnect = true
            startActivityForResult(intent, REQUEST_VPN)
        } else {
            connect()
        }
    }

    private fun connect() {
        val config = configJson()
        if (config.contains("\"token\":\"\"")) {
            Qp2pVpnService.status = "先填加入令牌"
            return
        }
        Qp2pVpnService.status = "正在连接…"
        val intent = Intent(this, Qp2pVpnService::class.java).apply {
            action = Qp2pVpnService.ACTION_CONNECT
            putExtra(Qp2pVpnService.EXTRA_CONFIG, config)
        }
        try {
            startService(intent)
        } catch (t: Throwable) {
            Qp2pVpnService.status = "启动服务失败：${t.javaClass.simpleName} ${t.message ?: ""}"
        }
    }

    private fun disconnect() {
        try {
            Native.stop()
            startService(
                Intent(this, Qp2pVpnService::class.java).apply {
                    action = Qp2pVpnService.ACTION_DISCONNECT
                }
            )
        } catch (t: Throwable) {
            Qp2pVpnService.status = "断开失败：${t.message}"
        }
        Qp2pVpnService.status = "正在断开…"
    }

    @Deprecated("VpnService 授权沿用旧回调，够用")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN && pendingConnect) {
            pendingConnect = false
            if (resultCode == RESULT_OK) {
                connect()
            } else {
                Qp2pVpnService.status = "你拒绝了 VPN 授权"
            }
        }
    }

    private companion object {
        const val REQUEST_VPN = 1001
    }
}
