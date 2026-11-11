package com.qp2p

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.view.Gravity
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import org.json.JSONObject

/**
 * 最简界面：填地址和令牌，一键启动，或只保存配置。
 *
 * 刻意不引入 AndroidX —— 少一个依赖就少一处 CI 上可能挂的地方，
 * 而这里需要的只是几个输入框和两个按钮。
 */
class MainActivity : Activity() {

    private val prefs by lazy { getSharedPreferences("qp2p", MODE_PRIVATE) }
    private val ui = Handler(Looper.getMainLooper())

    private lateinit var workerInput: EditText
    private lateinit var tokenInput: EditText
    private lateinit var nameInput: EditText
    private lateinit var ipInput: EditText
    private lateinit var subnetHint: TextView
    private lateinit var statusText: TextView
    private lateinit var connectButton: Button
    private lateinit var saveButton: Button

    private var pendingConnect = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(buildLayout())
        loadSettings()
        checkNative()

        // 手填 IP 实时校验：不合法就把按钮禁掉，别让人点了才看到服务端报错
        ipInput.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) = Unit
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) = Unit
            override fun afterTextChanged(s: Editable?) = refreshIpHint()
        })
        refreshIpHint()

        connectButton.setOnClickListener {
            if (Qp2pVpnService.connected) {
                disconnect()
            } else {
                ensurePermissionThenConnect()
            }
        }

        // 只保存、不连接：改完配置又不想现在连的时候用
        saveButton.setOnClickListener { saveOnly() }

        // 状态在 Service 里更新，这里定时捞一次，省掉跨进程广播的复杂度
        ui.post(object : Runnable {
            override fun run() {
                statusText.text = Qp2pVpnService.status.ifEmpty { "未连接" }
                connectButton.text = if (Qp2pVpnService.connected) "断开" else "启动马上连接"
                // 连上之后才知道网段，这里补一次提示
                refreshIpHint()
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

        root.addView(label("虚拟 IP（可留空，自动分配）"))
        ipInput = field("留空 = 服务端分配；想要固定地址就填，如 10.78.0.50", InputType.TYPE_CLASS_TEXT)
        root.addView(ipInput)
        subnetHint = TextView(this).apply {
            text = ""
            setTextColor(Color.parseColor("#888888"))
            textSize = 12f
            setPadding(0, 8, 0, 0)
        }
        root.addView(subnetHint)

        // 两个按钮一行：「启动马上连接」是主操作，占两倍宽
        val buttons = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        connectButton = Button(this).apply { text = "启动马上连接" }
        saveButton = Button(this).apply { text = "保存配置" }
        buttons.addView(
            connectButton,
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 2f)
        )
        buttons.addView(
            saveButton,
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        )
        root.addView(buttons)

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
        ipInput.setText(prefs.getString("virtual_ip", ""))
    }

    private fun saveSettings() {
        prefs.edit()
            .putString("worker", workerInput.text.toString().trim())
            .putString("token", tokenInput.text.toString().trim())
            .putString("name", nameInput.text.toString().trim())
            .putString("virtual_ip", ipInput.text.toString().trim())
            .apply()
    }

    private fun configJson(): String {
        val json = JSONObject()
        json.put("worker", workerInput.text.toString().trim().trimEnd('/'))
        json.put("token", tokenInput.text.toString().trim())
        json.put("name", nameInput.text.toString().trim())
        val ip = ipInput.text.toString().trim()
        if (ip.isNotEmpty()) json.put("virtual_ip", ip)
        json.put("data_dir", filesDir.absolutePath)
        // 移动网络常见 1280 的内层 MTU，先用保守值，跑通再按需调大
        json.put("mtu", 1280)
        json.put("bind", "0.0.0.0:0")
        return json.toString()
    }

    /** 空字符串表示"让服务端分配"，所以空值一律合法。 */
    private fun ipProblem(raw: String): String? {
        if (raw.isEmpty()) return null
        val parts = raw.split(".")
        if (parts.size != 4) return "格式应为 a.b.c.d"
        val nums = parts.map { it.toIntOrNull() ?: return "每段必须是数字" }
        if (nums.any { it < 0 || it > 255 }) return "每段必须在 0~255 之间"

        val cidr = Qp2pVpnService.lastCidr
        if (cidr.contains("/")) {
            val baseText = cidr.substringBefore("/")
            val prefix = cidr.substringAfter("/").toIntOrNull() ?: 16
            val shift = 32 - prefix.coerceIn(1, 32)
            val mask = if (shift == 32) 0u else (0xFFFFFFFFu shl shift)
            val ipInt = nums.fold(0u) { acc, n -> (acc shl 8) or n.toUInt() }
            val baseInt = baseText.split(".").mapNotNull { it.toIntOrNull() }
                .fold(0u) { acc, n -> (acc shl 8) or n.toUInt() }
            if ((ipInt and mask) != (baseInt and mask)) return "不在本网络网段 $cidr 内"
            val host = ipInt and mask.inv()
            if (host == 0u) return "这是网段地址，不能给设备用"
            if (host == mask.inv()) return "这是广播地址，不能给设备用"
        }
        return null
    }

    private fun refreshIpHint() {
        if (!::subnetHint.isInitialized) return
        val ip = ipInput.text.toString().trim()
        val problem = ipProblem(ip)
        val cidr = Qp2pVpnService.lastCidr
        subnetHint.text = when {
            problem != null -> "✗ $problem"
            cidr.isNotEmpty() -> "本网络网段 $cidr：留空自动分配，手填须在网段内"
            else -> "留空由服务端分配；第一次连上后会显示本网络网段"
        }
        subnetHint.setTextColor(
            if (problem != null) Color.parseColor("#D93025") else Color.parseColor("#888888")
        )
    }

    /**
     * 逐字段校验，返回第一处问题的说明；全部合法返回 null。
     *
     * 只报告、不自动纠正——静默改写用户填的地址比直接报错更难排查。
     */
    private fun validate(): String? {
        val worker = workerInput.text.toString().trim()
        if (worker.isEmpty()) return "请填写信令地址（Worker 地址）"
        // 只接受 https：Rust 侧 normalize_worker 同样拒绝明文地址，两端保持一致
        if (!worker.startsWith("https://")) {
            return "信令地址要以 https:// 开头，例如 https://p2p.example.com"
        }
        val host = worker.removePrefix("https://").substringBefore("/")
        if (!host.contains(".") || host.startsWith(".") || host.endsWith(".")) {
            return "信令地址不完整，例如 https://p2p.example.com"
        }
        val token = tokenInput.text.toString().trim()
        if (token.isEmpty()) return "请填写加入令牌"
        if (!token.startsWith("qp2p1_")) return "令牌应以 qp2p1_ 开头"
        if (token.count { it == '_' } < 2) return "令牌格式应为 qp2p1_<网络>_<密钥>"
        ipProblem(ipInput.text.toString().trim())?.let { return "虚拟 IP：$it" }
        return null
    }

    /** 只保存、不连接。连接中点也可以保存，改动下次连接生效。 */
    private fun saveOnly() {
        val problem = validate()
        if (problem != null) {
            // 失败原因停在状态栏里，让人能看清是哪一项不对
            Qp2pVpnService.status = "✗ $problem"
            return
        }
        saveSettings()
        // 成功用 Toast：这条信息不需要一直占着状态栏
        val hint = if (Qp2pVpnService.connected) "已保存，下次连接生效" else "已保存"
        Toast.makeText(this, hint, Toast.LENGTH_SHORT).show()
    }

    private fun ensurePermissionThenConnect() {
        val problem = validate()
        if (problem != null) {
            Qp2pVpnService.status = "✗ $problem"
            return
        }
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
        // 授权回调也可能走到这里，再校验一遍，避免配置在这期间被改坏
        val problem = validate()
        if (problem != null) {
            Qp2pVpnService.status = "✗ $problem"
            return
        }
        val config = configJson()
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
