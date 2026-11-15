package com.qp2p

import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.SharedPreferences
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import kotlin.math.roundToInt
import org.json.JSONObject

/**
 * 高级设置：局域网共享、网络参数、建网。
 *
 * 这里的每一项都真的会进到 [AppConfig] 拼出来的配置里；改动立即写 prefs，
 * 隧道已经在跑时提示「重连后生效」——不自动重连，免得用户改一半就被踢。
 */
class AdvancedActivity : Activity() {

    private lateinit var prefs: SharedPreferences

    private lateinit var lanSwitch: Switch
    private lateinit var lanTargetsBox: LinearLayout

    private lateinit var upnpSwitch: Switch
    private lateinit var stunValue: TextView

    private lateinit var nameInput: EditText
    private lateinit var adminInput: EditText
    private lateinit var cidrInput: EditText
    private lateinit var createButton: Button
    private lateinit var createResult: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        prefs = getSharedPreferences(AppConfig.PREFS, Context.MODE_PRIVATE)

        val scroll = ScrollView(this).apply { setBackgroundColor(BG) }
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(8), dp(16), dp(18))
        }
        scroll.addView(root)

        root.addView(buildTopBar())
        root.addView(buildLanGroup(), cardParams())
        root.addView(buildNetworkGroup(), cardParams())
        root.addView(buildCreateGroup(), cardParams())

        setContentView(scroll)
    }

    // ------------------------------------------------------------------
    // 顶栏
    // ------------------------------------------------------------------

    private fun buildTopBar(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        setPadding(0, 0, 0, dp(10))
        addView(
            TextView(this@AdvancedActivity).apply {
                text = "‹"
                textSize = 26f
                setTextColor(INK)
                gravity = Gravity.CENTER
                setPadding(dp(4), 0, dp(10), dp(2))
                isClickable = true
                setOnClickListener { finish() }
            }
        )
        addView(
            TextView(this@AdvancedActivity).apply {
                text = "高级"
                textSize = 19f
                setTextColor(INK)
                setTypeface(typeface, Typeface.BOLD)
            }
        )
    }

    // ------------------------------------------------------------------
    // 分组 1：局域网共享
    // ------------------------------------------------------------------

    private fun buildLanGroup(): LinearLayout {
        val (card, body) = groupCard("局域网共享", "新", expanded = true)

        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dp(2), 0, dp(2))
            minimumHeight = dp(40)
            addView(
                TextView(this@AdvancedActivity).apply {
                    text = "允许远程访问本机局域网"
                    textSize = 15f
                    setTextColor(INK)
                },
                LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f),
            )
            lanSwitch = tintedSwitch().apply {
                isChecked = prefs.getBoolean(AppConfig.KEY_LAN_ENABLED, false)
                setOnCheckedChangeListener { _, checked ->
                    prefs.edit().putBoolean(AppConfig.KEY_LAN_ENABLED, checked).apply()
                    notifyNeedReconnect()
                }
            }
            addView(lanSwitch)
        }
        body.addView(row)

        body.addView(hintText("走 TCP 转发，每个端口单独加一条"))

        lanTargetsBox = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        body.addView(lanTargetsBox)

        body.addView(
            TextView(this).apply {
                text = "＋ 添加目标"
                textSize = 13f
                setTextColor(BLUE)
                gravity = Gravity.CENTER
                minimumHeight = dp(40)
                background = dashedRect()
                isClickable = true
                setOnClickListener { askTarget() }
            },
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(8) },
        )

        renderTargets()
        return card
    }

    private fun renderTargets() {
        lanTargetsBox.removeAllViews()
        val entries = lanEntries()
        if (entries.isEmpty()) {
            lanTargetsBox.addView(
                hintText("还没有目标").apply {
                    setPadding(0, dp(6), 0, dp(2))
                }
            )
            return
        }
        entries.forEachIndexed { index, (address, note) ->
            lanTargetsBox.addView(targetRow(index, address, note))
        }
    }

    private fun targetRow(index: Int, address: String, note: String): LinearLayout =
        LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            minimumHeight = dp(42)
            setPadding(0, dp(2), 0, dp(2))
            addView(
                TextView(this@AdvancedActivity).apply {
                    text = address
                    textSize = 13f
                    setTextColor(INK)
                    typeface = Typeface.MONOSPACE
                }
            )
            addView(
                TextView(this@AdvancedActivity).apply {
                    text = note
                    textSize = 12f
                    setTextColor(MUTED)
                    gravity = Gravity.END
                    setPadding(dp(8), 0, dp(8), 0)
                },
                LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f),
            )
            addView(
                TextView(this@AdvancedActivity).apply {
                    text = "×"
                    textSize = 18f
                    setTextColor(HINT)
                    gravity = Gravity.CENTER
                    setPadding(dp(8), 0, dp(2), 0)
                    isClickable = true
                    setOnClickListener {
                        val list = lanEntries().toMutableList()
                        if (index in list.indices) list.removeAt(index)
                        saveLanEntries(list)
                    }
                }
            )
        }

    /** 弹窗添加一条：地址必填，备注可选 */
    private fun askTarget() {
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(6), dp(20), 0)
        }
        val address = EditText(this).apply {
            hint = "192.168.1.1:80"
            textSize = 15f
            inputType = InputType.TYPE_CLASS_TEXT
            setSingleLine()
        }
        val note = EditText(this).apply {
            hint = "备注，可留空"
            textSize = 15f
            inputType = InputType.TYPE_CLASS_TEXT
            setSingleLine()
        }
        column.addView(address)
        column.addView(note)

        AlertDialog.Builder(this)
            .setTitle("添加目标")
            .setView(column)
            .setNegativeButton("取消", null)
            .setPositiveButton("添加") { _, _ ->
                val text = address.text.toString().trim()
                if (!isAddressPort(text)) {
                    toast("格式应为 IP:端口，例如 192.168.1.1:80")
                    return@setPositiveButton
                }
                val list = lanEntries().toMutableList()
                if (list.any { it.first == text }) {
                    toast("这条已经加过了")
                    return@setPositiveButton
                }
                list.add(text to note.text.toString().trim())
                saveLanEntries(list)
            }
            .show()
    }

    private fun isAddressPort(text: String): Boolean {
        val parts = text.split(":")
        if (parts.size != 2) return false
        val ip = parts[0].split(".")
        if (ip.size != 4) return false
        if (ip.any { part -> part.toIntOrNull()?.let { it in 0..255 } != true }) return false
        val port = parts[1].toIntOrNull() ?: return false
        return port in 1..65535
    }

    private fun lanEntries(): List<Pair<String, String>> =
        prefs.getString(AppConfig.KEY_LAN_TARGETS, "").orEmpty()
            .lines()
            .mapNotNull { line ->
                val text = line.trim()
                if (text.isEmpty()) return@mapNotNull null
                val parts = text.split("|", limit = 2)
                parts[0].trim() to (parts.getOrNull(1)?.trim() ?: "")
            }

    private fun saveLanEntries(list: List<Pair<String, String>>) {
        val text = list.joinToString("\n") { (address, note) ->
            if (note.isEmpty()) address else "$address | $note"
        }
        prefs.edit().putString(AppConfig.KEY_LAN_TARGETS, text).apply()
        renderTargets()
        notifyNeedReconnect()
    }

    // ------------------------------------------------------------------
    // 分组 2：网络
    // ------------------------------------------------------------------

    private fun buildNetworkGroup(): LinearLayout {
        val (card, body) = groupCard("网络", null, expanded = false)

        body.addView(pickerRow("MTU", mtuText()))
        body.addView(pickerRow("监听端口", portText()))

        body.addView(
            LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                minimumHeight = dp(44)
                addView(
                    TextView(this@AdvancedActivity).apply {
                        text = "UPnP 端口映射"
                        textSize = 15f
                        setTextColor(INK)
                    },
                    LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f),
                )
                upnpSwitch = tintedSwitch().apply {
                    isChecked = prefs.getBoolean(AppConfig.KEY_UPNP, true)
                    setOnCheckedChangeListener { _, checked ->
                        prefs.edit().putBoolean(AppConfig.KEY_UPNP, checked).apply()
                        notifyNeedReconnect()
                    }
                }
                addView(upnpSwitch)
            }
        )

        body.addView(pickerRow("信令传输", transportText()))

        body.addView(
            TextView(this).apply {
                text = "STUN 服务器"
                textSize = 12f
                setTextColor(MUTED)
                setPadding(0, dp(10), 0, dp(6))
            }
        )
        stunValue = TextView(this).apply {
            text = stunText()
            textSize = 12f
            setTextColor(MUTED)
            typeface = Typeface.MONOSPACE
            setPadding(dp(10), dp(8), dp(10), dp(8))
            background = roundRect(Color.parseColor("#FBFCFD"), 10, 1, BORDER)
            isClickable = true
            setOnClickListener { askStun() }
        }
        body.addView(stunValue)

        return card
    }

    private fun mtuText(): String = "${prefs.getInt(AppConfig.KEY_MTU, AppConfig.MTU_DEFAULT)}"

    private fun portText(): String {
        val port = prefs.getInt(AppConfig.KEY_BIND_PORT, 0)
        return if (port <= 0) "自动" else "端口 $port"
    }

    private fun transportText(): String = when (prefs.getString(AppConfig.KEY_TRANSPORT, "auto")) {
        "ws" -> "长连接"
        "poll" -> "轮询"
        else -> "自动"
    }

    private fun stunText(): String {
        val saved = prefs.getString(AppConfig.KEY_STUN, "").orEmpty().trim()
        return if (saved.isEmpty()) DEFAULT_STUN_TEXT else saved
    }

    /** 左侧标签 + 右侧可点的当前值；点击按标签分派到各自的编辑框 */
    private fun pickerRow(label: String, value: String): LinearLayout =
        LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            minimumHeight = dp(44)
            addView(
                TextView(this@AdvancedActivity).apply {
                    text = label
                    textSize = 15f
                    setTextColor(INK)
                },
                LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f),
            )
            val text = TextView(this@AdvancedActivity).apply {
                this.text = "$value ▾"
                textSize = 14f
                setTextColor(MUTED)
                gravity = Gravity.CENTER
                setPadding(dp(9), dp(5), dp(9), dp(5))
                background = roundRect(Color.parseColor("#FBFCFD"), 8, 1, BORDER)
                isClickable = true
                setOnClickListener { onPickerClick(label, this) }
            }
            addView(text)
        }

    private fun onPickerClick(label: String, view: TextView) {
        when (label) {
            "MTU" -> askMtu(view)
            "监听端口" -> askPort(view)
            "信令传输" -> askTransport(view)
        }
    }

    private fun askMtu(view: TextView) {
        val choices = arrayOf("1280（默认）", "1360", "1420", "自定义")
        AlertDialog.Builder(this)
            .setTitle("MTU")
            .setItems(choices) { _, which ->
                when (which) {
                    0 -> saveMtu(view, 1280)
                    1 -> saveMtu(view, 1360)
                    2 -> saveMtu(view, 1420)
                    else -> askNumber("MTU", prefs.getInt(AppConfig.KEY_MTU, AppConfig.MTU_DEFAULT)) { n ->
                        if (n in 576..9000) saveMtu(view, n) else toast("MTU 应在 576–9000 之间")
                    }
                }
            }
            .show()
    }

    private fun saveMtu(view: TextView, value: Int) {
        prefs.edit().putInt(AppConfig.KEY_MTU, value).apply()
        view.text = "$value ▾"
        notifyNeedReconnect()
    }

    private fun askPort(view: TextView) {
        askNumber("监听 UDP 端口（0 = 自动）", prefs.getInt(AppConfig.KEY_BIND_PORT, 0)) { n ->
            if (n !in 0..65535) {
                toast("端口应在 0–65535 之间")
                return@askNumber
            }
            prefs.edit().putInt(AppConfig.KEY_BIND_PORT, n).apply()
            view.text = "${if (n == 0) "自动" else "端口 $n"} ▾"
            notifyNeedReconnect()
        }
    }

    private fun askTransport(view: TextView) {
        val labels = arrayOf("自动", "长连接（ws）", "只用轮询")
        val values = arrayOf("auto", "ws", "poll")
        val current = prefs.getString(AppConfig.KEY_TRANSPORT, "auto")
        val checked = values.indexOf(current).coerceAtLeast(0)
        AlertDialog.Builder(this)
            .setTitle("信令传输")
            .setSingleChoiceItems(labels, checked) { dialog, which ->
                prefs.edit().putString(AppConfig.KEY_TRANSPORT, values[which]).apply()
                view.text = "${labels[which]} ▾"
                dialog.dismiss()
                notifyNeedReconnect()
            }
            .show()
    }

    private fun askStun() {
        val input = EditText(this).apply {
            setText(prefs.getString(AppConfig.KEY_STUN, "").orEmpty())
            hint = DEFAULT_STUN_TEXT
            textSize = 13f
            typeface = Typeface.MONOSPACE
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE
            minLines = 3
            gravity = Gravity.TOP or Gravity.START
            setPadding(dp(12), dp(10), dp(12), dp(10))
        }
        AlertDialog.Builder(this)
            .setTitle("STUN 服务器（每行一个，留空用默认）")
            .setView(input)
            .setNegativeButton("取消", null)
            .setPositiveButton("保存") { _, _ ->
                prefs.edit()
                    .putString(AppConfig.KEY_STUN, input.text.toString().trim())
                    .apply()
                stunValue.text = stunText()
                notifyNeedReconnect()
            }
            .show()
    }

    private fun askNumber(title: String, current: Int, done: (Int) -> Unit) {
        val input = EditText(this).apply {
            setText(current.toString())
            inputType = InputType.TYPE_CLASS_NUMBER
            textSize = 15f
            setSelectAllOnFocus(true)
        }
        AlertDialog.Builder(this)
            .setTitle(title)
            .setView(input)
            .setNegativeButton("取消", null)
            .setPositiveButton("保存") { _, _ ->
                val n = input.text.toString().trim().toIntOrNull()
                if (n == null) toast("请填数字") else done(n)
            }
            .show()
    }

    // ------------------------------------------------------------------
    // 分组 3：建网
    // ------------------------------------------------------------------

    private fun buildCreateGroup(): LinearLayout {
        val (card, body) = groupCard("新建网络", null, expanded = false)

        nameInput = field("网络名，如 home")
        adminInput = field("管理密钥 ADMIN_SECRET").apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        cidrInput = field("网段，留空＝10.78.0.0/16")

        body.addView(nameInput)
        body.addView(adminInput)
        body.addView(cidrInput)

        createButton = Button(this).apply {
            text = "创建并生成令牌"
            textSize = 15f
            setTextColor(Color.WHITE)
            background = roundRect(BLUE, 12)
            minimumHeight = 0
            setPadding(0, dp(12), 0, dp(12))
            isAllCaps = false
            setOnClickListener { doCreate() }
        }
        body.addView(
            createButton,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(2) },
        )

        createResult = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
            setPadding(dp(12), dp(10), dp(12), dp(12))
        }
        body.addView(
            createResult,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(10) },
        )

        return card
    }

    private fun doCreate() {
        val name = nameInput.text.toString().trim()
        val admin = adminInput.text.toString().trim()
        val cidr = cidrInput.text.toString().trim()
        val worker = prefs.getString("worker", "").orEmpty().trim().trimEnd('/')

        if (name.isEmpty()) {
            toast("先填网络名")
            return
        }
        if (admin.isEmpty()) {
            toast("先填管理密钥")
            return
        }
        if (worker.isEmpty()) {
            toast("先在主界面填并保存信令地址")
            return
        }

        val request = JSONObject().apply {
            put("worker", worker)
            put("admin", admin)
            put("name", name)
            if (cidr.isNotEmpty()) put("cidr", cidr)
        }.toString()

        createButton.isEnabled = false
        createButton.text = "正在创建…"
        createResult.visibility = View.GONE

        Thread {
            val reply = try {
                Native.createNetwork(request)
            } catch (e: Throwable) {
                "{\"error\":\"${e.message ?: "调用失败"}\"}"
            }
            runOnUiThread {
                createButton.isEnabled = true
                createButton.text = "创建并生成令牌"
                showCreateResult(reply)
            }
        }.start()
    }

    private fun showCreateResult(reply: String) {
        val parsed = try {
            JSONObject(reply)
        } catch (e: Exception) {
            toast("返回内容看不懂：$reply")
            return
        }
        val error = parsed.optString("error", "")
        createResult.removeAllViews()
        createResult.visibility = View.VISIBLE

        if (error.isNotEmpty()) {
            createResult.background = roundRect(Color.parseColor("#FEF2F2"), 10, 1, RED)
            createResult.addView(
                TextView(this).apply {
                    text = error
                    textSize = 13f
                    setTextColor(RED)
                }
            )
            return
        }

        val token = parsed.optString("token", "")
        val cidr = parsed.optString("cidr", "")
        createResult.background = roundRect(Color.parseColor("#F0FDF4"), 10, 1, GREEN)
        createResult.addView(
            TextView(this).apply {
                text = "创建成功，网段 $cidr"
                textSize = 13f
                setTextColor(GREEN)
            }
        )
        createResult.addView(
            TextView(this).apply {
                text = token
                textSize = 13f
                setTextColor(INK)
                typeface = Typeface.MONOSPACE
                setPadding(0, dp(6), 0, dp(8))
                setTextIsSelectable(true)
            }
        )
        createResult.addView(
            TextView(this).apply {
                text = "复制令牌"
                textSize = 13f
                setTextColor(BLUE)
                isClickable = true
                setOnClickListener {
                    (getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager)
                        ?.setPrimaryClip(ClipData.newPlainText("qp2p 令牌", token))
                    toast("已复制，粘到主界面的「加入令牌」里")
                }
            }
        )
    }

    // ------------------------------------------------------------------
    // 通用件
    // ------------------------------------------------------------------

    /** 标题行可点：展开/收起下面的内容 */
    private fun groupCard(
        title: String,
        badge: String?,
        expanded: Boolean,
    ): Pair<LinearLayout, LinearLayout> {
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = roundRect(Color.WHITE, 14, 1, BORDER)
        }
        val body = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(14), 0, dp(14), dp(14))
            visibility = if (expanded) View.VISIBLE else View.GONE
        }
        val chev = TextView(this).apply {
            text = if (expanded) "▾" else "▸"
            textSize = 12f
            setTextColor(MUTED)
            gravity = Gravity.CENTER
        }
        val head = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(14), dp(14), dp(14), dp(14))
            isClickable = true
            addView(
                TextView(this@AdvancedActivity).apply {
                    text = title
                    textSize = 15f
                    setTextColor(INK)
                    setTypeface(typeface, Typeface.BOLD)
                },
                LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f),
            )
            if (badge != null) {
                addView(
                    TextView(this@AdvancedActivity).apply {
                        text = badge
                        textSize = 10f
                        setTextColor(BLUE)
                        setPadding(dp(5), dp(1), dp(5), dp(1))
                        background = roundRect(Color.parseColor("#EFF5FF"), 5, 1, Color.parseColor("#D7E4FD"))
                    },
                    LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.WRAP_CONTENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT,
                    ).apply { rightMargin = dp(8) },
                )
            }
            addView(
                chev,
                LinearLayout.LayoutParams(dp(14), LinearLayout.LayoutParams.WRAP_CONTENT),
            )
            setOnClickListener {
                val open = body.visibility == View.VISIBLE
                body.visibility = if (open) View.GONE else View.VISIBLE
                chev.text = if (open) "▸" else "▾"
            }
        }
        card.addView(head)
        card.addView(body)
        return card to body
    }

    private fun field(hintText: String): EditText = EditText(this).apply {
        hint = hintText
        textSize = 14f
        setTextColor(INK)
        setHintTextColor(HINT)
        setSingleLine()
        setPadding(dp(12), dp(10), dp(12), dp(10))
        background = roundRect(Color.parseColor("#FBFCFD"), 10, 1, BORDER)
    }

    private fun hintText(text: String): TextView = TextView(this).apply {
        this.text = text
        textSize = 12f
        setTextColor(MUTED)
        setPadding(0, dp(2), 0, dp(6))
    }

    private fun tintedSwitch(): Switch = Switch(this).apply {
        thumbTintList = ColorStateList(
            arrayOf(intArrayOf(android.R.attr.state_checked), intArrayOf()),
            intArrayOf(GREEN, Color.parseColor("#C7CBD1")),
        )
        trackTintList = ColorStateList(
            arrayOf(intArrayOf(android.R.attr.state_checked), intArrayOf()),
            intArrayOf(Color.parseColor("#BBF7D0"), Color.parseColor("#E5E7EB")),
        )
    }

    private fun cardParams(): LinearLayout.LayoutParams = LinearLayout.LayoutParams(
        LinearLayout.LayoutParams.MATCH_PARENT,
        LinearLayout.LayoutParams.WRAP_CONTENT,
    ).apply { bottomMargin = dp(10) }

    private fun roundRect(color: Int, radius: Int, stroke: Int, strokeColor: Int): GradientDrawable =
        GradientDrawable().apply {
            setColor(color)
            cornerRadius = dp(radius).toFloat()
            if (stroke > 0) setStroke(dp(stroke), strokeColor)
        }

    private fun dashedRect(): GradientDrawable = GradientDrawable().apply {
        shape = GradientDrawable.RECTANGLE
        setColor(Color.TRANSPARENT)
        cornerRadius = dp(10).toFloat()
        setStroke(dp(1), Color.parseColor("#C7CBD1"), dp(4).toFloat(), dp(3).toFloat())
    }

    private fun notifyNeedReconnect() {
        if (!Qp2pVpnService.connected) return
        toast("已保存，重连后生效")
    }

    private fun toast(text: String) {
        Toast.makeText(this, text, Toast.LENGTH_SHORT).show()
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).roundToInt()

    companion object {
        private val BG = Color.parseColor("#F4F6F8")
        private val INK = Color.parseColor("#1F2329")
        private val MUTED = Color.parseColor("#8A9099")
        private val HINT = Color.parseColor("#B6BCC5")
        private val BORDER = Color.parseColor("#E3E7EC")
        private val BLUE = Color.parseColor("#2563EB")
        private val GREEN = Color.parseColor("#16A34A")
        private val RED = Color.parseColor("#DC2626")

        /** 与 Rust 侧 `default_stun()` 保持一致 */
        private const val DEFAULT_STUN_TEXT =
            "stun.cloudflare.com:3478\nstun.l.google.com:19302"
    }
}
