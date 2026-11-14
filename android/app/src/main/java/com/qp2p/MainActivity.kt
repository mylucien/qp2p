package com.qp2p

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.StateListDrawable
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.provider.Settings
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.InputMethodManager
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.Switch
import android.widget.TextView
import kotlin.math.roundToInt

/**
 * 一页式界面：状态卡 + 告警条 + 一张连接信息卡片 + 两个按钮。
 *
 * 「自动连接」开关和「连接」按钮是两件事：开关打开则打开 App、以及开机后都自动入网；
 * 开关没打开时，需要手动点「连接」。开机自启由 [BootReceiver] 按这个开关决定。
 *
 * 刻意不引入 AndroidX —— 少一个依赖就少一处 CI 上可能挂的地方。
 * 所有提示都做在页面里（状态卡 + 内联告警条），**不用 Toast、不用对话框**：
 * 连接失败往往发生在锁屏或切到别的应用之后，浮层一闪而过等于没说。
 */
class MainActivity : Activity() {

    private val prefs by lazy { getSharedPreferences("qp2p", MODE_PRIVATE) }
    private val ui = Handler(Looper.getMainLooper())

    private lateinit var scroll: ScrollView
    private lateinit var workerInput: EditText
    private lateinit var tokenInput: EditText
    private lateinit var nameInput: EditText
    private lateinit var ipInput: EditText
    private lateinit var subnetHint: TextView

    private lateinit var statusCard: LinearLayout
    private lateinit var statusDot: View
    private lateinit var statusTitle: TextView
    private lateinit var statusDetail: TextView
    private lateinit var statusAgo: TextView

    private lateinit var banner: LinearLayout
    private lateinit var bannerTitle: TextView
    private lateinit var bannerBody: TextView

    private lateinit var keepSwitch: Switch
    private lateinit var autoSwitch: Switch
    private lateinit var idleSpinner: Spinner
    private lateinit var idleLabel: TextView
    private lateinit var powerHint: TextView

    private lateinit var connectButton: Button
    private lateinit var saveButton: Button

    private var pendingConnect = false

    /** 输入校验错误：优先于服务端状态显示在告警条里 */
    private var localError: String? = null

    /** 用户手动关掉的告警（按内容去重，状态一变就重新出现） */
    private var dismissedKey = ""
    private var noticeText = ""
    private var noticeUntil = 0L
    private var lastPhase: Qp2pVpnService.Phase? = null
    private var lastBannerSig = ""

    /** 加载配置时不要触发"已保存"提示 */
    private var loading = false

    /**
     * 信令地址 / 令牌是否处于「已保存、打码」状态。
     *
     * 打码后框里只有星号，真实值只在 prefs 里；读取一律走 [workerValue] / [tokenValue]，
     * 别直接读输入框，否则会把 `********` 当成配置存进去。
     */
    private var workerMasked = false
    private var tokenMasked = false

    /** 打码状态下的提示行，两个框都没打码时隐藏 */
    private lateinit var maskHint: TextView

    @Suppress("DEPRECATION")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor = BG
        window.decorView.systemUiVisibility = View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR
        setContentView(buildRoot())
        loadSettings()
        checkNative()
        // 电视盒子靠遥控器敲不进令牌，允许 adb 从启动参数里灌（见 applyLaunchExtras）
        val launch = applyLaunchExtras(intent)

        // 手填 IP 实时校验：不合法就把按钮禁掉，别让人点了才看到服务端报错
        ipInput.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) = Unit
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) = Unit
            override fun afterTextChanged(s: Editable?) {
                clearLocalError()
                refreshIpHint()
            }
        })
        listOf(workerInput, tokenInput).forEach { input ->
            input.addTextChangedListener(object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) = Unit
                override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) = Unit
                override fun afterTextChanged(s: Editable?) = clearLocalError()
            })
        }

        // 打码状态下点一下即清空重输。误触不要紧：真实值还在 prefs 里，
        // 退出重进 App 就回到星号状态，不会把已保存的配置弄丢。
        workerInput.setOnClickListener { if (workerMasked) maskWorker(false) }
        tokenInput.setOnClickListener { if (tokenMasked) maskToken(false) }

        connectButton.setOnClickListener {
            if (Qp2pVpnService.connected) {
                disconnect()
            } else {
                ensurePermissionThenConnect()
            }
        }
        saveButton.setOnClickListener { saveOnly() }

        keepSwitch.setOnCheckedChangeListener { _, checked ->
            if (loading) return@setOnCheckedChangeListener
            // 值没变就什么都不做：程序里回设开关也会回调，那不是用户操作
            if (prefs.getBoolean("keep_online", false) == checked) return@setOnCheckedChangeListener
            prefs.edit().putBoolean("keep_online", checked).apply()
            syncPowerUi()
            flash(if (Qp2pVpnService.connected) "已保存，重连后生效" else "已保存")
        }
        autoSwitch.setOnCheckedChangeListener { _, checked ->
            if (loading) return@setOnCheckedChangeListener
            if (prefs.getBoolean("auto_connect", false) == checked) return@setOnCheckedChangeListener
            prefs.edit().putBoolean("auto_connect", checked).apply()
            flash(if (checked) "已保存，下次打开 App 直接入网" else "已保存")
        }
        idleSpinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(
                parent: AdapterView<*>?, view: View?, position: Int, id: Long
            ) {
                if (loading) return
                val minutes = IDLE_MINUTES.getOrElse(position) { IDLE_MINUTES[0] }
                // Spinner 要等第一次布局完成才发这次回调，所以它总在 post 之后到达。
                // 靠标志位挡不住，只能比"值变了没"——这就是以前一打开 App 就弹
                // 「已保存」的原因。
                if (prefs.getInt("idle_minutes", 10) == minutes) return
                prefs.edit().putInt("idle_minutes", minutes).apply()
                flash(if (Qp2pVpnService.connected) "已保存，重连后生效" else "已保存")
            }

            override fun onNothingSelected(parent: AdapterView<*>?) = Unit
        }
        powerHint.setOnClickListener { openBatterySettings() }

        // 「自动连接」在 App 冷启动时生效：旋转屏幕、VPN 授权回来都不重复触发。
        // 已连上时不重复发起；Service 侧也做了幂等，防止 App 进程重建再次拉起隧道。
        // `-e connect 1` 与「自动连接」等价，但只对这一次启动有效，不改持久开关。
        if (savedInstanceState == null &&
            (prefs.getBoolean("auto_connect", false) || launch.connect) &&
            !Qp2pVpnService.connected
        ) {
            ui.post { ensurePermissionThenConnect() }
        }

        // 状态由 Service 在后台更新，这里定时捞一次，省掉跨进程广播的复杂度
        ui.post(object : Runnable {
            override fun run() {
                renderStatus()
                ui.postDelayed(this, 500)
            }
        })
    }

    override fun onDestroy() {
        ui.removeCallbacksAndMessages(null)
        super.onDestroy()
    }

    /** 已经在运行时又被 adb 拉起来一次（比如换了令牌）：不重建界面，直接填进去。 */
    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        if (intent != null) setIntent(intent)
        val launch = applyLaunchExtras(intent)
        if (launch.connect && !Qp2pVpnService.connected && !pendingConnect) {
            ui.post { ensurePermissionThenConnect() }
        }
    }

    // ------------------------------------------------------------------
    // 启动参数（电视盒子 / 电视用 adb 灌配置，遥控器敲不进令牌）
    // ------------------------------------------------------------------

    private class LaunchConfig(val filled: Boolean, val connect: Boolean)

    /**
     * 从启动参数里读配置，读到就立即落盘，省得下次再敲一遍。认这几个 key：
     *
     *     adb shell am start -n com.qp2p/.MainActivity \
     *         -e worker https://p2p.example.com -e token qp2p1_home_xxx \
     *         -e name tvbox -e connect 1
     *
     * 也接受电脑上 `qp2p create` 打印的那种整链接，一次给完：
     *
     *     adb shell am start -n com.qp2p/.MainActivity \
     *         -e join "https://p2p.example.com/?token=qp2p1_home_xxx"
     *
     * `connect` 只对这一次启动生效，不改「自动连接」那个持久开关。
     */
    private fun applyLaunchExtras(intent: Intent?): LaunchConfig {
        val from = intent ?: return LaunchConfig(false, false)
        fun extra(key: String): String = from.getStringExtra(key)?.trim().orEmpty()

        var filled = false
        extra("join").takeIf { it.isNotEmpty() }?.let { link ->
            parseJoinLink(link)?.let { (worker, token) ->
                revealWorker(worker)
                revealToken(token)
                filled = true
            }
        }
        extra("worker").takeIf { it.isNotEmpty() }?.let {
            revealWorker(it)
            filled = true
        }
        extra("token").takeIf { it.isNotEmpty() }?.let {
            revealToken(it)
            filled = true
        }
        extra("name").takeIf { it.isNotEmpty() }?.let {
            nameInput.setText(it)
            filled = true
        }
        // 灌进去就算存过：和界面上点保存一致，立刻打码
        if (filled) {
            saveSettings()
            maskSavedSecrets()
        }

        val connect = extra("connect").lowercase().let { it == "1" || it == "true" || it == "yes" }
        return LaunchConfig(filled, connect)
    }

    /** `https://host/?token=qp2p1_xxx` → (https://host, qp2p1_xxx)；形状不对返回 null */
    private fun parseJoinLink(link: String): Pair<String, String>? {
        val q = link.indexOf('?')
        if (q <= 0) return null
        val worker = link.substring(0, q).trimEnd('/')
        if (!worker.startsWith("https://")) return null
        val marker = "token="
        val at = link.indexOf(marker, q)
        if (at < 0) return null
        val token = link.substring(at + marker.length).substringBefore('&').trim()
        if (!token.startsWith("qp2p1_")) return null
        return worker to token
    }

    // ------------------------------------------------------------------
    // 界面
    // ------------------------------------------------------------------

    private fun buildRoot(): View {
        scroll = ScrollView(this).apply {
            isFillViewport = true
            setBackgroundColor(BG)
        }
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.MATCH_PARENT,
            )
            setPadding(dp(20), dp(18), dp(20), dp(16))
        }
        scroll.addView(root)

        root.addView(
            TextView(this).apply {
                text = "qp2p"
                textSize = 24f
                setTextColor(INK)
                setTypeface(typeface, Typeface.BOLD)
                setPadding(0, 0, 0, dp(14))
            }
        )

        root.addView(buildStatusCard())
        root.addView(buildBanner())
        root.addView(buildFormCard(), cardParams(top = 2))
        root.addView(
            buildButtons(),
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(14) },
        )
        return scroll
    }

    private fun buildStatusCard(): LinearLayout {
        statusCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(14), dp(16), dp(14))
        }

        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        statusDot = View(this).apply {
            background = dot(Color.parseColor("#9CA3AF"))
            layoutParams = LinearLayout.LayoutParams(dp(12), dp(12)).apply { rightMargin = dp(10) }
        }
        statusTitle = TextView(this).apply {
            text = "未连接"
            textSize = 20f
            setTextColor(INK)
            setTypeface(typeface, Typeface.BOLD)
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        statusAgo = TextView(this).apply {
            text = ""
            textSize = 13f
            setTextColor(MUTED)
        }
        row.addView(statusDot)
        row.addView(statusTitle)
        row.addView(statusAgo)
        statusCard.addView(row)

        statusDetail = TextView(this).apply {
            text = "填好下面的信息，点连接"
            textSize = 13f
            setTextColor(MUTED)
            setPadding(0, dp(6), 0, 0)
        }
        statusCard.addView(statusDetail)
        return statusCard
    }

    private fun buildBanner(): LinearLayout {
        banner = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            visibility = View.GONE
            setPadding(dp(14), dp(12), dp(10), dp(12))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(12) }
        }
        val texts = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        bannerTitle = TextView(this).apply {
            textSize = 14f
            setTypeface(typeface, Typeface.BOLD)
        }
        bannerBody = TextView(this).apply {
            textSize = 13f
            setPadding(0, dp(3), 0, 0)
            setLineSpacing(dp(2).toFloat(), 1f)
        }
        texts.addView(bannerTitle)
        texts.addView(bannerBody)

        val close = TextView(this).apply {
            text = "✕"
            textSize = 16f
            setTextColor(MUTED)
            setPadding(dp(10), 0, dp(4), 0)
            setOnClickListener {
                dismissedKey = bannerKey()
                renderBanner()
            }
        }
        banner.addView(texts)
        banner.addView(close)
        return banner
    }

    private fun buildFormCard(): LinearLayout {
        val card = card()

        card.addView(sectionTitle("连接信息"))

        card.addView(label("信令地址"))
        workerInput = field("https://你的-worker.workers.dev", WORKER_TYPE)
        // 关掉 View 状态自动恢复：旋转屏幕/重建会从 savedInstanceState 把明文捞回来，
        // 那等于打码白做。这两个框的显示状态一律由 loadSettings 决定。
        workerInput.isSaveEnabled = false
        card.addView(workerInput)

        card.addView(label("加入令牌", top = 14))
        tokenInput = field("qp2p1_home_xxxx", TOKEN_TYPE)
        tokenInput.isSaveEnabled = false
        card.addView(tokenInput)

        // 打码后必须让人知道怎么改回来，否则会以为配置丢了
        maskHint = TextView(this).apply {
            text = "地址与令牌已隐藏：点方框即清空，重新输入后保存"
            textSize = 12f
            setTextColor(MUTED)
            setPadding(dp(2), dp(8), 0, 0)
            visibility = View.GONE
        }
        card.addView(maskHint)

        card.addView(label("本机名称（可留空）", top = 14))
        nameInput = field("phone", InputType.TYPE_CLASS_TEXT)
        card.addView(nameInput)

        card.addView(label("虚拟 IP（可留空，自动分配）", top = 14))
        ipInput = field("留空 = 服务端分配，如 10.78.0.50", InputType.TYPE_CLASS_TEXT)
        card.addView(ipInput)

        subnetHint = TextView(this).apply {
            text = ""
            setTextColor(MUTED)
            textSize = 12f
            setPadding(dp(2), dp(6), 0, dp(2))
        }
        card.addView(subnetHint)

        card.addView(
            View(this).apply {
                setBackgroundColor(BORDER)
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT, dp(1)
                ).apply {
                    topMargin = dp(10)
                    bottomMargin = dp(14)
                }
            }
        )

        keepSwitch = tintedSwitch()
        card.addView(switchRow("保持在线", keepSwitch))

        val idleRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply { bottomMargin = dp(12) }
        }
        idleLabel = TextView(this).apply {
            text = "直连保持"
            textSize = 15f
            setTextColor(INK)
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        idleSpinner = Spinner(this).apply {
            background = roundRect(Color.parseColor("#FBFCFD"), 10, 1, BORDER)
            setPadding(dp(12), dp(6), dp(12), dp(6))
        }
        val labels = IDLE_MINUTES.map { "$it 分钟" }
        val adapter = object : ArrayAdapter<String>(
            this@MainActivity, android.R.layout.simple_spinner_item, labels
        ) {
            override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
                val v = super.getView(position, convertView, parent) as TextView
                v.text = "${labels[position]}  ▾"
                v.setTextColor(INK)
                v.textSize = 15f
                return v
            }
        }
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        idleSpinner.adapter = adapter
        idleRow.addView(idleLabel)
        idleRow.addView(idleSpinner)
        card.addView(idleRow)

        autoSwitch = tintedSwitch()
        card.addView(switchRow("自动连接", autoSwitch))

        // 只有选了「保持在线」且系统确实限制后台时才出现，平时不占版面
        powerHint = TextView(this).apply {
            text = "系统仍可能限制后台：点这里打开电池优化设置，把 qp2p 设为不限制"
            textSize = 12f
            setTextColor(BLUE)
            visibility = View.GONE
        }
        card.addView(powerHint)
        return card
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

    private fun switchRow(text: String, sw: Switch): LinearLayout {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply { bottomMargin = dp(12) }
        }
        row.addView(
            TextView(this).apply {
                this.text = text
                textSize = 15f
                setTextColor(INK)
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            }
        )
        row.addView(sw)
        return row
    }

    private fun buildButtons(): LinearLayout {
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }
        saveButton = Button(this).apply {
            text = "保存配置"
            textSize = 16f
            isAllCaps = false
            background = roundRect(Color.WHITE, 12, 1, BORDER)
            setTextColor(INK)
            stateListAnimator = null
        }
        connectButton = Button(this).apply {
            text = "连接"
            textSize = 16f
            isAllCaps = false
            background = roundRect(BLUE, 12)
            setTextColor(Color.WHITE)
            stateListAnimator = null
        }
        col.addView(
            saveButton,
            LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(52)),
        )
        col.addView(
            connectButton,
            LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(52)).apply {
                topMargin = dp(10)
            },
        )
        return col
    }

    private fun card() = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        background = roundRect(Color.WHITE, 14, 1, BORDER)
        setPadding(dp(16), dp(14), dp(16), dp(16))
    }

    private fun cardParams(top: Int) = LinearLayout.LayoutParams(
        LinearLayout.LayoutParams.MATCH_PARENT,
        LinearLayout.LayoutParams.WRAP_CONTENT,
    ).apply { topMargin = dp(top) }

    private fun sectionTitle(text: String) = TextView(this).apply {
        this.text = text
        textSize = 12f
        setTextColor(MUTED)
        letterSpacing = 0.08f
        setTypeface(typeface, Typeface.BOLD)
        setPadding(0, 0, 0, dp(4))
    }

    private fun label(text: String, top: Int = 0) = TextView(this).apply {
        this.text = text
        textSize = 13f
        setTextColor(SUBTLE)
        setPadding(dp(2), dp(top), 0, dp(6))
    }

    private fun field(hintText: String, type: Int) = EditText(this).apply {
        hint = hintText
        inputType = type
        textSize = 16f
        setTextColor(INK)
        setHintTextColor(HINT)
        setSingleLine()
        setPadding(dp(14), dp(13), dp(14), dp(13))
        background = inputBg()
        minHeight = dp(50)
    }

    private fun inputBg(): StateListDrawable {
        val focused = roundRect(Color.WHITE, 10, 2, BLUE)
        val normal = roundRect(Color.parseColor("#FBFCFD"), 10, 1, BORDER)
        return StateListDrawable().apply {
            addState(intArrayOf(android.R.attr.state_focused), focused)
            addState(intArrayOf(), normal)
        }
    }

    private fun roundRect(fill: Int, radiusDp: Int, strokeDp: Int = 0, stroke: Int = 0) =
        GradientDrawable().apply {
            shape = GradientDrawable.RECTANGLE
            setColor(fill)
            cornerRadius = dp(radiusDp).toFloat()
            if (strokeDp > 0) setStroke(dp(strokeDp), stroke)
        }

    private fun dot(color: Int) = GradientDrawable().apply {
        shape = GradientDrawable.OVAL
        setColor(color)
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).roundToInt()

    // ------------------------------------------------------------------
    // 状态渲染
    // ------------------------------------------------------------------

    private fun renderStatus() {
        val phase = Qp2pVpnService.phase
        if (phase != lastPhase) {
            lastPhase = phase
            applyPhase(phase)
            // 状态变了，之前关掉的告警应该重新出现
            dismissedKey = ""
            renderBanner()
        }

        if (phase == Qp2pVpnService.Phase.CONNECTED) {
            val at = Qp2pVpnService.connectedAt
            statusAgo.text = if (at > 0) humanDuration(System.currentTimeMillis() - at) else ""
        } else {
            statusAgo.text = ""
            // 连接中/出错时 detail 会变（"正在注册…" → "正在建立隧道…"），
            // 阶段没变也要跟着更新，否则界面停在第一句上
            if (phase != Qp2pVpnService.Phase.IDLE) {
                statusDetail.text = Qp2pVpnService.detail
            }
        }
        // 提示条的过期、错误内容变化都在这里兜住
        renderBanner()
    }

    private fun applyPhase(phase: Qp2pVpnService.Phase) {
        val (main, soft, deep) = when (phase) {
            Qp2pVpnService.Phase.CONNECTED ->
                Triple(GREEN, Color.parseColor("#F0FDF4"), Color.parseColor("#BBF7D0"))
            Qp2pVpnService.Phase.CONNECTING ->
                Triple(AMBER, Color.parseColor("#FFFBEB"), Color.parseColor("#FDE68A"))
            Qp2pVpnService.Phase.ERROR ->
                Triple(RED, Color.parseColor("#FEF2F2"), Color.parseColor("#FECACA"))
            Qp2pVpnService.Phase.IDLE ->
                Triple(Color.parseColor("#9CA3AF"), Color.WHITE, BORDER)
        }

        statusDot.background = dot(main)
        statusCard.background = roundRect(soft, 14, 1, deep)
        statusTitle.text = when (phase) {
            Qp2pVpnService.Phase.CONNECTED -> "已连接"
            Qp2pVpnService.Phase.CONNECTING -> "连接中"
            Qp2pVpnService.Phase.ERROR -> "连接失败"
            Qp2pVpnService.Phase.IDLE -> "未连接"
        }
        statusTitle.setTextColor(if (phase == Qp2pVpnService.Phase.IDLE) INK else main)

        statusDetail.text = when (phase) {
            Qp2pVpnService.Phase.CONNECTED ->
                listOf(Qp2pVpnService.virtualIp, Qp2pVpnService.cidr)
                    .filter { it.isNotEmpty() }
                    .joinToString(" · ")
                    .ifEmpty { Qp2pVpnService.detail }
            Qp2pVpnService.Phase.IDLE -> "填好下面的信息，点连接"
            else -> Qp2pVpnService.detail
        }

        // 已连接时切成白底绿框的「断开连接」；平时一律叫「连接」。
        // 按钮就叫「连接」，别和上面的「自动连接」开关混。
        connectButton.text = if (phase == Qp2pVpnService.Phase.CONNECTED) "断开连接" else "连接"
        if (phase == Qp2pVpnService.Phase.CONNECTED) {
            connectButton.background = roundRect(Color.WHITE, 12, 1, GREEN)
            connectButton.setTextColor(GREEN)
        } else if (phase == Qp2pVpnService.Phase.CONNECTING) {
            connectButton.background = roundRect(Color.parseColor("#93C5FD"), 12)
            connectButton.setTextColor(Color.WHITE)
            connectButton.isEnabled = false
        } else {
            connectButton.background = roundRect(BLUE, 12)
            connectButton.setTextColor(Color.WHITE)
        }
        if (phase != Qp2pVpnService.Phase.CONNECTING) {
            connectButton.isEnabled = true
        }
        syncPowerUi()
    }

    private fun bannerKey(): String =
        Qp2pVpnService.phase.name + "|" + Qp2pVpnService.detail + "|" + (localError ?: "")

    private fun renderBanner() {
        val phase = Qp2pVpnService.phase
        val now = System.currentTimeMillis()

        // 内容没变就别每 500ms 重建一次圆角背景
        val sig = when {
            localError != null -> "local|$localError"
            now < noticeUntil && noticeText.isNotEmpty() -> "notice|$noticeText"
            phase == Qp2pVpnService.Phase.ERROR && dismissedKey != bannerKey() ->
                "error|${Qp2pVpnService.detail}|${Qp2pVpnService.advice}"
            else -> "none"
        }
        if (sig == lastBannerSig) return
        lastBannerSig = sig

        // 1) 用户刚填错：最优先，改任何一个输入框就消失
        val local = localError
        if (local != null) {
            showBanner(
                Color.parseColor("#FEF2F2"),
                Color.parseColor("#FECACA"),
                RED,
                "填错了",
                local,
                closable = false,
            )
            return
        }

        // 2) 保存/切换成功之类的即时反馈，3 秒后自己消失
        if (now < noticeUntil && noticeText.isNotEmpty()) {
            showBanner(
                Color.parseColor("#F0FDF4"),
                Color.parseColor("#BBF7D0"),
                GREEN,
                noticeText,
                "",
                closable = false,
            )
            return
        }

        // 3) 连接出错：一直留着，直到恢复或用户手动关掉
        if (phase == Qp2pVpnService.Phase.ERROR) {
            if (dismissedKey == bannerKey()) {
                banner.visibility = View.GONE
                return
            }
            showBanner(
                Color.parseColor("#FEF2F2"),
                Color.parseColor("#FECACA"),
                RED,
                Qp2pVpnService.detail.ifEmpty { "连接失败" },
                Qp2pVpnService.advice,
                closable = true,
            )
            return
        }

        banner.visibility = View.GONE
    }

    private fun showBanner(
        bg: Int,
        stroke: Int,
        fg: Int,
        title: String,
        body: String,
        closable: Boolean,
    ) {
        banner.visibility = View.VISIBLE
        banner.background = roundRect(bg, 12, 1, stroke)
        bannerTitle.text = title
        bannerTitle.setTextColor(fg)
        if (body.isEmpty()) {
            bannerBody.visibility = View.GONE
        } else {
            bannerBody.visibility = View.VISIBLE
            bannerBody.text = body
            bannerBody.setTextColor(fg)
        }
        // 关闭按钮只对"服务端错误"有意义；本地校验错误改输入就没了
        banner.getChildAt(1).visibility = if (closable) View.VISIBLE else View.GONE
    }

    /** 保存成功的绿色提示，3 秒后自动收起 */
    private fun flash(text: String) {
        noticeText = text
        noticeUntil = System.currentTimeMillis() + 3000
        renderBanner()
    }

    private fun clearLocalError() {
        if (localError != null) {
            localError = null
            renderBanner()
        }
    }

    private fun humanDuration(ms: Long): String {
        val s = (ms / 1000).coerceAtLeast(0)
        return when {
            s < 60 -> "${s}秒"
            s < 3600 -> "${s / 60}分钟"
            else -> "${s / 3600}小时${(s % 3600) / 60}分"
        }
    }

    // ------------------------------------------------------------------
    // 连接行为
    // ------------------------------------------------------------------

    private fun syncPowerUi() {
        if (!::idleSpinner.isInitialized) return
        val keep = keepSwitch.isChecked
        idleSpinner.isEnabled = !keep
        idleSpinner.alpha = if (keep) 0.4f else 1f
        idleLabel.setTextColor(if (keep) HINT else INK)
        // 电池优化提示只在选了「保持在线」且系统确实限制后台时才出现
        powerHint.visibility =
            if (keep && !isIgnoringBatteryOptimizations()) View.VISIBLE else View.GONE
    }

    private fun isIgnoringBatteryOptimizations(): Boolean = try {
        val pm = getSystemService(PowerManager::class.java)
        pm?.isIgnoringBatteryOptimizations(packageName) ?: true
    } catch (_: Throwable) {
        true
    }

    /** 打开系统列表页，不弹任何对话框，也不申请白名单权限 */
    private fun openBatterySettings() {
        try {
            startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
        } catch (_: Throwable) {
            flash("这台机器没有电池优化设置页")
        }
    }

    private fun idleMinutes(): Int =
        IDLE_MINUTES.getOrElse(idleSpinner.selectedItemPosition) { IDLE_MINUTES[0] }

    private fun idlePosition(minutes: Int): Int =
        IDLE_MINUTES.indexOf(minutes).coerceAtLeast(0)

    // ------------------------------------------------------------------
    // 配置
    // ------------------------------------------------------------------

    /** 本地库加载不了的话，后面点什么都没用，先把原因摆出来 */
    private fun checkNative() {
        try {
            Native.isPrepared()
        } catch (t: Throwable) {
            // 真实原因全在 message 里（比如 "dlopen failed: cannot locate symbol ..."），
            // 只显示类名等于把唯一的线索扔了。
            Qp2pVpnService.markError(
                "本地库加载失败：${t.javaClass.simpleName}",
                t.message?.lineSequence()?.firstOrNull()?.take(200)
                    ?: "APK 可能没装完整（缺 so）；卸载后重装一次",
            )
        }
    }

    private fun loadSettings() {
        loading = true
        // 存过就一律打码：不因为"重新打开了 App"就把明文又摆出来一次
        val worker = prefs.getString("worker", "").orEmpty().trim()
        val token = prefs.getString("token", "").orEmpty().trim()
        maskWorker(worker.isNotEmpty(), focus = false)
        maskToken(token.isNotEmpty(), focus = false)
        nameInput.setText(prefs.getString("name", ""))
        ipInput.setText(prefs.getString("virtual_ip", ""))
        keepSwitch.isChecked = prefs.getBoolean("keep_online", false)
        autoSwitch.isChecked = prefs.getBoolean("auto_connect", false)
        idleSpinner.setSelection(idlePosition(prefs.getInt("idle_minutes", 10)))
        loading = false
        syncPowerUi()
    }

    private fun saveSettings() {
        prefs.edit()
            .putString("worker", workerValue())
            .putString("token", tokenValue())
            .putString("name", nameInput.text.toString().trim())
            .putString("virtual_ip", ipInput.text.toString().trim())
            .putBoolean("keep_online", keepSwitch.isChecked)
            .putBoolean("auto_connect", autoSwitch.isChecked)
            .putInt("idle_minutes", idleMinutes())
            .apply()
    }

    // ------------------------------------------------------------------
    // 信令地址 / 令牌打码
    // ------------------------------------------------------------------

    /**
     * 掩码状态下框里只有星号，真实值只在 prefs 里。
     *
     * 所以读配置一律走这两个函数，**不能**直接读输入框——否则会把 `********`
     * 当成地址存进 prefs，下次连接直接连到不存在的域名。
     */
    private fun workerValue(): String =
        if (workerMasked) prefs.getString("worker", "").orEmpty().trim()
        else workerInput.text.toString().trim()

    private fun tokenValue(): String =
        if (tokenMasked) prefs.getString("token", "").orEmpty().trim()
        else tokenInput.text.toString().trim()

    /** 配置已落盘：把有值的字段打成星号。保存和连接都走这里，两条路径行为一致。 */
    private fun maskSavedSecrets() {
        if (prefs.getString("worker", "").orEmpty().isNotEmpty()) maskWorker(true)
        if (prefs.getString("token", "").orEmpty().isNotEmpty()) maskToken(true)
    }

    private fun maskWorker(masked: Boolean, focus: Boolean = true) {
        workerMasked = masked
        if (masked) applyMask(workerInput) else prepareForEdit(workerInput, WORKER_TYPE, focus)
        refreshMaskHint()
    }

    private fun maskToken(masked: Boolean, focus: Boolean = true) {
        tokenMasked = masked
        if (masked) applyMask(tokenInput) else prepareForEdit(tokenInput, TOKEN_TYPE, focus)
        refreshMaskHint()
    }

    /**
     * 打码：固定 8 个星号（不透露真实长度），同时关掉焦点、光标、长按——
     * 长按菜单里能「复制」，关了才真的拿不到。点击保留，用来清空重输。
     */
    private fun applyMask(input: EditText) {
        input.setTextIsSelectable(false)
        input.setText(MASK_TEXT)
        input.inputType = InputType.TYPE_NULL
        input.isFocusable = false
        input.isFocusableInTouchMode = false
        input.isLongClickable = false
        input.isClickable = true
        input.setTextColor(MUTED)
    }

    /** adb 灌进来的值：先按明文放好（后面 saveSettings + maskSavedSecrets 统一打码） */
    private fun revealWorker(text: String) {
        workerInput.setText(text)
        restoreEditable(workerInput, WORKER_TYPE)
        workerMasked = false
        refreshMaskHint()
    }

    private fun revealToken(text: String) {
        tokenInput.setText(text)
        restoreEditable(tokenInput, TOKEN_TYPE)
        tokenMasked = false
        refreshMaskHint()
    }

    /** 只恢复可编辑属性，不动已有文本 */
    private fun restoreEditable(input: EditText, type: Int) {
        input.inputType = type
        input.isFocusable = true
        input.isFocusableInTouchMode = true
        input.isLongClickable = true
        input.isClickable = true
        input.setTextIsSelectable(true)
        input.setTextColor(INK)
    }

    /**
     * 清空成空框并恢复可编辑。
     *
     * [focus] 为 false 时只恢复属性、不抢焦点——进 App 加载配置时字段本来可能为空，
     * 那时候弹软键盘、把光标塞进去只会让人以为出错了。
     */
    private fun prepareForEdit(input: EditText, type: Int, focus: Boolean) {
        input.setText("")
        input.inputType = type
        input.isFocusable = true
        input.isFocusableInTouchMode = true
        input.isLongClickable = true
        input.isClickable = true
        input.setTextIsSelectable(true)
        input.setTextColor(INK)
        if (!focus) return
        input.requestFocus()
        // 电视盒子常常没软键盘，这步失败也无所谓
        (getSystemService(Context.INPUT_METHOD_SERVICE) as? InputMethodManager)
            ?.showSoftInput(input, InputMethodManager.SHOW_IMPLICIT)
    }

    private fun refreshMaskHint() {
        if (!::maskHint.isInitialized) return
        maskHint.visibility = if (workerMasked || tokenMasked) View.VISIBLE else View.GONE
    }

    /** 拼装交给 [AppConfig]：开机自启那条路径用的必须是同一份字段，别在两处各写一遍 */
    private fun configJson(): String {
        val keep = keepSwitch.isChecked
        return AppConfig.build(
            worker = workerValue().trimEnd('/'),
            token = tokenValue(),
            name = nameInput.text.toString().trim(),
            virtualIp = ipInput.text.toString().trim(),
            dataDir = filesDir.absolutePath,
            keepOnline = keep,
            idleMinutes = idleMinutes(),
        )
    }

    // ------------------------------------------------------------------
    // 校验
    // ------------------------------------------------------------------

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
        subnetHint.setTextColor(if (problem != null) RED else MUTED)
    }

    /**
     * 逐字段校验，返回第一处问题的说明；全部合法返回 null。
     *
     * 只报告、不自动纠正——静默改写用户填的地址比直接报错更难排查。
     */
    private fun validate(): String? {
        val worker = workerValue()
        if (worker.isEmpty()) return "请填写信令地址（Worker 地址）"
        // 只接受 https：Rust 侧 normalize_worker 同样拒绝明文地址，两端保持一致
        if (!worker.startsWith("https://")) {
            return "信令地址要以 https:// 开头，例如 https://p2p.example.com"
        }
        val host = worker.removePrefix("https://").substringBefore("/")
        if (!host.contains(".") || host.startsWith(".") || host.endsWith(".")) {
            return "信令地址不完整，例如 https://p2p.example.com"
        }
        val token = tokenValue()
        if (token.isEmpty()) return "请填写加入令牌"
        if (!token.startsWith("qp2p1_")) return "令牌应以 qp2p1_ 开头"
        if (token.count { it == '_' } < 2) return "令牌格式应为 qp2p1_<网络>_<密钥>"
        ipProblem(ipInput.text.toString().trim())?.let { return "虚拟 IP：$it" }
        return null
    }

    private fun showValidationError(problem: String) {
        localError = problem
        renderBanner()
        scroll.smoothScrollTo(0, 0)
    }

    // ------------------------------------------------------------------
    // 动作
    // ------------------------------------------------------------------

    /** 只保存、不连接。连接中点也可以保存，改动下次连接生效。 */
    private fun saveOnly() {
        val problem = validate()
        if (problem != null) {
            showValidationError(problem)
            return
        }
        saveSettings()
        maskSavedSecrets()
        flash(if (Qp2pVpnService.connected) "已保存，下次连接生效" else "已保存")
    }

    private fun ensurePermissionThenConnect() {
        val problem = validate()
        if (problem != null) {
            showValidationError(problem)
            return
        }
        saveSettings()
        maskSavedSecrets()
        val intent = VpnService.prepare(this)
        if (intent != null) {
            // 第一次用会弹系统授权框（系统行为，无法内联）
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
            showValidationError(problem)
            return
        }
        saveSettings()
        val config = configJson()
        // 配置已进 prefs，先取好 JSON 再打码（打码只动界面，prefs 里仍是明文那次快照）
        maskSavedSecrets()
        val intent = Intent(this, Qp2pVpnService::class.java).apply {
            action = Qp2pVpnService.ACTION_CONNECT
            putExtra(Qp2pVpnService.EXTRA_CONFIG, config)
        }
        try {
            startService(intent)
        } catch (t: Throwable) {
            Qp2pVpnService.markError(
                "启动服务失败：${t.javaClass.simpleName}",
                t.message ?: "详情见 logcat 里 qp2p 标记的日志",
            )
        }
    }

    private fun disconnect() {
        Qp2pVpnService.markIdle("正在断开…")
        try {
            Native.stop()
            startService(
                Intent(this, Qp2pVpnService::class.java).apply {
                    action = Qp2pVpnService.ACTION_DISCONNECT
                }
            )
        } catch (t: Throwable) {
            Qp2pVpnService.markError(
                "断开失败",
                t.message ?: "再点一次，或直接关掉 App",
            )
        }
    }

    @Deprecated("VpnService 授权沿用旧回调，够用")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN && pendingConnect) {
            pendingConnect = false
            if (resultCode == RESULT_OK) {
                connect()
            } else {
                Qp2pVpnService.markError(
                    "你拒绝了 VPN 授权",
                    "没有这个授权就建不了虚拟网卡；再点一次连接可以重新授权",
                )
            }
        }
    }

    private companion object {
        const val REQUEST_VPN = 1001

        /** 打码后框里固定显示这个：不给长度信息，两个框长得一样 */
        const val MASK_TEXT = "********"

        /** 从掩码恢复成可编辑时要按原类型设回去，否则 URI 键盘和令牌输入会串 */
        val WORKER_TYPE = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
        val TOKEN_TYPE = InputType.TYPE_CLASS_TEXT

        val IDLE_MINUTES = listOf(10, 30, 60)

        val BG = Color.parseColor("#F4F6F8")
        val INK = Color.parseColor("#1F2329")
        val SUBTLE = Color.parseColor("#4B5563")
        val MUTED = Color.parseColor("#8A9099")
        val HINT = Color.parseColor("#B6BCC5")
        val BORDER = Color.parseColor("#E3E7EC")
        val BLUE = Color.parseColor("#2563EB")
        val GREEN = Color.parseColor("#16A34A")
        val AMBER = Color.parseColor("#D97706")
        val RED = Color.parseColor("#DC2626")
    }
}
