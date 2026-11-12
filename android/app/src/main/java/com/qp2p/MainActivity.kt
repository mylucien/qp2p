package com.qp2p

import android.app.Activity
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
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import org.json.JSONObject
import kotlin.math.roundToInt

/**
 * 一页式界面：上面看状态，中间填配置，下面选省电策略。
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
    private lateinit var idleGroup: RadioGroup
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

    @Suppress("DEPRECATION")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor = BG
        window.decorView.systemUiVisibility = View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR
        setContentView(buildRoot())
        loadSettings()
        checkNative()

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
            prefs.edit().putBoolean("keep_online", checked).apply()
            syncPowerUi()
            flash(if (Qp2pVpnService.connected) "已保存，重连后生效" else "已保存")
        }
        idleGroup.setOnCheckedChangeListener { _, checkedId ->
            if (loading || checkedId == View.NO_ID) return@setOnCheckedChangeListener
            prefs.edit().putInt("idle_minutes", minutesOf(checkedId)).apply()
            flash(if (Qp2pVpnService.connected) "已保存，重连后生效" else "已保存")
        }
        powerHint.setOnClickListener { openBatterySettings() }

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
            }
        )
        root.addView(
            TextView(this).apply {
                text = "点对点组网 · 只接管虚拟网段"
                textSize = 13f
                setTextColor(MUTED)
                setPadding(0, dp(2), 0, dp(14))
            }
        )

        root.addView(buildStatusCard())
        root.addView(buildBanner())
        root.addView(buildFormCard(), cardParams(top = 14))
        root.addView(buildPowerCard(), cardParams(top = 12))
        root.addView(
            buildButtons(),
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(14) },
        )

        // 说明贴底：内容不满一屏时也不会在下方留一大块空白
        val footer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.BOTTOM
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                0,
                1f,
            )
            setPadding(0, dp(16), 0, 0)
        }
        footer.addView(
            TextView(this).apply {
                text = "只接管虚拟网段（10.x），公网照旧走系统网络，不做全局代理。\n" +
                    "需要先在有公网的机器上用 qp2p create 建好网络。\n" +
                    "信令地址、令牌、省电策略的改动都在下一次连接时生效。"
                textSize = 12f
                setTextColor(MUTED)
                setLineSpacing(dp(3).toFloat(), 1f)
            }
        )
        root.addView(footer)
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
        workerInput = field(
            "https://你的-worker.workers.dev",
            InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI,
        )
        card.addView(workerInput)

        card.addView(label("加入令牌", top = 14))
        tokenInput = field("qp2p1_home_xxxx", InputType.TYPE_CLASS_TEXT)
        card.addView(tokenInput)

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
            setPadding(dp(2), dp(6), 0, 0)
        }
        card.addView(subnetHint)
        return card
    }

    private fun buildPowerCard(): LinearLayout {
        val card = card()
        card.addView(sectionTitle("省电"))

        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        val left = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        left.addView(
            TextView(this).apply {
                text = "保持在线"
                textSize = 15f
                setTextColor(INK)
            }
        )
        left.addView(
            TextView(this).apply {
                text = "锁屏后也不断开长连接，消息随时能到；会多耗一点电"
                textSize = 12f
                setTextColor(MUTED)
                setPadding(0, dp(3), dp(8), 0)
                setLineSpacing(dp(2).toFloat(), 1f)
            }
        )
        keepSwitch = Switch(this).apply {
            thumbTintList = ColorStateList(
                arrayOf(intArrayOf(android.R.attr.state_checked), intArrayOf()),
                intArrayOf(GREEN, Color.parseColor("#C7CBD1")),
            )
            trackTintList = ColorStateList(
                arrayOf(intArrayOf(android.R.attr.state_checked), intArrayOf()),
                intArrayOf(Color.parseColor("#BBF7D0"), Color.parseColor("#E5E7EB")),
            )
        }
        row.addView(left)
        row.addView(keepSwitch)
        card.addView(row)

        idleLabel = label("空闲多久断开直连", top = 16)
        card.addView(idleLabel)

        idleGroup = RadioGroup(this).apply {
            orientation = LinearLayout.HORIZONTAL
        }
        listOf(10, 30, 60).forEach { minutes ->
            val rb = RadioButton(this).apply {
                id = View.generateViewId()
                text = "$minutes 分钟"
                textSize = 14f
                tag = minutes
                setTextColor(INK)
                buttonTintList = ColorStateList(
                    arrayOf(intArrayOf(android.R.attr.state_checked), intArrayOf()),
                    intArrayOf(GREEN, Color.parseColor("#9CA3AF")),
                )
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            }
            idleGroup.addView(rb)
        }
        card.addView(idleGroup)

        powerHint = TextView(this).apply {
            text = ""
            textSize = 12f
            setTextColor(BLUE)
            setPadding(0, dp(10), 0, 0)
            visibility = View.GONE
        }
        card.addView(powerHint)
        return card
    }

    private fun buildButtons(): LinearLayout {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
        }
        connectButton = Button(this).apply {
            text = "连接"
            textSize = 16f
            isAllCaps = false
            background = roundRect(BLUE, 12)
            setTextColor(Color.WHITE)
            stateListAnimator = null
        }
        saveButton = Button(this).apply {
            text = "保存"
            textSize = 16f
            isAllCaps = false
            background = roundRect(Color.WHITE, 12, 1, BORDER)
            setTextColor(INK)
            stateListAnimator = null
        }
        row.addView(
            connectButton,
            LinearLayout.LayoutParams(0, dp(52), 2f).apply { rightMargin = dp(10) },
        )
        row.addView(saveButton, LinearLayout.LayoutParams(0, dp(52), 1f))
        return row
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

        // 已连接用白底绿框的"断开连接"，绿色始终是"在线"的意思
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
    // 省电
    // ------------------------------------------------------------------

    private fun syncPowerUi() {
        if (!::idleGroup.isInitialized) return
        val keep = keepSwitch.isChecked
        idleGroup.alpha = if (keep) 0.4f else 1f
        for (i in 0 until idleGroup.childCount) {
            idleGroup.getChildAt(i).isEnabled = !keep
        }
        idleLabel.setTextColor(if (keep) HINT else SUBTLE)

        if (keep && !isIgnoringBatteryOptimizations()) {
            powerHint.text = "系统仍可能限制后台：点这里打开电池优化设置，把 qp2p 设为不限制"
            powerHint.visibility = View.VISIBLE
        } else {
            powerHint.visibility = View.GONE
        }
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

    private fun minutesOf(id: Int): Int {
        for (i in 0 until idleGroup.childCount) {
            val child = idleGroup.getChildAt(i)
            if (child.id == id) return child.tag as Int
        }
        return 10
    }

    private fun minutesToId(minutes: Int): Int {
        for (i in 0 until idleGroup.childCount) {
            val child = idleGroup.getChildAt(i)
            if (child.tag as Int == minutes) return child.id
        }
        return idleGroup.getChildAt(0).id
    }

    // ------------------------------------------------------------------
    // 配置
    // ------------------------------------------------------------------

    /** 本地库加载不了的话，后面点什么都没用，先把原因摆出来 */
    private fun checkNative() {
        try {
            Native.isPrepared()
        } catch (t: Throwable) {
            Qp2pVpnService.markError(
                "本地库加载失败：${t.javaClass.simpleName}",
                "APK 可能没装完整（缺 so）；卸载后重装一次",
            )
        }
    }

    private fun loadSettings() {
        loading = true
        workerInput.setText(prefs.getString("worker", ""))
        tokenInput.setText(prefs.getString("token", ""))
        nameInput.setText(prefs.getString("name", ""))
        ipInput.setText(prefs.getString("virtual_ip", ""))
        keepSwitch.isChecked = prefs.getBoolean("keep_online", false)
        idleGroup.check(minutesToId(prefs.getInt("idle_minutes", 10)))
        loading = false
        syncPowerUi()
    }

    private fun saveSettings() {
        prefs.edit()
            .putString("worker", workerInput.text.toString().trim())
            .putString("token", tokenInput.text.toString().trim())
            .putString("name", nameInput.text.toString().trim())
            .putString("virtual_ip", ipInput.text.toString().trim())
            .putBoolean("keep_online", keepSwitch.isChecked)
            .putInt("idle_minutes", minutesOf(idleGroup.checkedRadioButtonId))
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
        val keep = keepSwitch.isChecked
        json.put("keep_online", keep)
        json.put("idle_secs", if (keep) 0 else minutesOf(idleGroup.checkedRadioButtonId) * 60)
        return json.toString()
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
        flash(if (Qp2pVpnService.connected) "已保存，下次连接生效" else "已保存")
    }

    private fun ensurePermissionThenConnect() {
        val problem = validate()
        if (problem != null) {
            showValidationError(problem)
            return
        }
        saveSettings()
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
