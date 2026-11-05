package com.qp2p

/**
 * 与 Rust 侧的 JNI 门面一一对应（crates/android/src/lib.rs）。
 *
 * 分两步走是 Android 的硬约束：VpnService 必须先知道虚拟地址和网段才能建接口，
 * 而这两个值是注册时服务端给的。所以先 prepare() 换地址，再用这个地址建接口，
 * 最后把接口的 fd 交给 start()。
 */
object Native {
    init {
        System.loadLibrary("qp2p_android")
    }

    /** 返回 {"node_id":..,"virtual_ip":..,"cidr":..,"prefix":..,"mtu":..} 或 {"error":".."} */
    external fun prepare(configJson: String): String

    /** 阻塞到断开；成功返回 null，失败返回错误文本 */
    external fun start(fd: Int): String?

    /** 置停止位，start() 最多 3 秒内退出 */
    external fun stop()

    external fun isPrepared(): Boolean
}
