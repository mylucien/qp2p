//! 把 qp2p.ico 编进 Windows exe 的资源表。
//!
//! 只影响"文件本身长什么样"（资源管理器、任务栏、Alt+Tab）。窗口和托盘图标是
//! 运行期用 `LoadImageW` 加载的，不依赖这里。找不到 rc.exe 时只警告不报错——
//! 图标是锦上添花，不该让整个构建失败。

fn main() {
    println!("cargo:rerun-if-changed=../../assets/qp2p.ico");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let mut res = winresource::WindowsResource::new();
    res.set_icon("../../assets/qp2p.ico");
    res.set("ProductName", "qp2p");
    res.set("FileDescription", "qp2p private mesh");
    res.set("LegalCopyright", "");
    if let Err(e) = res.compile() {
        println!("cargo:warning=exe 图标没编进去（{e}），会用系统默认图标");
    }
}
