//! 把 qp2p.ico 和应用程序清单编进 Windows exe 的资源表。
//!
//! 清单里声明 `requireAdministrator`：双击就弹 UAC，进程（以及它拉起的 `up`
//! 子进程）从一开始就是管理员，创建 Wintun 虚拟网卡不需要再单独提权。
//!
//! 只影响 Windows 目标；找不到 rc.exe 时只警告不报错——图标和清单是锦上添花，
//! 不该让整个构建失败。

/// 应用程序清单：
/// - requireAdministrator：创建虚拟网卡需要管理员，双击即提权；
/// - Common-Controls 6.0：按钮/列表用系统视觉样式，不然是 Win95 那种灰方块；
/// - per-monitor v2 DPI：高分屏字不糊；
/// - 声明 Win10/11 支持，避免系统按兼容模式跑。
const MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="qp2p" version="1.0.0.0" processorArchitecture="*"/>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
      <supportedOS Id="{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}"/>
      <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/>
      <supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"/>
    </application>
  </compatibility>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls"
                        version="6.0.0.0" processorArchitecture="*"
                        publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">permonitorv2</dpiAwareness>
      <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>
    </windowsSettings>
  </application>
</assembly>
"#;

fn main() {
    println!("cargo:rerun-if-changed=../../assets/qp2p.ico");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let mut res = winresource::WindowsResource::new();
    res.set_icon("../../assets/qp2p.ico");
    res.set_manifest(MANIFEST);
    res.set("ProductName", "qp2p");
    res.set("FileDescription", "qp2p private mesh");
    if let Err(e) = res.compile() {
        println!("cargo:warning=图标/清单没编进去（{e}），exe 会用默认图标且不会自动提权");
    }
}
