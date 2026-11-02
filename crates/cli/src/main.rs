//! qp2p 命令行前端。
//!
//! 当前阶段（P0）只做骨架：版本与帮助。子命令在 P4 接入。

use std::process::ExitCode;

const HELP: &str = "\
qp2p — 私有打洞组网

用法：
  qp2p <命令>

命令：
  join <密钥>        加入网络（密钥形如 qp2p1_<network>_<secret>）
  run                前台运行引擎
  status             查看节点与连接状态
  forward            管理端口映射
  doctor             自检：环境、权限、信令与打洞能力

选项：
  -h, --help         显示本帮助
  -V, --version      显示版本
";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);

    match args.next().as_deref() {
        None | Some("-h") | Some("--help") => {
            print!("{HELP}");
            ExitCode::SUCCESS
        }
        Some("-V") | Some("--version") => {
            println!(
                "qp2p {} (protocol {})",
                env!("CARGO_PKG_VERSION"),
                qp2p_core::PROTOCOL_VERSION
            );
            ExitCode::SUCCESS
        }
        Some(command) => {
            eprintln!("命令尚未实现：{command}\n");
            eprint!("{HELP}");
            ExitCode::FAILURE
        }
    }
}
