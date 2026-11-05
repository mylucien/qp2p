//! 私密文件的写入。
//!
//! 关键点：权限在**创建那一刻**就是 `0600`，而不是先按默认模式写完再 chmod——
//! 后者中间有一小段窗口，同机的其他用户能读到私钥；而且 chmod 失败常常被
//! `let _ =` 吞掉，等于悄悄退化成"谁都能读"。
//!
//! 用 `create_new` 还有第二个好处：两个进程同时首次启动时，只有一个能创建成功，
//! 另一个拿到 `Ok(false)` 后改为读取对方的文件，不会互相覆盖身份。

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

/// 写入只有本用户可读的文件。
///
/// - `Ok(true)`：本进程创建成功
/// - `Ok(false)`：文件已存在（另一个进程抢先了），调用方应改为读取
pub fn create_private(path: &Path, bytes: &[u8]) -> std::io::Result<bool> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // 只在创建时生效，不存在"先有权限再收紧"的窗口
        opts.mode(0o600);
    }

    match opts.open(path) {
        Ok(mut file) => {
            file.write_all(bytes)?;
            file.sync_all()?;
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e),
    }
}

/// 覆盖写入私密文件（配置、令牌）。
///
/// 和 [`create_private`] 的区别是允许覆盖：先写到同目录的临时文件，
/// 再 rename 顶上去——中途崩溃不会留下半个文件，也不会出现
/// "旧文件被截断、新内容还没写完"的窗口。
pub fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp-write");

    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    {
        let mut file = opts.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }

    // Windows 的 rename 不覆盖既有文件：先删再改名。配置里有令牌，
    // 删除与改名之间即使被打断，最坏也只是丢配置（重新 join 一次），不会泄漏。
    if let Err(first) = std::fs::rename(&tmp, path) {
        if path.exists() {
            std::fs::remove_file(path)?;
            std::fs::rename(&tmp, path)?;
        } else {
            let _ = std::fs::remove_file(&tmp);
            return Err(first);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_private_replaces_content() {
        let dir = std::env::temp_dir().join(format!("qp2p-secret-w-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("c.toml");

        write_private(&path, b"one").unwrap();
        write_private(&path, b"two").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"two");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn write_private_keeps_mode_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("qp2p-secret-wm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("c.toml");
        write_private(&path, b"x").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn creates_once_then_reports_existing() {
        let dir = std::env::temp_dir().join(format!("qp2p-secret-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("k");

        assert!(create_private(&path, b"first").unwrap(), "首次应当创建成功");
        assert!(
            !create_private(&path, b"second").unwrap(),
            "第二次应报告已存在"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"first",
            "已有文件不能被覆盖"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn mode_is_owner_only_from_creation() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("qp2p-secret-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("k");

        create_private(&path, b"x").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
