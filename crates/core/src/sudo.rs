//! `sudo` 下的数据目录归属。
//!
//! `sudo qp2p up` 会带着 **root 的 `HOME`** 启动，数据目录于是落到
//! `/root/.qp2p`：普通用户建过的网、令牌、身份一个都不在里面，用户看到的是
//! "配置没了，得重新建网"。反过来，root 写出来的文件是 `0600 root:root`，
//! 之后不带 sudo 跑 `qp2p status` 又读不到。
//!
//! 所以只要检测到 `SUDO_USER`，就把默认目录换成那个用户自己的 `~/.qp2p`，
//! 并把 root 写进去的文件改归原用户。
//!
//! 边界：
//! - 只接管**默认目录**。显式 `--data-dir` 或 `QP2P_HOME` 一律不插手——
//!   用户明确指定了位置，归属就按他的来。
//! - 只改归属，不改权限位：私密文件仍然是 `0600`，只是主从 root 变成原用户。
//! - 找不到原用户的 home（容器里没有 passwd 条目、用户已删除）就什么都不做，
//!   继续用原来的目录，绝不猜一个路径出来。

#[cfg(unix)]
mod imp {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::OnceLock;

    use tracing::{debug, warn};

    struct Takeover {
        user: String,
        uid: u32,
        gid: u32,
        dir: PathBuf,
    }

    static TAKEOVER: OnceLock<Option<Takeover>> = OnceLock::new();
    static WARNED: AtomicBool = AtomicBool::new(false);

    /// 接管后的默认数据目录；不在 sudo 场景时为 `None`。
    ///
    /// 首次调用会顺手把目录建出来并改归原用户——目录如果留在 root 名下
    /// （哪怕权限是 0755），普通用户后面也写不进去。
    pub fn home() -> Option<PathBuf> {
        let taken = TAKEOVER.get_or_init(detect);
        let taken = taken.as_ref()?;
        prepare(taken);
        Some(taken.dir.clone())
    }

    /// 把 `path` 改归原用户；不在接管目录下的路径一律不动。
    pub fn adopt(path: &Path) {
        let Some(taken) = TAKEOVER.get() else {
            // 还没调过 home()：说明这次运行根本没走默认目录，直接不动
            return;
        };
        let Some(taken) = taken.as_ref() else { return };
        if !path.starts_with(&taken.dir) {
            return;
        }
        if let Err(e) = chown_to(path, taken.uid, taken.gid) {
            if !WARNED.swap(true, Ordering::Relaxed) {
                warn!(
                    "sudo 场景：改归属失败（{}）：{e}；之后不用 sudo 运行可能读不到这些文件",
                    path.display()
                );
            }
        }
    }

    fn detect() -> Option<Takeover> {
        // SAFETY: geteuid 无参数、无副作用，任何线程调用都安全
        if unsafe { libc::geteuid() } != 0 {
            return None;
        }
        let user = std::env::var("SUDO_USER").ok()?.trim().to_string();
        // 直接以 root 登录（不是 sudo）时 SUDO_USER 不存在或就是 root，
        // 这时候 /root/.qp2p 就是"对的"目录，不该换
        if user.is_empty() || user == "root" {
            return None;
        }
        let (uid, gid, home) = resolve(&user)?;
        if !home.is_dir() {
            debug!(
                "sudo 场景：{user} 的 home {} 不存在，保持原目录",
                home.display()
            );
            return None;
        }
        Some(Takeover {
            dir: home.join(".qp2p"),
            user,
            uid,
            gid,
        })
    }

    /// 用户名 → (uid, gid, home)。
    ///
    /// 先读 `/etc/passwd`（Linux 与多数 BSD 都有），找不到再按约定路径探测：
    /// macOS 的用户不在 passwd 里，容器里也常常只剩 `/home/<user>`。
    fn resolve(user: &str) -> Option<(u32, u32, PathBuf)> {
        if let Some(found) = from_passwd(user) {
            return Some(found);
        }
        for candidate in ["/home", "/Users"] {
            let home = Path::new(candidate).join(user);
            let Ok(meta) = std::fs::metadata(&home) else {
                continue;
            };
            if !meta.is_dir() {
                continue;
            }
            use std::os::unix::fs::MetadataExt;
            return Some((meta.uid(), meta.gid(), home));
        }
        debug!("sudo 场景：查不到用户 {user} 的 home，保持原目录");
        None
    }

    fn from_passwd(user: &str) -> Option<(u32, u32, PathBuf)> {
        let text = std::fs::read_to_string("/etc/passwd").ok()?;
        parse_passwd(&text, user)
    }

    /// `name:passwd:uid:gid:gecos:home:shell`，字段不足的行直接跳过。
    fn parse_passwd(text: &str, user: &str) -> Option<(u32, u32, PathBuf)> {
        for line in text.lines() {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() < 7 || f[0] != user || f[5].is_empty() {
                continue;
            }
            let (Ok(uid), Ok(gid)) = (f[2].parse::<u32>(), f[3].parse::<u32>()) else {
                continue;
            };
            return Some((uid, gid, PathBuf::from(f[5])));
        }
        None
    }

    fn prepare(taken: &Takeover) {
        if let Err(e) = std::fs::create_dir_all(&taken.dir) {
            warn!("sudo 场景：建不出 {}：{e}", taken.dir.display());
            return;
        }
        if let Err(e) = chown_to(&taken.dir, taken.uid, taken.gid) {
            warn!("sudo 场景：{} 改归属失败：{e}", taken.dir.display());
        } else {
            debug!(
                "sudo 场景：数据目录改用 {}（归 {}）",
                taken.dir.display(),
                taken.user
            );
        }
    }

    /// 已经是目标主属就跳过，省掉每次写文件一次多余的 syscall。
    fn chown_to(path: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::symlink_metadata(path)?;
        if meta.uid() == uid && meta.gid() == gid {
            return Ok(());
        }
        std::os::unix::fs::chown(path, Some(uid), Some(gid))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::path::PathBuf;

        #[test]
        fn passwd_entry_supplies_uid_gid_and_home() {
            let text = "root:x:0:0:root:/root:/bin/bash\n\
                        lucien:x:1000:1000:Lucien:/home/lucien:/bin/bash\n";
            assert_eq!(
                parse_passwd(text, "lucien"),
                Some((1000, 1000, PathBuf::from("/home/lucien")))
            );
            // gecos 里有空格也不能影响字段位置
            assert_eq!(
                parse_passwd(text, "root"),
                Some((0, 0, PathBuf::from("/root")))
            );
            assert_eq!(parse_passwd(text, "nobody"), None);
            // 字段不足或 home 为空的行不能当成有效条目
            assert_eq!(parse_passwd("bad:x:1\n", "bad"), None);
            assert_eq!(parse_passwd("bad:x:1:1:g::/bin/sh\n", "bad"), None);
        }

        /// 非 root 进程不该接管任何目录（CI 就是这种身份）
        #[test]
        fn no_takeover_without_sudo() {
            if unsafe { libc::geteuid() } != 0 {
                assert!(home().is_none());
            }
        }
    }
}

#[cfg(not(unix))]
mod imp {
    use std::path::{Path, PathBuf};

    /// Windows 没有 sudo，也没有 `SUDO_USER` 这种"换个身份"的约定。
    pub fn home() -> Option<PathBuf> {
        None
    }

    pub fn adopt(_path: &Path) {}
}

pub use imp::{adopt, home};
