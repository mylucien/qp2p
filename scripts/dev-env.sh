# 只在需要本机跑调试时 source 一下；**正常开发不要编译**，编译交给 GitHub CI。
#
#   source scripts/dev-env.sh
#
# 这套设置解决的是「C 盘被写满」：cargo 的 registry、下载缓存、临时文件
# 默认都在 C:\Users\<你>\ 下，一台 C 盘只剩几个 G 的机器编两次就满了。

export CARGO_HOME="E:/workbuddy/cargo-home"
export TMPDIR="/e/workbuddy/tmp"
export TMP="E:/workbuddy/tmp"
export TEMP="E:/workbuddy/tmp"
export CARGO_INCREMENTAL=0          # E: 上的 incremental 目录会「拒绝访问」
export PATH="$CARGO_HOME/bin:$PATH"

# 产物目录放到**工作区之外**。
#
# 放在仓库里（默认 target/）有个坑：agent 的「安全删除」会在删除前把整棵树
# 备份到 C:\Users\<你>\.workbuddy\workspace\sessions\<会话>\modify_backup，
# 然后进回收站。一次 `cargo clean` 删掉 5.4GB 产物，就等于在 C 盘又写了一份
# 5.4GB，而且不真正释放空间——这台机器的 C 盘就是这么被占满的。
# 挪到工作区外，清理时就不会被备份。
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-E:/workbuddy/qp2p-target}"

mkdir -p "$TMPDIR"
echo "CARGO_HOME=$CARGO_HOME"
echo "TMPDIR=$TMPDIR"
echo "CARGO_TARGET_DIR=$CARGO_TARGET_DIR"
echo "提示：能用 CI 就别本机编。推送用 python scripts/push_api.py"
echo "注意：不要在仓库内执行 cargo clean —— 删除会被备份到 C 盘会话目录并进回收站，"
