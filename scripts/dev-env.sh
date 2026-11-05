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

# 产物目录本来就是仓库内的 target（在 E:），这里显式写一遍，防止有人从别处启动
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$(pwd)/target}"

mkdir -p "$TMPDIR"
echo "CARGO_HOME=$CARGO_HOME"
echo "TMPDIR=$TMPDIR"
echo "CARGO_TARGET_DIR=$CARGO_TARGET_DIR"
echo "提示：能用 CI 就别本机编。推送用 python scripts/push_api.py"
