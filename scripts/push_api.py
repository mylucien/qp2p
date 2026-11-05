#!/usr/bin/env python3
"""用 GitHub Git Data API 推送当前 HEAD。

为什么不用 `git push`：本机访问 github.com:443 必须走代理，而代理对它的
CONNECT 经常返回 502；api.github.com 却是通的。API 推送不依赖 git 协议，
也能一次把「哪些文件变了」说清楚，失败时报的是具体哪一步。

用法：
    python scripts/push_api.py                 # 用 HEAD 的提交说明
    python scripts/push_api.py "提交说明"       # 指定说明

令牌来源：环境变量 QP2P_TOKEN_FILE 指向的文件（默认 E:/workbuddy/token.txt）。
"""

import base64
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

REPO = os.environ.get("QP2P_REPO", "mylucien/qp2p")
BRANCH = os.environ.get("QP2P_BRANCH", "main")
TOKEN_FILE = os.environ.get("QP2P_TOKEN_FILE", "E:/workbuddy/token.txt")
API = f"https://api.github.com/repos/{REPO}"


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], check=True, capture_output=True, text=True
    ).stdout


def call(method: str, path: str, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(
        API + path,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            return json.load(response)
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:400]
        raise SystemExit(f"{method} {path} 失败（HTTP {e.code}）：{detail}")


token = open(TOKEN_FILE, encoding="utf-8").read().strip()
message = sys.argv[1] if len(sys.argv) > 1 else git("log", "-1", "--pretty=%B").strip()

# 1) 远端现在在哪
ref = call("GET", f"/git/ref/heads/{BRANCH}")
remote_head = ref["object"]["sha"]
remote_tree = call("GET", f"/git/commits/{remote_head}")["tree"]["sha"]
local_tree = git("rev-parse", "HEAD^{tree}").strip()
print(f"远端 {BRANCH}: {remote_head[:7]}  本地 tree: {local_tree[:7]}")

# 快速路径只在工作树干净（没有未提交修改）时生效：脚本实际推送的是
# 工作树内容，工作树和 HEAD 不一致时 HEAD^{tree} 相同不代表内容相同。
dirty = bool(git("status", "--porcelain").strip())
if not dirty and remote_tree == local_tree:
    print("内容已经一致，不需要推送")
    raise SystemExit(0)

# 2) 把工作树里的每个被跟踪文件都传成一个 blob。
#    不做增量 diff：本地与远端的历史常常因为 API 推送而不一致，
#    整树覆盖是唯一不会漏文件、也不会带上 CRLF 差异的做法。
files = [f for f in git("ls-files").splitlines() if f.strip()]
entries = []
normalized = 0
for path in files:
    with open(path, "rb") as handle:
        data = handle.read()
    # Git Data API 是直接传字节，不走 .gitattributes 的 eol 规范化。
    # 本地文件常被编辑器/Python 改成 CRLF，这里统一回 LF，否则整个仓库会
    # 出现"内容没变但全文件不同"的提交（上次就是这么来的）。
    if b"\0" not in data and b"\r\n" in data:
        data = data.replace(b"\r\n", b"\n")
        normalized += 1
    content = base64.b64encode(data).decode()
    blob = call("POST", "/git/blobs", {"content": content, "encoding": "base64"})
    entries.append({"path": path, "mode": "100644", "type": "blob", "sha": blob["sha"]})

print(f"已上传 {len(files)} 个文件（其中 {normalized} 个把 CRLF 归一成 LF）")

# 3) 建树（不带 base_tree：远端多出来的文件会被自然删掉，和本地完全一致）
tree = call("POST", "/git/trees", {"tree": entries})

# 4) 建提交并移动分支
commit = call(
    "POST",
    "/git/commits",
    {"message": message, "tree": tree["sha"], "parents": [remote_head]},
)
call("PATCH", f"/git/refs/heads/{BRANCH}", {"sha": commit["sha"]})

print(f"已推送 {commit['sha'][:7]} → {BRANCH}")
print(f"CI: https://github.com/{REPO}/actions")
