#!/usr/bin/env python3
"""用 GitHub Git Data API 打版本标签，触发 ci 的自动发布。

为什么不用 `git push --tags`：本机到 github.com:443 走代理常返回
CONNECT tunnel failed 502，只有 api.github.com 稳定可达（和 push_api.py 同理）。

用法：
    python scripts/tag_api.py v0.1.1                  # 打在远端 main 当前 HEAD 上
    python scripts/tag_api.py v0.1.1 <commit-sha>     # 打在指定提交上

前置条件：代码已经用 push_api.py 推到 main，且
.github/release-notes/<tag>.md 已提交，否则 release job 会明确报错。

标签已存在时脚本不会覆盖也不会删除，直接退出——重发请换版本号，
或先在 GitHub 上手动删掉旧 tag 和对应 Release。

令牌来源：环境变量 QP2P_TOKEN_FILE 指向的文件（默认 E:/workbuddy/token.txt）。
"""

import json
import os
import sys
import urllib.error
import urllib.request

REPO = os.environ.get("QP2P_REPO", "mylucien/qp2p")
BRANCH = os.environ.get("QP2P_BRANCH", "main")
TOKEN_FILE = os.environ.get("QP2P_TOKEN_FILE", "E:/workbuddy/token.txt")
API = f"https://api.github.com/repos/{REPO}"

token = open(TOKEN_FILE, encoding="utf-8").read().strip()


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
    with urllib.request.urlopen(request, timeout=90) as response:
        return json.load(response)


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    tag = sys.argv[1]
    if not tag.startswith("v"):
        raise SystemExit(f"标签必须以 v 开头，收到的是 {tag!r}（ci 只认 v*）")

    sha = (
        sys.argv[2]
        if len(sys.argv) > 2
        else call("GET", f"/git/ref/heads/{BRANCH}")["object"]["sha"]
    )

    try:
        call("GET", f"/git/ref/tags/{tag}")
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise SystemExit(f"查询标签失败（HTTP {e.code}）：{e.read().decode()[:300]}")
    else:
        raise SystemExit(f"标签 {tag} 已存在，脚本不覆盖。要重发请换版本号或先手动删 tag。")

    ref = call("POST", "/git/refs", {"ref": f"refs/tags/{tag}", "sha": sha})
    print(f"已打标签 {tag} → {sha[:7]}（ref={ref['ref']}）")
    print(f"CI:      https://github.com/{REPO}/actions")
    print(f"发布页:  https://github.com/{REPO}/releases/tag/{tag}")


if __name__ == "__main__":
    main()
