#!/usr/bin/env python3
"""偽の LLM を動かす。接続先のない場所で `tia analyze` を試すためのもの。実環境では使わない。

    uv run python tools/fake-llm.py --port 18090 --key-file /tmp/tia/key

鍵のファイルがなければ作る。止めるまで動く。
"""
from __future__ import annotations

import argparse
import secrets
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from fakes import FakeLlm, FakeServer  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--port", type=int, default=18090)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--mode", default="ok", help="ok、schema_violation、slow、http_500 など。空白区切りで順に")
    args = parser.parse_args()
    if args.key_file.exists():
        key = args.key_file.read_text(encoding="utf-8").strip()
    else:
        key = "owui-" + secrets.token_hex(16)
        args.key_file.parent.mkdir(parents=True, exist_ok=True)
        args.key_file.write_text(key + "\n", encoding="utf-8")
        args.key_file.chmod(0o600)
    fake = FakeLlm(key=key)
    fake.modes = [m for m in args.mode.split() if m != "ok"]
    with FakeServer(fake.handle, port=args.port) as server:
        print(f"偽の LLM: {server.url}/openai （鍵は {args.key_file}）", flush=True)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
