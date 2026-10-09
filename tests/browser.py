"""テストから headless の Chromium を動かす小さな部品。

`--remote-debugging-pipe` で CDP を話す。fd 3 に要求、fd 4 から応答が来て、1 つの JSON は NUL で区切られる。
websocket もほかの依存も要らない。`tools/web-screenshot.py` と同じ探し方で Chromium を見つける。
"""
from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path


def chromium_path() -> str | None:
    return shutil.which("chromium") or shutil.which("google-chrome") or shutil.which("chromium-browser")


class BrowserError(RuntimeError):
    pass


class Browser:
    """1 つのタブを持つ Chromium。`goto`、`eval`、`wait_for`、`requests` を使う。"""

    def __init__(self, timeout: float = 30.0) -> None:
        exe = chromium_path()
        if exe is None:
            raise BrowserError("Chromium が見つからない")
        self._timeout = timeout
        self._profile = tempfile.mkdtemp(prefix="tia-browser-")
        read_from_chrome, chrome_writes = os.pipe()
        chrome_reads, write_to_chrome = os.pipe()
        self._proc = subprocess.Popen(
            [exe, "--headless=new", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage", "--hide-scrollbars",
             "--remote-debugging-pipe", "--window-size=1440,1100", f"--user-data-dir={self._profile}", "about:blank"],
            pass_fds=(3, 4), preexec_fn=lambda: (os.dup2(chrome_reads, 3), os.dup2(chrome_writes, 4)),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.close(chrome_reads)
        os.close(chrome_writes)
        self._in = os.fdopen(write_to_chrome, "wb", buffering=0)
        self._out = os.fdopen(read_from_chrome, "rb", buffering=0)
        self._next_id = 0
        self._replies: dict[int, queue.Queue] = {}
        self._events: list[dict] = []
        self._lock = threading.Lock()
        self._reader = threading.Thread(target=self._read_loop, name="tia-browser-reader", daemon=True)
        self._reader.start()
        self._session: str | None = None
        self.requests: list[str] = []
        self.console: list[str] = []
        self._open_tab()

    # --- CDP の送受信 -------------------------------------------------------------------------------------------
    def _read_loop(self) -> None:
        buffer = b""
        while True:
            try:
                chunk = self._out.read(65536)
            except OSError:
                return
            if not chunk:
                return
            buffer += chunk
            while b"\0" in buffer:
                raw, buffer = buffer.split(b"\0", 1)
                try:
                    message = json.loads(raw.decode())
                except ValueError:
                    continue
                self._dispatch(message)

    def _dispatch(self, message: dict) -> None:
        if "id" in message:
            with self._lock:
                waiter = self._replies.get(message["id"])
            if waiter is not None:
                waiter.put(message)
            return
        method = message.get("method", "")
        params = message.get("params", {})
        if method == "Network.requestWillBeSent":
            self.requests.append(params.get("request", {}).get("url", ""))
        elif method == "Runtime.consoleAPICalled":
            self.console.append(" ".join(str(a.get("value", a.get("description", ""))) for a in params.get("args", [])))
        elif method == "Log.entryAdded":
            self.console.append(str(params.get("entry", {}).get("text", "")))
        with self._lock:
            self._events.append(message)

    def send(self, method: str, params: dict | None = None, *, session: bool = True) -> dict:
        self._next_id += 1
        message: dict = {"id": self._next_id, "method": method, "params": params or {}}
        if session and self._session:
            message["sessionId"] = self._session
        waiter: queue.Queue = queue.Queue()
        with self._lock:
            self._replies[self._next_id] = waiter
        self._in.write(json.dumps(message).encode() + b"\0")
        try:
            reply = waiter.get(timeout=self._timeout)
        except queue.Empty as exc:
            raise BrowserError(f"{method} の応答がない") from exc
        finally:
            with self._lock:
                self._replies.pop(self._next_id, None)
        if "error" in reply:
            raise BrowserError(f"{method}: {reply['error']}")
        return reply.get("result", {})

    def _open_tab(self) -> None:
        target = self.send("Target.createTarget", {"url": "about:blank"}, session=False)["targetId"]
        self._session = self.send("Target.attachToTarget", {"targetId": target, "flatten": True}, session=False)["sessionId"]
        self.send("Page.enable")
        self.send("Runtime.enable")
        self.send("Network.enable")
        self.send("Log.enable")

    # --- 操作 ------------------------------------------------------------------------------------------------------
    def goto(self, url: str) -> None:
        self.requests.clear()
        self.send("Page.navigate", {"url": url})
        self.wait_for("document.readyState === 'complete'")

    def eval(self, expression: str):
        result = self.send("Runtime.evaluate", {"expression": expression, "returnByValue": True, "awaitPromise": True})
        if "exceptionDetails" in result:
            text = result["exceptionDetails"].get("exception", {}).get("description", "")
            raise BrowserError(f"JS の失敗: {text or result['exceptionDetails'].get('text')}")
        return result.get("result", {}).get("value")

    def wait_for(self, expression: str, timeout: float = 10.0, interval: float = 0.1):
        """式が真になるまで待ち、その値を返す。"""
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            last = self.eval(expression)
            if last:
                return last
            time.sleep(interval)
        raise BrowserError(f"{timeout} 秒待っても真にならない: {expression!r}（最後の値 {last!r}）")

    def click(self, selector: str) -> None:
        self.eval(f"(function(){{var el=document.querySelector({json.dumps(selector)}); if(!el) throw new Error('ない: '+{json.dumps(selector)}); el.click(); return true;}})()")

    def type_into(self, selector: str, text: str) -> None:
        self.eval(f"(function(){{var el=document.querySelector({json.dumps(selector)}); el.focus(); el.value={json.dumps(text)}; "
                  f"el.dispatchEvent(new Event('input',{{bubbles:true}})); return true;}})()")

    def close(self) -> None:
        try:
            self.send("Browser.close", session=False)
        except BrowserError:
            pass
        try:
            self._proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            self._proc.wait(timeout=5)
        for stream in (self._in, self._out):
            try:
                stream.close()
            except OSError:
                pass
        shutil.rmtree(self._profile, ignore_errors=True)

    def __enter__(self) -> "Browser":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
