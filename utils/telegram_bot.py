import json
import time
import urllib.parse
import urllib.request


class TelegramBotApi:
    def __init__(self, token: str):
        self.token = (token or "").strip()
        if not self.token:
            raise ValueError("missing telegram bot token")

    def _url(self, method: str) -> str:
        return f"https://api.telegram.org/bot{self.token}/{method}"

    def _post(self, method: str, data: dict) -> dict:
        body = urllib.parse.urlencode(data).encode("utf-8")
        req = urllib.request.Request(self._url(method), data=body, method="POST")
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read().decode("utf-8")
        return json.loads(raw)

    def _get(self, method: str, params: dict) -> dict:
        qs = urllib.parse.urlencode(params)
        url = self._url(method) + ("?" + qs if qs else "")
        with urllib.request.urlopen(url, timeout=20) as resp:
            raw = resp.read().decode("utf-8")
        return json.loads(raw)

    def send_message(
        self,
        chat_id: str,
        text: str,
        disable_web_page_preview: bool = True,
        reply_markup: dict | None = None,
    ) -> int:
        data = {
            "chat_id": chat_id,
            "text": text,
            "disable_web_page_preview": "true" if disable_web_page_preview else "false",
        }
        if reply_markup is not None:
            data["reply_markup"] = json.dumps(reply_markup, ensure_ascii=False)
        resp = self._post("sendMessage", data)
        if not resp.get("ok"):
            raise RuntimeError(f"telegram sendMessage failed: {resp}")
        try:
            return int((resp.get("result") or {}).get("message_id"))
        except Exception:
            return 0

    def delete_message(self, chat_id: str, message_id: int) -> None:
        data = {"chat_id": chat_id, "message_id": int(message_id)}
        resp = self._post("deleteMessage", data)
        if not resp.get("ok"):
            raise RuntimeError(f"telegram deleteMessage failed: {resp}")

    def answer_callback_query(self, callback_query_id: str, text: str = "") -> None:
        data = {"callback_query_id": callback_query_id}
        if text:
            data["text"] = text
        resp = self._post("answerCallbackQuery", data)
        if not resp.get("ok"):
            raise RuntimeError(f"telegram answerCallbackQuery failed: {resp}")

    def get_updates(self, offset: int | None = None, timeout: int = 25) -> list[dict]:
        params: dict = {"timeout": int(timeout)}
        if offset is not None:
            params["offset"] = int(offset)
        resp = self._get("getUpdates", params)
        if not resp.get("ok"):
            raise RuntimeError(f"telegram getUpdates failed: {resp}")
        return list(resp.get("result") or [])


def parse_start_payload(text: str) -> str:
    t = (text or "").strip()
    if not t.startswith("/start"):
        return ""
    parts = t.split(maxsplit=1)
    if len(parts) < 2:
        return ""
    return parts[1].strip()


def backoff_sleep(seconds: float) -> None:
    time.sleep(max(0.0, seconds))
