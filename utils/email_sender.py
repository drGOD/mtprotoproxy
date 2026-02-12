import os
import smtplib
import ssl
from email.message import EmailMessage


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "on")


class EmailSender:
    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        from_email: str,
        use_tls: bool,
    ):
        self.host = host
        self.port = int(port)
        self.username = username
        self.password = password
        self.from_email = from_email
        self.use_tls = bool(use_tls)

    @staticmethod
    def from_env() -> "EmailSender | None":
        host = os.environ.get("MTPROTO_SMTP_HOST", "").strip()
        port = os.environ.get("MTPROTO_SMTP_PORT", "").strip()
        username = os.environ.get("MTPROTO_SMTP_USER", "").strip()
        password = os.environ.get("MTPROTO_SMTP_PASS", "").strip()
        from_email = os.environ.get("MTPROTO_SMTP_FROM", "").strip() or username
        use_tls = _env_bool("MTPROTO_SMTP_TLS", True)

        if not host or not port or not from_email:
            return None

        return EmailSender(
            host=host,
            port=int(port),
            username=username,
            password=password,
            from_email=from_email,
            use_tls=use_tls,
        )

    def send_text(self, to_email: str, subject: str, text: str) -> None:
        to_email = (to_email or "").strip()
        if not to_email:
            raise ValueError("missing to_email")

        msg = EmailMessage()
        msg["From"] = self.from_email
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.set_content(text)

        context = ssl.create_default_context()
        if self.use_tls:
            with smtplib.SMTP_SSL(self.host, self.port, context=context) as s:
                if self.username:
                    s.login(self.username, self.password)
                s.send_message(msg)
        else:
            with smtplib.SMTP(self.host, self.port) as s:
                s.ehlo()
                if _env_bool("MTPROTO_SMTP_STARTTLS", False):
                    s.starttls(context=context)
                    s.ehlo()
                if self.username:
                    s.login(self.username, self.password)
                s.send_message(msg)
