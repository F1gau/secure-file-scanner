import logging
import sys
from contextvars import ContextVar

request_id_var: ContextVar[str] = ContextVar("request_id", default="-")
user_id_var: ContextVar[str] = ContextVar("user_id", default="-")
scan_id_var: ContextVar[str] = ContextVar("scan_id", default="-")


class ContextFilter(logging.Filter):
    """Inject request/user/scan identifiers into every log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get()
        record.user_id = user_id_var.get()
        record.scan_id = scan_id_var.get()
        return True


def setup_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(ContextFilter())
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s level=%(levelname)s event=%(message)s "
            "request_id=%(request_id)s user_id=%(user_id)s scan_id=%(scan_id)s "
            "logger=%(name)s"
        )
    )
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
