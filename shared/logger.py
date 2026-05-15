import json
import logging
import sys
from datetime import datetime
from pathlib import Path


class AuditLogger:
    """JSON 行式审计日志"""

    def __init__(self, log_file: str | Path = "audit.log"):
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.log_file, "a")

    def _emit(self, level: str, message: str, **extra):
        record = {
            "ts": datetime.now().isoformat(),
            "level": level,
            "msg": message,
            **extra,
        }
        line = json.dumps(record, ensure_ascii=False)
        self._fh.write(line + "\n")
        self._fh.flush()

    def info(self, message: str, **extra):
        self._emit("INFO", message, **extra)

    def warning(self, message: str, **extra):
        self._emit("WARN", message, **extra)

    def error(self, message: str, **extra):
        self._emit("ERROR", message, **extra)

    def finding(self, message: str, **extra):
        self._emit("FINDING", message, **extra)

    def close(self):
        if not self._fh.closed:
            self._fh.close()

    def __del__(self):
        self.close()


# 标准库 logging 兼容桥，方便第三方库接入
_std_handler: logging.Handler | None = None


def setup_std_logging(level: int = logging.WARNING):
    """将标准库 logging 重定向到 stdout"""
    global _std_handler
    if _std_handler:
        return
    fmt = logging.Formatter("[%(asctime)s] %(levelname)s %(name)s: %(message)s", datefmt="%H:%M:%S")
    _std_handler = logging.StreamHandler(sys.stdout)
    _std_handler.setFormatter(fmt)
    _std_handler.setLevel(level)
    logging.root.addHandler(_std_handler)
    logging.root.setLevel(level)
