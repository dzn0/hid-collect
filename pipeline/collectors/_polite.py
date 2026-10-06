"""Persistent per-source pauses; never retry access challenges automatically."""
import json
import threading
import time
from email.utils import parsedate_to_datetime

from .. import config


class SourceBlocked(RuntimeError):
    pass


def retry_after(headers):
    value = (headers.get("Retry-After") or headers.get("retry-after") or "").strip()
    try:
        return max(0.0, float(value)) if value.isdigit() else max(
            0.0, parsedate_to_datetime(value).timestamp() - time.time())
    except (ValueError, TypeError, OverflowError):
        return None


class SourcePause:
    def __init__(self, name, *, ignore_batch_pause=False):
        self.name = name
        self.ignore_batch_pause = ignore_batch_pause
        self.stopped = threading.Event()
        self.lock = threading.Lock()

    def path(self):
        return config.collectors_dir() / self.name / "cooldown.json"

    def defer(self, seconds, reason):
        with self.lock:
            p = self.path()
            previous = json.loads(p.read_text()) if p.exists() else {}
            now = time.time()
            until = max(previous.get("until", 0), now + seconds)
            # A batch pause must never relabel an active server/access restriction.
            if previous.get("until", 0) > now and (
                    (reason == "pause between batches" and previous.get("reason") != reason)
                    or (previous.get("until", 0) > now + seconds
                        and previous.get("reason") != "pause between batches")):
                reason = previous.get("reason", reason)
            p.parent.mkdir(parents=True, exist_ok=True)
            temporary = p.with_suffix(".tmp")
            temporary.write_text(json.dumps({"until": until, "reason": reason}))
            temporary.replace(p)

    def check(self):
        if self.stopped.is_set():
            raise SourceBlocked(f"{self.name}: access denied; run stopped")
        with self.lock:
            p = self.path()
            state = json.loads(p.read_text()) if p.exists() else {}
        remaining = state.get("until", 0) - time.time()
        if self.ignore_batch_pause and state.get("reason") == "pause between batches":
            return
        if remaining > 0:
            raise SourceBlocked(f"{self.name}: pause active ({remaining:.0f}s remaining): "
                                f"{state.get('reason', '')}")

    def block(self, headers=None):
        self.stopped.set()
        self.defer(max(3600, retry_after(headers or {}) or 0), "access denied/rate limited")
        raise SourceBlocked(f"{self.name}: access denied; stopped for at least one hour "
                            "(or longer Retry-After). Wait for restored access before restarting.")

    def respect_retry_after(self, headers):
        seconds = retry_after(headers)
        if seconds and seconds > 0:
            self.defer(seconds, "server Retry-After")
            self.stopped.set()
            raise SourceBlocked(f"{self.name}: server requested Retry-After {seconds:.0f}s; run stopped")
