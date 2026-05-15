import asyncio
import time


class TokenBucket:
    """异步令牌桶，控制 QPS"""

    def __init__(self, rate: float = 5.0, burst: int = 3):
        self.rate = rate
        self.capacity = max(burst, 1)
        self._tokens = float(self.capacity)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """获取一个令牌，若桶空则等待"""
        while True:
            async with self._lock:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                wait = (1.0 - self._tokens) / self.rate
            await asyncio.sleep(wait)

    def _refill(self):
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
        self._last_refill = now

    def update_rate(self, new_rate: float):
        self.rate = new_rate


class RateLimiter:
    """按域名分桶的限流器，同一域名共享一个桶"""

    def __init__(self, default_qps: float = 5.0, night_qps: float = 10.0,
                 night_window: tuple[int, int] = (2, 6)):
        self.default_qps = default_qps
        self.night_qps = night_qps
        self.night_window = night_window
        self._buckets: dict[str, TokenBucket] = {}

    def _is_night(self) -> bool:
        h = time.localtime().tm_hour
        start, end = self.night_window
        if start < end:
            return start <= h < end
        return h >= start or h < end

    @property
    def current_qps(self) -> float:
        return self.night_qps if self._is_night() else self.default_qps

    def get_bucket(self, domain: str) -> TokenBucket:
        if domain not in self._buckets:
            self._buckets[domain] = TokenBucket(rate=self.current_qps)
        # 按当前时间窗口更新速率
        self._buckets[domain].update_rate(self.current_qps)
        return self._buckets[domain]


# 全局单例
_global_limiter: RateLimiter | None = None


def get_limiter(default_qps: float = 5.0, night_qps: float = 10.0,
                night_window: tuple[int, int] = (2, 6)) -> RateLimiter:
    global _global_limiter
    if _global_limiter is None:
        _global_limiter = RateLimiter(default_qps, night_qps, night_window)
    return _global_limiter
