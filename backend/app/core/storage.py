"""Storage abstraction for raw artifacts (S3 or local filesystem fallback)."""
import os
from pathlib import Path

from app.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

# Local fallback directory when S3 is not configured (dev/demo).
_LOCAL_ROOT = Path("data/artifacts")


class Storage:
    """Minimal storage wrapper. Uses S3 if configured, else local disk."""

    def __init__(self) -> None:
        self._s3 = None
        if settings.s3_endpoint or os.getenv("AWS_ACCESS_KEY_ID"):
            try:
                import boto3  # type: ignore

                self._s3 = boto3.client(
                    "s3",
                    endpoint_url=settings.s3_endpoint or None,
                )
            except Exception as exc:  # pragma: no cover
                logger.warning("S3 unavailable, falling back to local storage: %s", exc)
                self._s3 = None

    def save(self, key: str, data: bytes) -> str:
        """Persist raw bytes under a key, return the storage reference."""
        if self._s3 is not None:
            self._s3.put_object(Bucket=settings.s3_bucket, Key=key, Body=data)
            return f"s3://{settings.s3_bucket}/{key}"
        path = _LOCAL_ROOT / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return str(path)

    def load(self, ref: str) -> bytes:
        """Load bytes from a storage reference."""
        if ref.startswith("s3://"):
            bucket, key = ref[5:].split("/", 1)
            obj = self._s3.get_object(Bucket=bucket, Key=key)
            return obj["Body"].read()
        return Path(ref).read_bytes()

    def exists(self, ref: str) -> bool:
        if ref.startswith("s3://"):
            bucket, key = ref[5:].split("/", 1)
            try:
                self._s3.head_object(Bucket=bucket, Key=key)
                return True
            except Exception:
                return False
        return os.path.exists(ref)


storage = Storage()
