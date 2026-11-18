"""Content addressed evidence storage.

Files are addressed by their SHA-256 digest and stored at
``root/<sha[:2]>/<sha>``. A write goes to a temporary file in the same
directory and is moved into place with :func:`os.replace`, so a reader never
observes a partial upload. Two tasks that attach the same document share one
physical file.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path


class EvidenceStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    @staticmethod
    def digest(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def path_for(self, sha256: str) -> Path:
        return self.root / sha256[:2] / sha256

    def exists(self, sha256: str) -> bool:
        return self.path_for(sha256).is_file()

    def put(self, data: bytes) -> str:
        sha256 = self.digest(data)
        target = self.path_for(sha256)
        if target.is_file():
            return sha256
        target.parent.mkdir(parents=True, exist_ok=True)
        handle, temp_name = tempfile.mkstemp(dir=target.parent, prefix=".upload-")
        try:
            with os.fdopen(handle, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_name, target)
        except BaseException:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass
            raise
        return sha256

    def read(self, sha256: str) -> bytes:
        return self.path_for(sha256).read_bytes()

    def unlink(self, sha256: str) -> bool:
        try:
            self.path_for(sha256).unlink()
            return True
        except FileNotFoundError:
            return False
