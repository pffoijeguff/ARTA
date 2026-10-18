"""Narrow workspace-scoped text tools for ARTA's controlled-state-change milestone.

This adapter is deliberately allowlist-only: it exposes no arbitrary filesystem path,
directory listing, delete, shell, or recursive write operation. It is defense in depth,
not an OS sandbox against a hostile process running as the same user.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import stat
import tempfile
from pathlib import Path, PurePosixPath
from threading import RLock
from typing import Any, Mapping

from .core import ToolGateway, ToolSpec


MAX_WORKSPACE_FILE_BYTES = 1024 * 1024


class WorkspaceError(RuntimeError):
    """Raised when a workspace operation violates containment or concurrency rules."""


def _validate_relative_path(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise WorkspaceError("Workspace path must be a non-empty relative path.")
    if "\x00" in value or "\\" in value:
        raise WorkspaceError("Workspace paths cannot contain NUL or backslash characters.")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in value.split("/")):
        raise WorkspaceError("Workspace path must not be absolute or traverse parent directories.")
    if path.as_posix() != value:
        raise WorkspaceError("Workspace path must use normalized POSIX separators.")
    return value


class WorkspaceAdapter:
    """Expose read and compare-before-write operations for an explicit file allowlist."""

    def __init__(
        self,
        root: str | Path,
        *,
        allowed_paths: tuple[str, ...] | list[str],
        max_file_bytes: int = MAX_WORKSPACE_FILE_BYTES,
    ) -> None:
        if isinstance(allowed_paths, (str, bytes)) or not isinstance(allowed_paths, (tuple, list)):
            raise WorkspaceError("allowed_paths must be a non-empty sequence of relative paths.")
        normalized = tuple(_validate_relative_path(item) for item in allowed_paths)
        if not normalized or len(set(normalized)) != len(normalized):
            raise WorkspaceError("allowed_paths must be non-empty and unique.")
        if isinstance(max_file_bytes, bool) or not isinstance(max_file_bytes, int):
            raise WorkspaceError("max_file_bytes must be a positive integer.")
        if not 1 <= max_file_bytes <= MAX_WORKSPACE_FILE_BYTES:
            raise WorkspaceError("max_file_bytes must be between 1 byte and 1 MiB.")

        raw_root = Path(root).expanduser()
        raw_root.mkdir(parents=True, exist_ok=True)
        if raw_root.is_symlink() or not raw_root.is_dir():
            raise WorkspaceError("Workspace root must be a real directory, not a symlink.")
        self.root = raw_root.resolve(strict=True)
        self.allowed_paths = normalized
        self.max_file_bytes = max_file_bytes
        self._lock = RLock()

    def _target(self, value: object, *, must_exist: bool) -> Path:
        relative = _validate_relative_path(value)
        if relative not in self.allowed_paths:
            raise WorkspaceError("Requested path is not in the workspace allowlist.")
        target = self.root
        parts = relative.split("/")
        for index, part in enumerate(parts):
            target = target / part
            try:
                mode = target.lstat().st_mode
            except FileNotFoundError:
                if must_exist or index < len(parts) - 1:
                    raise WorkspaceError("Workspace path or parent directory does not exist.") from None
                continue
            if stat.S_ISLNK(mode):
                raise WorkspaceError("Symlinks are not allowed in workspace paths.")
            if index < len(parts) - 1 and not stat.S_ISDIR(mode):
                raise WorkspaceError("Every workspace parent must be a real directory.")
            if index == len(parts) - 1 and must_exist and not stat.S_ISREG(mode):
                raise WorkspaceError("Workspace target must be a regular file.")
            if index == len(parts) - 1 and not must_exist and not (
                stat.S_ISREG(mode) or stat.S_ISDIR(mode)
            ):
                raise WorkspaceError("Workspace target has an unsupported file type.")
        resolved_parent = target.parent.resolve(strict=True)
        if resolved_parent != self.root and self.root not in resolved_parent.parents:
            raise WorkspaceError("Workspace path escaped its configured root.")
        return target

    def _read_bytes(self, target: Path) -> bytes:
        self._target(target.relative_to(self.root).as_posix(), must_exist=True)
        descriptor = -1
        try:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(target, flags)
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise WorkspaceError("Workspace target must be a regular file.")
            with os.fdopen(descriptor, "rb") as handle:
                descriptor = -1
                data = handle.read(self.max_file_bytes + 1)
        except WorkspaceError:
            raise
        except OSError:
            raise WorkspaceError("Workspace file could not be read safely.") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if len(data) > self.max_file_bytes:
            raise WorkspaceError("Workspace file exceeds the configured size limit.")
        return data

    @staticmethod
    def _sha256(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def read(self, arguments: Mapping[str, Any]) -> Mapping[str, Any]:
        """Read one allowlisted UTF-8 file and return its content plus integrity metadata."""
        path = _validate_relative_path(arguments.get("path"))
        with self._lock:
            target = self._target(path, must_exist=True)
            data = self._read_bytes(target)
        try:
            content = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise WorkspaceError("Workspace file is not valid UTF-8 text.") from None
        return {
            "path": path,
            "content": content,
            "sha256": self._sha256(data),
            "bytes": len(data),
        }

    def write(self, arguments: Mapping[str, Any]) -> Mapping[str, Any]:
        """Atomically create a file or replace it only when the prior SHA-256 matches."""
        path = _validate_relative_path(arguments.get("path"))
        content = arguments.get("content")
        expected = arguments.get("expected_sha256")
        if not isinstance(content, str):
            raise WorkspaceError("Workspace content must be a UTF-8 string.")
        try:
            new_bytes = content.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            raise WorkspaceError("Workspace content is not valid UTF-8 text.") from None
        if len(new_bytes) > self.max_file_bytes:
            raise WorkspaceError("Workspace content exceeds the configured size limit.")
        if "\x00" in content:
            raise WorkspaceError("NUL characters are not accepted in workspace text files.")
        if expected is not None and (
            not isinstance(expected, str)
            or len(expected) != 64
            or any(char not in "0123456789abcdef" for char in expected)
        ):
            raise WorkspaceError("expected_sha256 must be null or a lowercase SHA-256 hex digest.")

        with self._lock:
            target = self._target(path, must_exist=False)
            existed = target.exists()
            if existed and not target.is_file():
                raise WorkspaceError("Only regular files can be replaced.")
            if existed:
                before = self._read_bytes(target)
                before_hash = self._sha256(before)
                if expected is None or not hmac_compare(expected, before_hash):
                    raise WorkspaceError("Existing file changed or requires its exact expected_sha256.")
            else:
                before = b""
                before_hash = None
                if expected is not None:
                    raise WorkspaceError("A new file cannot have an expected prior SHA-256.")

            # A temporary sibling plus atomic replace prevents readers from observing a
            # partially written file. The second check catches ordinary concurrent edits.
            fd = -1
            temp_name: str | None = None
            try:
                fd, temp_name = tempfile.mkstemp(prefix=".arta-write-", dir=str(target.parent))
                if hasattr(os, "fchmod"):
                    os.fchmod(fd, 0o600)
                with os.fdopen(fd, "wb") as handle:
                    fd = -1
                    handle.write(new_bytes)
                    handle.flush()
                    os.fsync(handle.fileno())

                # Revalidate path components and the exact prior state before replacing.
                checked_target = self._target(path, must_exist=False)
                if checked_target != target:
                    raise WorkspaceError("Workspace target changed during the write.")
                if existed:
                    current = self._read_bytes(target)
                    if not hmac_compare(self._sha256(current), before_hash or ""):
                        raise WorkspaceError("Workspace file changed during the write; retry from a fresh read.")
                elif target.exists() or target.is_symlink():
                    raise WorkspaceError("Workspace target appeared during the write; retry from a fresh read.")

                os.replace(temp_name, target)
                temp_name = None
                if os.name != "nt":
                    try:
                        dir_fd = os.open(target.parent, os.O_RDONLY)
                        try:
                            os.fsync(dir_fd)
                        finally:
                            os.close(dir_fd)
                    except OSError:
                        # File contents are already atomically replaced; directory fsync is
                        # a durability enhancement not supported by every filesystem.
                        pass
            except WorkspaceError:
                raise
            except OSError:
                raise WorkspaceError("Workspace write failed; no success is reported.") from None
            finally:
                if fd >= 0:
                    os.close(fd)
                if temp_name is not None:
                    try:
                        os.unlink(temp_name)
                    except OSError:
                        pass

        after_hash = self._sha256(new_bytes)
        return {
            "path": path,
            "created": not existed,
            "before_sha256": before_hash,
            "after_sha256": after_hash,
            "bytes": len(new_bytes),
        }

    def register(self, gateway: ToolGateway, *, read_tool_name: str = "workspace.read",
                 write_tool_name: str = "workspace.write") -> None:
        """Register allowlisted read and approval-gated write tools on a ToolGateway."""
        if not isinstance(gateway, ToolGateway):
            raise WorkspaceError("register requires a ToolGateway.")
        gateway.register(ToolSpec(
            name=read_tool_name,
            handler=self.read,
            read_only=True,
            allowed_arguments=("path",),
            required_arguments=("path",),
            target_argument="path",
            allowed_targets=self.allowed_paths,
        ))
        gateway.register(ToolSpec(
            name=write_tool_name,
            handler=self.write,
            read_only=False,
            requires_approval=True,
            allowed_arguments=("path", "content", "expected_sha256"),
            required_arguments=("path", "content"),
            target_argument="path",
            allowed_targets=self.allowed_paths,
        ))


def hmac_compare(left: str, right: str) -> bool:
    """Constant-time compare for the fixed-size public SHA-256 digests."""
    return hmac.compare_digest(left, right)
