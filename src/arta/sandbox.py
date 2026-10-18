"""Linux Bubblewrap execution boundary for untrusted project tasks.

The sandbox requires user, PID, IPC, UTS, and network namespaces. It fails closed when
Bubblewrap, user namespaces, private tmpfs setup, or required runtime mounts are unavailable.
The source workspace is mounted read-only, then copied into a size-capped private tmpfs:
all task writes disappear when the sandbox exits. Persisting artifacts must go through a
separate trusted, approved workspace adapter.
"""
from __future__ import annotations

import math
import os
import shutil
import shlex
import signal
import subprocess
import sys
import time
from threading import Thread
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


class SandboxError(RuntimeError):
    """Raised when strong isolation cannot be established or input violates its contract."""


@dataclass(frozen=True)
class SandboxResult:
    executable: str
    return_code: int
    stdout: str
    stderr: str
    timed_out: bool
    stdout_truncated: bool
    stderr_truncated: bool
    elapsed_seconds: float


class BubblewrapSandbox:
    """Run an allowlisted executable without host network, secrets, or persistent writes.

    The executable alias/path and source workspace are trusted runtime configuration.
    Arguments are still untrusted data: they are passed as an argv array and never through
    a host shell. Inside the boundary, the task receives a private tmpfs copy of the source.
    """

    _SYSTEM_ROOTS = ("/usr", "/bin", "/sbin", "/lib", "/lib64")
    _SANDBOX_SCRIPT = 'exec "$@"'

    def __init__(
        self,
        workspace_root: str | Path,
        *,
        allowed_executables: Mapping[str, str | Path],
        bwrap_path: str | Path | None = None,
        default_timeout_seconds: float = 10.0,
        max_timeout_seconds: float = 60.0,
        memory_limit_bytes: int = 512 * 1024 * 1024,
        output_limit_bytes: int = 256 * 1024,
        workspace_limit_bytes: int = 256 * 1024 * 1024,
        temp_limit_bytes: int = 64 * 1024 * 1024,
    ) -> None:
        if sys.platform != "linux":
            raise SandboxError("BubblewrapSandbox is Linux-only; no fallback execution is permitted.")
        if not isinstance(allowed_executables, Mapping) or not allowed_executables:
            raise SandboxError("At least one executable alias must be configured by the trusted runtime.")

        try:
            root = Path(workspace_root).expanduser().resolve(strict=True)
        except OSError:
            raise SandboxError("Workspace root does not exist or cannot be resolved.") from None
        if not root.is_dir() or root == Path("/"):
            raise SandboxError("Workspace must be a dedicated existing directory, not the filesystem root.")
        home = Path.home().expanduser().resolve()
        if root == home or root in home.parents:
            raise SandboxError("Workspace must be a dedicated project directory, not the user home or its parent.")
        for raw in ("/etc", "/var", "/opt", "/run", "/dev", "/proc", "/sys", "/boot", "/mnt", "/media"):
            protected = Path(raw).resolve()
            if root == protected or protected in root.parents or root in protected.parents:
                raise SandboxError("Workspace must not overlap a protected operating-system directory.")
        if root == Path("/tmp") or root in Path("/tmp").parents:
            raise SandboxError("Use a dedicated subdirectory rather than a shared temporary directory.")
        self._workspace_root = root
        self._system_roots = self._resolve_system_roots()
        if any(
            root == system_root or root in system_root.parents or system_root in root.parents
            for system_root in self._system_roots
        ):
            raise SandboxError("Workspace must not overlap an operating-system runtime directory.")

        configured: dict[str, str] = {}
        for alias, executable in allowed_executables.items():
            if (
                not isinstance(alias, str)
                or not alias
                or alias != alias.strip()
                or len(alias) > 64
                or any(not (ch.isalnum() or ch in "_-") for ch in alias)
            ):
                raise SandboxError("Executable aliases must be short, trimmed identifiers.")
            try:
                resolved = Path(executable).expanduser().resolve(strict=True)
            except OSError:
                raise SandboxError(f"Configured executable is missing: {alias}.") from None
            if not resolved.is_file() or not os.access(resolved, os.X_OK):
                raise SandboxError(f"Configured executable is missing or not executable: {alias}.")
            if not self._is_visible_runtime_path(resolved):
                raise SandboxError(f"Executable is outside the read-only sandbox runtime roots: {alias}.")
            configured[alias] = str(resolved)
        self._allowed_executables = configured

        raw_bwrap = str(bwrap_path) if bwrap_path is not None else shutil.which("bwrap")
        if not raw_bwrap:
            raise SandboxError("Bubblewrap is not installed; refusing to run outside a sandbox.")
        try:
            resolved_bwrap = Path(raw_bwrap).expanduser().resolve(strict=True)
        except OSError:
            raise SandboxError("Configured Bubblewrap executable is missing or not executable.") from None
        if not resolved_bwrap.is_file() or not os.access(resolved_bwrap, os.X_OK):
            raise SandboxError("Configured Bubblewrap executable is missing or not executable.")
        self._bwrap = str(resolved_bwrap)

        self._default_timeout_seconds = self._bounded_number(
            default_timeout_seconds, "default_timeout_seconds", 0.1, 60.0
        )
        self._max_timeout_seconds = self._bounded_number(
            max_timeout_seconds, "max_timeout_seconds", self._default_timeout_seconds, 60.0
        )
        self._memory_limit_bytes = self._bounded_int(
            memory_limit_bytes, "memory_limit_bytes", 64 * 1024 * 1024, 4 * 1024 * 1024 * 1024
        )
        self._output_limit_bytes = self._bounded_int(
            output_limit_bytes, "output_limit_bytes", 1024, 4 * 1024 * 1024
        )
        self._workspace_limit_bytes = self._bounded_int(
            workspace_limit_bytes, "workspace_limit_bytes", 1024 * 1024, 2 * 1024 * 1024 * 1024
        )
        self._temp_limit_bytes = self._bounded_int(
            temp_limit_bytes, "temp_limit_bytes", 1024 * 1024, 512 * 1024 * 1024
        )

        self._prlimit = self._resolve_runtime_command(("prlimit", "/usr/bin/prlimit", "/bin/prlimit"))
        self._shell = self._resolve_runtime_command(("sh", "/bin/sh", "/usr/bin/sh"))
        self._copy = self._resolve_runtime_command(("cp", "/bin/cp", "/usr/bin/cp"))
        self._find = self._resolve_runtime_command(("find", "/usr/bin/find", "/bin/find"))
        self._rm = self._resolve_runtime_command(("rm", "/usr/bin/rm", "/bin/rm"))
        self._true = self._resolve_runtime_command(("true", "/usr/bin/true", "/bin/true"))

    @staticmethod
    def _bounded_number(value: object, label: str, minimum: float, maximum: float) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise SandboxError(f"{label} must be a finite number.")
        numeric = float(value)
        if not math.isfinite(numeric) or not minimum <= numeric <= maximum:
            raise SandboxError(f"{label} must be between {minimum} and {maximum}.")
        return numeric

    @staticmethod
    def _bounded_int(value: object, label: str, minimum: int, maximum: int) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
            raise SandboxError(f"{label} must be an integer between {minimum} and {maximum}.")
        return value

    @property
    def allowed_aliases(self) -> tuple[str, ...]:
        """Return immutable executable aliases configured by the trusted runtime."""
        return tuple(sorted(self._allowed_executables))

    def _resolve_system_roots(self) -> tuple[Path, ...]:
        resolved: list[Path] = []
        for raw in self._SYSTEM_ROOTS:
            path = Path(raw)
            try:
                candidate = path.resolve(strict=True)
            except OSError:
                continue
            if path.exists() and candidate.is_dir() and candidate not in resolved:
                resolved.append(candidate)
        if Path("/usr").resolve() not in resolved:
            raise SandboxError("A readable /usr runtime tree is required for the sandbox.")
        return tuple(resolved)

    def _is_visible_runtime_path(self, path: Path) -> bool:
        return any(path == root or root in path.parents for root in self._system_roots)

    def _resolve_runtime_command(self, candidates: Sequence[str]) -> str:
        for candidate in candidates:
            raw = shutil.which(candidate) if "/" not in candidate else candidate
            if not raw:
                continue
            try:
                resolved = Path(raw).resolve(strict=True)
            except OSError:
                continue
            if resolved.is_file() and os.access(resolved, os.X_OK) and self._is_visible_runtime_path(resolved):
                return str(resolved)
        raise SandboxError("The read-only runtime is missing a required command for bounded execution.")

    @staticmethod
    def _system_mount_arguments() -> list[str]:
        args: list[str] = []
        for raw in BubblewrapSandbox._SYSTEM_ROOTS:
            path = Path(raw)
            if not path.exists():
                continue
            resolved = path.resolve()
            if path.is_symlink():
                # Recreate system merged-/usr symlinks inside the otherwise empty sandbox root.
                args.extend(["--symlink", "/" + resolved.as_posix().lstrip("/"), raw])
            elif path.is_dir():
                args.extend(["--ro-bind", raw, raw])
        return args

    def _resource_arguments(self, timeout_seconds: float) -> list[str]:
        cpu_soft = max(1, math.ceil(timeout_seconds))
        cpu_hard = cpu_soft + 1
        return [
            f"--cpu={cpu_soft}:{cpu_hard}",
            f"--as={self._memory_limit_bytes}",
            f"--fsize={self._workspace_limit_bytes}",
            "--nproc=32:32",
            "--nofile=64:64",
            "--core=0:0",
        ]

    def _build_command(
        self,
        executable: str,
        arguments: Sequence[str],
        *,
        timeout_seconds: float,
        preflight: bool = False,
    ) -> list[str]:
        if executable not in self._allowed_executables:
            raise SandboxError("Executable alias is not on the trusted runtime allowlist.")
        if isinstance(arguments, (str, bytes)) or not isinstance(arguments, Sequence):
            raise SandboxError("Arguments must be a sequence of strings, not a shell command.")
        checked_args: list[str] = []
        total = 0
        for value in arguments:
            if not isinstance(value, str) or "\x00" in value or len(value) > 8192:
                raise SandboxError("Each argument must be a bounded string without NUL bytes.")
            total += len(value.encode("utf-8"))
            if total > 64 * 1024:
                raise SandboxError("Total argument data exceeds 64 KiB.")
            checked_args.append(value)

        command = [
            self._bwrap,
            "--die-with-parent",
            "--new-session",
            "--unshare-user",
            "--unshare-pid",
            "--unshare-net",
            "--unshare-ipc",
            "--unshare-uts",
            "--disable-userns",
        ]
        command.extend(self._system_mount_arguments())
        command.extend([
            "--proc", "/proc",
            "--dev", "/dev",
            "--ro-bind", str(self._workspace_root), "/source",
            "--size", str(self._workspace_limit_bytes),
            "--tmpfs", "/workspace",
            "--size", str(self._temp_limit_bytes),
            "--tmpfs", "/tmp",
            "--chmod", "1777", "/tmp",
            "--chdir", "/workspace",
            "--clearenv",
            "--setenv", "HOME", "/tmp",
            "--setenv", "TMPDIR", "/tmp",
            "--setenv", "PATH", "/usr/bin:/bin",
            "--setenv", "LANG", "C.UTF-8",
            "--setenv", "LC_ALL", "C.UTF-8",
        ])

        resource_args = self._resource_arguments(timeout_seconds)
        if preflight:
            safe_probe = (
                f"test -x {shlex.quote(self._shell)} && "
                f"test -x {shlex.quote(self._copy)} && "
                f"test -x {shlex.quote(self._prlimit)} && "
                f"test -x {shlex.quote(self._find)} && test -x {shlex.quote(self._rm)} && "
                "test -d /source && test -d /workspace"
            )
            command.extend([
                self._prlimit, *resource_args, "--",
                self._shell, "-c", safe_probe,
            ])
        else:
            cleanup_private_files = (
                f"{shlex.quote(self._find)} /workspace -type d "
                "\\( -name .git -o -name .aws -o -name .ssh -o -name .gnupg -o -name .docker \\) "
                f"-prune -exec {shlex.quote(self._rm)} -rf -- {{}} + && "
                f"{shlex.quote(self._find)} /workspace -type f "
                "\\( -name '.env' -o -name '.env.*' -o -name '*.pem' -o -name '*.key' "
                "-o -name '*credentials*' -o -name '*secret*' -o -name '.npmrc' "
                "-o -name '.pypirc' -o -name '.netrc' -o -name 'id_rsa' "
                "-o -name 'id_ed25519' \\) -delete"
            )
            copy_script = (
                f"{shlex.quote(self._copy)} -R --no-preserve=mode,ownership,timestamps "
                f"-- /source/. /workspace/ && {cleanup_private_files} && {self._SANDBOX_SCRIPT}"
            )
            command.extend([
                self._prlimit, *resource_args, "--",
                self._shell, "-c", copy_script, "arta-sandbox",
                self._allowed_executables[executable], *checked_args,
            ])
        return command

    def _spawn(
        self,
        command: Sequence[str],
        *,
        timeout_seconds: float,
    ) -> tuple[int, str, str, bool, bool, bool, float]:
        started = time.monotonic()
        try:
            process = subprocess.Popen(
                list(command),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                cwd="/",
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                close_fds=True,
                start_new_session=True,
            )
        except (OSError, ValueError):
            raise SandboxError("Sandbox process could not be started; no unsandboxed fallback exists.") from None
        if process.stdout is None or process.stderr is None:
            try:
                process.kill()
            except OSError:
                pass
            raise SandboxError("Sandbox output streams could not be bounded.")

        def drain(stream: Any) -> tuple[bytes, bool]:
            kept = bytearray()
            truncated = False
            while True:
                chunk = stream.read(8192)
                if not chunk:
                    break
                remaining = self._output_limit_bytes - len(kept)
                if remaining > 0:
                    kept.extend(chunk[:remaining])
                if len(chunk) > max(remaining, 0):
                    truncated = True
            return bytes(kept), truncated

        output: dict[str, tuple[bytes, bool]] = {}
        readers = (
            Thread(target=lambda: output.__setitem__("stdout", drain(process.stdout)), daemon=True),
            Thread(target=lambda: output.__setitem__("stderr", drain(process.stderr)), daemon=True),
        )
        for reader in readers:
            reader.start()

        timed_out = False
        try:
            process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            # Bubblewrap's --die-with-parent tears down the namespace child if bwrap dies.
            try:
                process.kill()
            except OSError:
                pass
            try:
                process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                raise SandboxError("Sandbox supervisor could not be stopped after timeout.") from None

        for reader in readers:
            reader.join(timeout=2.0)
            if reader.is_alive():
                raise SandboxError("Sandbox output stream did not close after the supervisor stopped.")

        elapsed = time.monotonic() - started
        stdout_bytes, stdout_truncated = output.get("stdout", (b"", False))
        stderr_bytes, stderr_truncated = output.get("stderr", (b"", False))
        return (
            int(process.returncode if process.returncode is not None else -1),
            stdout_bytes.decode("utf-8", errors="replace"),
            stderr_bytes.decode("utf-8", errors="replace"),
            timed_out,
            stdout_truncated,
            stderr_truncated,
            elapsed,
        )

    def run(
        self,
        executable: str,
        arguments: Sequence[str] = (),
        *,
        timeout_seconds: float | None = None,
    ) -> SandboxResult:
        """Probe the required namespaces/mounts, then run the allowlisted executable.

        The workspace is copied into a size-capped temporary filesystem and is discarded
        after execution. If the probe fails for any reason, the task is never started.
        """
        timeout = (
            self._default_timeout_seconds
            if timeout_seconds is None
            else self._bounded_number(timeout_seconds, "timeout_seconds", 0.1, self._max_timeout_seconds)
        )
        # Validate aliases and argv before even invoking the sandbox probe.
        if executable not in self._allowed_executables:
            raise SandboxError("Executable alias is not on the trusted runtime allowlist.")
        command = self._build_command(executable, arguments, timeout_seconds=timeout)
        probe_command = self._build_command(executable, (), timeout_seconds=min(timeout, 5.0), preflight=True)
        probe_rc, _probe_out, _probe_err, probe_timeout, _out_truncated, _err_truncated, _elapsed = self._spawn(
            probe_command,
            timeout_seconds=min(timeout, 5.0),
        )
        if probe_timeout or probe_rc != 0:
            raise SandboxError("Bubblewrap isolation preflight failed; task execution was refused.")

        rc, stdout, stderr, timed_out, stdout_truncated, stderr_truncated, elapsed = self._spawn(
            command,
            timeout_seconds=timeout,
        )
        return SandboxResult(
            executable=executable,
            return_code=rc,
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
            elapsed_seconds=elapsed,
        )
