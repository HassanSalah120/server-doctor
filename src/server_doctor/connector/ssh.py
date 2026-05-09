"""SSH Connector - Secure connection to remote servers.

This module handles all SSH communication with remote servers.
It is read-only by default and provides methods for running
commands and retrieving file contents.
"""

from dataclasses import dataclass, field
import os
from pathlib import Path
import threading
import time
from typing import Callable

import paramiko
from paramiko.ssh_exception import AuthenticationException, PasswordRequiredException, SSHException


@dataclass
class SSHConfig:
    """SSH connection configuration."""

    host: str
    user: str = "root"
    port: int = 22
    key_path: str | None = None
    passphrase: str | None = None  # For encrypted private keys
    password: str | None = None  # Fallback, prefer keys
    use_sudo: bool = True
    timeout: int = 30
    # Maximum number of concurrent exec_command calls for one SSH session.
    # If None, server_doctor_SSH_MAX_PARALLEL (default: 1) is used.
    max_parallel_commands: int | None = None


@dataclass
class CommandResult:
    """Result of a command execution."""

    command: str
    stdout: str
    stderr: str
    exit_code: int
    success: bool = field(init=False)

    def __post_init__(self) -> None:
        self.success = self.exit_code == 0


class SSHConnector:
    """SSH connection manager for remote server operations.

    This class provides a safe interface for executing read-only
    commands on remote servers. Write operations are explicitly
    separated and require confirmation.

    Example:
        >>> config = SSHConfig(host="192.168.1.100", user="deploy")
        >>> with SSHConnector(config) as ssh:
        ...     result = ssh.run("nginx -v")
        ...     print(result.stdout)
    """

    def __init__(self, config: SSHConfig) -> None:
        """Initialize SSH connector with configuration."""
        self.config = config
        self._client: paramiko.SSHClient | None = None
        configured_parallel = config.max_parallel_commands
        if configured_parallel is None:
            try:
                configured_parallel = int(os.getenv("server_doctor_SSH_MAX_PARALLEL", "1"))
            except ValueError:
                configured_parallel = 1
        self._max_parallel_commands = max(1, configured_parallel)
        try:
            retries = int(os.getenv("server_doctor_SSH_CHANNEL_RETRIES", "4"))
        except ValueError:
            retries = 4
        self._channel_retries = max(0, retries)
        try:
            keepalive = int(os.getenv("server_doctor_SSH_KEEPALIVE_SEC", "20"))
        except ValueError:
            keepalive = 20
        self._keepalive_seconds = max(0, keepalive)
        # Allow bounded command concurrency while avoiding unbounded channel pressure.
        self._run_semaphore = threading.BoundedSemaphore(self._max_parallel_commands)
        self._reconnect_lock = threading.Lock()

    def connect(self) -> None:
        """Establish SSH connection."""
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs: dict = {
            "hostname": self.config.host,
            "port": self.config.port,
            "username": self.config.user,
            "timeout": self.config.timeout,
        }

        # Prefer key-based authentication
        if self.config.key_path:
            key_path = Path(self.config.key_path).expanduser()
            # explicitly fail early if user provided an explicit key that doesn't exist
            if not key_path.exists():
                raise ConnectionError(f"SSH key file not found: {key_path}")

            connect_kwargs["key_filename"] = str(key_path)
            if self.config.passphrase:
                connect_kwargs["passphrase"] = self.config.passphrase
            # If we have a specific key, don't look for others
            connect_kwargs["look_for_keys"] = False
            connect_kwargs["allow_agent"] = False
        elif self.config.password:
            connect_kwargs["password"] = self.config.password
            # Important: do NOT disable key/agent discovery when a password is present.
            # Many servers accept key auth only, and UIs sometimes capture a password even
            # when the real auth path is ssh-agent or default ~/.ssh keys.

        try:
            self._client.connect(**connect_kwargs)
            transport_getter = getattr(self._client, "get_transport", None)
            transport = transport_getter() if callable(transport_getter) else None
            if transport and self._keepalive_seconds > 0:
                transport.set_keepalive(self._keepalive_seconds)
        except PasswordRequiredException as e:
            raise ConnectionError(
                "Authentication failed: encrypted private key requires a passphrase ("
                "provide passphrase or use ssh-agent)"
            ) from e
        except AuthenticationException as e:
            # Paramiko often returns the generic string "Authentication failed.";
            # avoid echoing it twice in our message. normalize to a single human
            # readable phrase.
            msg = str(e) or "Authentication failed"
            if msg.lower().startswith("authentication failed"):
                raise ConnectionError("Authentication failed") from e
            else:
                raise ConnectionError(f"Authentication failed: {msg}") from e
        except (IOError, OSError) as e:
            # this typically surfaces when Paramiko cannot load a key file
            raise ConnectionError(f"SSH key file error: {e}") from e
        except SSHException as e:
            if str(e).strip().lower() == "invalid key" and self.config.key_path:
                raise ConnectionError(
                    "SSH key could not be decrypted or parsed. If this key is "
                    "encrypted, check the SSH Key Passphrase field; do not use "
                    "the server/root password there."
                ) from e
            raise ConnectionError(f"SSH error: {e}") from e

    def disconnect(self) -> None:
        """Close SSH connection."""
        if self._client:
            self._client.close()
            self._client = None

    def __enter__(self) -> "SSHConnector":
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, *args: object) -> None:
        """Context manager exit."""
        self.disconnect()

    def run(self, command: str, use_sudo: bool | None = None, timeout: float | None = None) -> CommandResult:
        """Execute a command on the remote server.

        Args:
            command: The command to execute.
            use_sudo: Whether to use sudo. Defaults to config setting.
            timeout: Command timeout in seconds. Defaults to config timeout.

        Returns:
            CommandResult with stdout, stderr, and exit_code.
        """
        if not self._client:
            raise RuntimeError("Not connected. Use 'with SSHConnector(config):' context.")

        if use_sudo is None:
            use_sudo = self.config.use_sudo

        exec_command = command
        should_write_password = False
        if use_sudo and self.config.user != "root":
            # Always execute via shell under sudo so shell builtins/redirects/pipes/loops work.
            # Never embed password in command text to avoid leaking secrets in logs/errors.
            shell_wrapped = f"sh -lc {self._shell_quote(command)}"
            if self.config.password:
                exec_command = f"sudo -S -p '' {shell_wrapped}"
                should_write_password = True
            else:
                # -n prevents hanging on password prompt when no password is configured.
                exec_command = f"sudo -n {shell_wrapped}"
        
        # Use provided timeout or default from config
        cmd_timeout = timeout if timeout is not None else self.config.timeout

        attempts = 1 + self._channel_retries
        last_error: Exception | None = None
        for attempt in range(attempts):
            stdin = None
            stdout = None
            stderr = None
            channel = None
            try:
                with self._run_semaphore:
                    client = self._client
                    if client is None:
                        raise SSHException("SSH client is not connected")

                    stdin, stdout, stderr = client.exec_command(exec_command, timeout=cmd_timeout)
                    channel = stdout.channel
                    if should_write_password and self.config.password is not None:
                        stdin.write(self.config.password + "\n")
                        stdin.flush()
                        shutdown_write = getattr(getattr(stdin, "channel", None), "shutdown_write", None)
                        if callable(shutdown_write):
                            try:
                                shutdown_write()
                            except Exception:
                                pass

                    stdout_chunks: list[bytes] = []
                    stderr_chunks: list[bytes] = []
                    deadline = time.monotonic() + float(cmd_timeout)
                    while not channel.exit_status_ready():
                        self._drain_channel(channel, stdout_chunks, stderr_chunks)
                        if time.monotonic() >= deadline:
                            try:
                                channel.close()
                            except Exception:
                                pass
                            stdout_text = b"".join(stdout_chunks).decode(
                                "utf-8",
                                errors="replace",
                            )
                            stderr_text = b"".join(stderr_chunks).decode(
                                "utf-8",
                                errors="replace",
                            )
                            if self._is_sudo_auth_failure(stderr_text):
                                return CommandResult(
                                    command=exec_command,
                                    stdout=stdout_text,
                                    stderr=self._sudo_auth_failure_message(),
                                    exit_code=126,
                                )
                            timeout_text = f"SSH command timed out after {cmd_timeout}s"
                            stderr_text = (
                                f"{stderr_text.rstrip()}\n{timeout_text}"
                                if stderr_text.strip()
                                else timeout_text
                            )
                            return CommandResult(
                                command=exec_command,
                                stdout=stdout_text,
                                stderr=stderr_text,
                                exit_code=124,
                            )
                        time.sleep(0.05)

                    self._drain_channel(channel, stdout_chunks, stderr_chunks)
                    exit_code = channel.recv_exit_status()
                    self._drain_channel(channel, stdout_chunks, stderr_chunks)
                    stdout_text = b"".join(stdout_chunks).decode("utf-8", errors="replace")
                    stderr_text = b"".join(stderr_chunks).decode("utf-8", errors="replace")
                    if self._is_sudo_auth_failure(stderr_text):
                        stderr_text = self._sudo_auth_failure_message()
                        exit_code = 126

                    return CommandResult(
                        command=exec_command,
                        stdout=stdout_text,
                        stderr=stderr_text,
                        exit_code=exit_code,
                    )
            except Exception as e:
                last_error = e
                if attempt < attempts - 1:
                    if self._is_retriable_channel_error(e):
                        # Avoid reconnect storms while other commands are in-flight.
                        # Channel-open failures are often transient (MaxSessions pressure).
                        if not self._transport_is_active():
                            self._recover_transport()
                        time.sleep(min(1.25, 0.20 * (attempt + 1)))
                        continue
                    if not self._transport_is_active():
                        self._recover_transport()
                        time.sleep(min(1.25, 0.20 * (attempt + 1)))
                        continue
                break
            finally:
                for stream in (stdin, stdout, stderr):
                    try:
                        if stream is not None:
                            stream.close()
                    except Exception:
                        pass
                try:
                    if channel is not None:
                        channel.close()
                except Exception:
                    pass

        # Handle timeouts or other SSH errors gracefully
        return CommandResult(
            command=exec_command,
            stdout="",
            stderr=f"SSH Execution Error: {str(last_error) if last_error else 'unknown'}",
            exit_code=255,
        )

    @staticmethod
    def _shell_quote(value: str) -> str:
        return "'" + value.replace("'", "'\"'\"'") + "'"

    @staticmethod
    def _is_sudo_auth_failure(stderr: str) -> bool:
        text = (stderr or "").lower()
        return (
            "sorry, try again" in text
            or "incorrect password" in text
            or "authentication failure" in text and "sudo" in text
            or "a password is required" in text
        )

    @staticmethod
    def _sudo_auth_failure_message() -> str:
        return (
            "sudo authentication failed: password was rejected or missing for the SSH user. "
            "Use that user's sudo password, not the root password, or configure passwordless sudo for read-only diagnostics."
        )

    @staticmethod
    def _drain_channel(channel: object, stdout_chunks: list[bytes], stderr_chunks: list[bytes]) -> None:
        recv_ready = getattr(channel, "recv_ready", None)
        recv = getattr(channel, "recv", None)
        while callable(recv_ready) and callable(recv) and recv_ready():
            stdout_chunks.append(recv(65535))

        recv_stderr_ready = getattr(channel, "recv_stderr_ready", None)
        recv_stderr = getattr(channel, "recv_stderr", None)
        while callable(recv_stderr_ready) and callable(recv_stderr) and recv_stderr_ready():
            stderr_chunks.append(recv_stderr(65535))

    def _is_retriable_channel_error(self, exc: Exception) -> bool:
        """Best-effort detection for transient SSH channel open failures."""
        text = str(exc).lower()
        if "channelexception" in text and "connect failed" in text:
            return True
        if "channel open failed" in text:
            return True
        if "administratively prohibited" in text:
            return True
        if isinstance(exc, SSHException) and "channel" in text and "failed" in text:
            return True
        return False

    def _recover_transport(self) -> None:
        """Best-effort session refresh after channel-open failures."""
        with self._reconnect_lock:
            try:
                if self._client is None:
                    self.connect()
                    return
                self.disconnect()
                time.sleep(0.1)
                self.connect()
            except Exception:
                # Keep retry loop resilient; final error will be surfaced by caller.
                return

    def _transport_is_active(self) -> bool:
        client = self._client
        if client is None:
            return False
        try:
            transport = client.get_transport()
        except Exception:
            return False
        return bool(transport and transport.is_active())

    def read_file(self, path: str) -> str | None:
        """Read file contents from remote server.

        Args:
            path: Absolute path to the file.

        Returns:
            File contents as string, or None if file doesn't exist.
        """
        result = self.run(f"cat {path}", use_sudo=True)
        if result.success:
            return result.stdout
        return None

    def file_exists(self, path: str) -> bool:
        """Check if a file exists on the remote server."""
        result = self.run(f"test -f {path}", use_sudo=True)
        return result.success

    def dir_exists(self, path: str) -> bool:
        """Check if a directory exists on the remote server."""
        result = self.run(f"test -d {path}", use_sudo=True)
        return result.success

    def list_dir(self, path: str) -> list[str]:
        """List directory contents.

        Args:
            path: Directory path.

        Returns:
            List of filenames in the directory.
        """
        result = self.run(f"ls -1 {path}", use_sudo=True)
        if result.success:
            return [f for f in result.stdout.strip().split("\n") if f]
        return []

    # =========================================================================
    # WRITE OPERATIONS - Require explicit confirmation
    # =========================================================================

    def write_file(
        self,
        path: str,
        content: str,
        *,
        backup: bool = True,
        confirm_callback: Callable[[], bool] | None = None,
    ) -> bool:
        """Write content to a file on the remote server.

        ⚠️  WARNING: This modifies the server!

        Args:
            path: Absolute path to write to.
            content: Content to write.
            backup: Whether to backup existing file first.
            confirm_callback: Optional callback to confirm the operation.

        Returns:
            True if successful.
        """
        if confirm_callback and not confirm_callback():
            return False

        if backup and self.file_exists(path):
            self.run(f"cp {path} {path}.bak", use_sudo=True)

        # Use heredoc to write content
        # Note: This is a simplified implementation. Production would use SFTP.
        escaped_content = content.replace("'", "'\"'\"'")
        result = self.run(f"echo '{escaped_content}' > {path}", use_sudo=True)
        return result.success
