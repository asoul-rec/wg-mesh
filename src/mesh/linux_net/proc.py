import asyncio
import logging
import shlex
import subprocess
from collections.abc import Callable

logger = logging.getLogger(__name__.rsplit(".", 1)[0])


def run(cmd, **kwargs):
    """Wrapper around subprocess.run that logs the command at DEBUG level."""
    default_kwargs = {"check": True, "capture_output": True}
    default_kwargs.update(kwargs)
    logger.debug(f"Exec: $ {shlex.join(cmd)}")
    return subprocess.run(cmd, **default_kwargs)  # ty: ignore[no-matching-overload]  # noqa: PLW1510


async def run_async(cmd, timeout=None):
    """Run a subprocess with optional timeout, ensuring zombie reap on any exit path."""
    logger.debug(f"Exec async: $ {shlex.join(cmd)}")
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    try:
        if timeout is not None:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        else:
            stdout, stderr = await proc.communicate()
        return proc.returncode, stdout, stderr
    finally:
        if proc.returncode is None:
            try:
                proc.kill()
                await proc.wait()
            except OSError:
                pass


def log_called_process_error(logger: Callable[[str], None], e: subprocess.CalledProcessError):
    msg = [str(e)]
    try:
        if out := e.stdout.decode().strip():
            msg.append(f"stdout: {out!r}")
        if err := e.stderr.decode().strip():
            msg.append(f"stderr: {err!r}")
    except Exception as e1:  # noqa: BLE001
        msg.append(f"[Failed to get streams: {e1!r}]")
    logger(" ".join(msg))
