import asyncio
import logging
import shlex
import subprocess


def run(cmd, **kwargs):
    """Wrapper around subprocess.run that logs the command at DEBUG level."""
    default_kwargs = {"check": True, "capture_output": True}
    default_kwargs.update(kwargs)
    logging.debug(f"Exec: $ {shlex.join(cmd)}")
    return subprocess.run(cmd, **default_kwargs)


async def run_async(cmd, timeout=None):
    """Run a subprocess with optional timeout, ensuring zombie reap on any exit path."""
    logging.debug(f"Exec async: $ {shlex.join(cmd)}")
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

def log_called_process_error(logger, e):
    msg = [str(e)]
    if e.stdout:
        msg.append(f"stdout: {e.stdout.decode()}")
    if e.stderr:
        msg.append(f"stderr: {e.stderr.decode()}")
    logger(" ".join(msg))
