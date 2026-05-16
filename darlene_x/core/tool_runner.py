"""
Tool runner for subprocess management.

Wraps subprocess calls with:
- Timeout handling (prevents hanging)
- Tool availability checking (graceful degradation)
- Error capture (logging without crashing)
- Return value normalization

If a tool is missing, run() returns empty output instead of raising.
If a tool times out, run() returns a timeout indicator instead of raising.
"""

import subprocess
import shutil
import logging
from typing import Tuple

log = logging.getLogger(__name__)


def run(
    cmd: list[str],
    timeout: int = 120,
    check: bool = False,
) -> Tuple[str, str, int]:
    """
    Run a command safely with timeout and error handling.

    Args:
        cmd: Command as list (e.g., ["jadx", "app.apk", "-d", "out"])
        timeout: Max seconds to wait (default 120s)
        check: If True, raise on non-zero exit (default False for graceful degradation)

    Returns:
        Tuple of (stdout, stderr, returncode)
        - If tool missing: ("", "tool_name not installed", -1)
        - If timeout: ("", "timeout", -1)
        - If error: ("", error_message, returncode)
        - On success: (stdout, stderr, 0)

    Example:
        >>> stdout, stderr, code = run(["apktool", "d", "app.apk", "-o", "out"])
        >>> if code == 0:
        ...     print("Success:", stdout[:100])
        >>> elif code == -1:
        ...     print("Error:", stderr)
    """
    tool_name = cmd[0]

    # Check if tool is available in PATH
    if not shutil.which(tool_name):
        log.warning(f"Tool not found: {tool_name} — skipping")
        return "", f"{tool_name} not installed", -1

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        
        if check and result.returncode != 0:
            log.error(f"Command failed: {' '.join(cmd)}\nSTDERR: {result.stderr}")
            raise subprocess.CalledProcessError(
                result.returncode, cmd, result.stdout, result.stderr
            )
        
        return result.stdout, result.stderr, result.returncode

    except subprocess.TimeoutExpired:
        log.warning(f"Command timeout ({timeout}s): {' '.join(cmd)}")
        return "", "timeout", -1

    except subprocess.CalledProcessError as e:
        log.error(f"Command failed: {' '.join(cmd)}")
        return e.stdout or "", e.stderr or str(e), e.returncode

    except Exception as e:
        log.error(f"Command error: {' '.join(cmd)} — {str(e)}")
        return "", str(e), -1


def exists(tool_name: str) -> bool:
    """Check if a tool is available in PATH."""
    return shutil.which(tool_name) is not None


def check_tools(tools: list[str]) -> dict[str, bool]:
    """
    Check availability of multiple tools.

    Args:
        tools: List of tool names (e.g., ["apktool", "jadx", "semgrep"])

    Returns:
        Dict mapping tool name to availability (True/False)

    Example:
        >>> status = check_tools(["apktool", "jadx", "badtool"])
        >>> for tool, available in status.items():
        ...     print(f"{tool}: {'✓' if available else '✗'}")
    """
    return {tool: exists(tool) for tool in tools}
