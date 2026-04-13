"""
Install uvloop as the asyncio event loop on supported platforms.

Import this module before starting the server to activate uvloop.
On Windows (where uvloop is unavailable) this is a no-op.
"""

import sys


def install() -> bool:
    """
    Install uvloop if available.

    Returns True when uvloop was activated, False otherwise.
    """
    if sys.platform == "win32":
        return False
    try:
        import uvloop  # type: ignore[import]
        uvloop.install()
        return True
    except ImportError:
        return False
