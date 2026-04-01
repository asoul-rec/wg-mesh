from .utils import version_to_int

__all__ = [
    "VERSION_STR",
    "VERSION",
    "MINIMAL_COMPATIBLE_VERSION",
]

VERSION_STR = "0.0.2.0"
VERSION = version_to_int(VERSION_STR)
MINIMAL_COMPATIBLE_VERSION = version_to_int("0.0.1.1")
