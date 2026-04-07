from .utils import version_to_int

__all__ = [
    "VERSION_STR",
    "VERSION",
]

VERSION_STR = "0.0.5.0"
VERSION = version_to_int(VERSION_STR)
