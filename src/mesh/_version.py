from .utils.version import *

__all__ = [
    "VERSION",
    "VERSION_STR",
]

VERSION_STR = "0.0.6.1"
VERSION = version_to_int(VERSION_STR)
