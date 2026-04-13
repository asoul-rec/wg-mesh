__all__ = [
    "version_to_int",
    "int_to_version",
]


def version_to_int(v_str: str) -> int:
    parts = [int(x) for x in v_str.split('.')]
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]


def int_to_version(v_int: int) -> str:
    return f"{(v_int >> 24) & 255}.{(v_int >> 16) & 255}.{(v_int >> 8) & 255}.{v_int & 255}"
