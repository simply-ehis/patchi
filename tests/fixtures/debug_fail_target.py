"""Intentionally buggy script used to verify debug capture works."""


def process_order(items: list[str]) -> str:
    if not items:
        total = None
    else:
        total = len(items) * 10
    # BUG: total is None when items is empty, but we treat it as int
    return f"Total: {total + 5}"  # TypeError: unsupported operand type(s) for +: 'NoneType' and 'int'


def helper() -> None:
    # This function has a local variable that should appear in the stack
    multiplier = 2
    _ = multiplier


if __name__ == "__main__":
    helper()
    result = process_order([])
    print(result)
