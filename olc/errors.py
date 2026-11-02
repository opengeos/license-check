"""Error types shared across modules."""


class InputError(ValueError):
    """Invalid caller input: artifacts, limits, arguments. CLI exit 4."""

    code = "invalid-input"

    def __init__(self, message, code=None):
        super().__init__(message)
        if code:
            self.code = code
