"""User-facing error types.

Every message should say what happened and what to do about it.
"""


class SilkScanError(Exception):
    """Base class for errors that are reported to the user without a traceback."""


class ConfigError(SilkScanError):
    pass


class DataValidationError(SilkScanError):
    pass


class LeakageError(SilkScanError):
    """A target/identity field could reach feature extraction, or splits overlap."""


class SchemaMismatchError(SilkScanError):
    pass


class DependencyError(SilkScanError):
    pass


class ExtractionError(SilkScanError):
    """Feature extraction failed for records whose group policy is `error`."""


class RunExistsError(SilkScanError):
    pass
