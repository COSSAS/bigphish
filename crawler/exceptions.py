"""All custom exceptions for the crawler."""


class StopException(Exception):
    """Exception for stopping the crawler because of browser errors or offline domain."""


class FalsePositiveException(Exception):
    """Exception for detected false positives."""


class NothingChangedException(Exception):
    """Exception for a domain on which nothing has changed."""


class MonitoringTimeOut(Exception):
    """Exception for timeout on monitoring, after a domain has been monitored for X days."""


class RedirectException(Exception):
    """Exception for a domain that redirects the browser away from the phishing website."""
