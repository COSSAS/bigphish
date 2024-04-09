"""Utilities for domain detection."""

from datetime import datetime
from re import match
from typing import Dict, Tuple


class Domain:
    """Domain object, which contains all the information extracted from the domain."""

    def __init__(self):
        """Initialize a new domain object."""
        self.score = 0
        self.domain = ""
        self.domain_unconfused = ""
        self.tld = ""
        self.no_of_domains = 1
        self.date = datetime.utcnow().isoformat()
        self.unicode = False
        self.suspicious_tld = ""
        self.suspicious_keywords = set()
        self.fake_tld = ""
        self.possible_company = set()
        self.company = set()
        self.dashes = 0
        self.sub_domains = 0
        self.free_ca = ""
        self.cn_is_none = False
        self.extended_validity = False
        self.fake_www = False

    def print(self):
        """Print all properties of this domain object."""
        print(vars(self))

    def increase_score(self, value):
        """Increase the score with value."""
        self.score += value

    def decrease_score(self, value):
        """Decrease the score with value."""
        self.score -= value

    def reset_score(self):
        """Reset the score to zero."""
        self.score = 0


def unconfuse(domain_name: str, confusables: Dict[str, str]) -> Tuple[str, bool]:
    """
    Detect confusables and typo squatting in domain names.

    :param domain_name: domain name as a string
    :return: the unconfused domain name and a boolean indicating a change
    """
    confused_characters = False

    # If the domain contains xn--, there is unicode involved
    if domain_name.find("xn--") == 0:
        try:
            domain_name = domain_name.encode("idna").decode("idna")

        # If this step fails, it contains weird (unsupported characters),
        # so return that confused_characters are used
        except Exception:
            confused_characters = True
            return domain_name, confused_characters

    # If previous steps worked, try to unconfuse the domain name
    unconfused = ""
    for _, character in enumerate(domain_name):
        # If the confused character can be found in the list
        if character in confusables:
            # Add it to the unconfused domain name
            unconfused += confusables[character]

            # If a character is a unicode confusable, set confused characters true
            if character.isalpha():
                confused_characters = True
        else:
            # Else, just add the character to the unconfused domain name
            unconfused += character

    return unconfused, confused_characters


def search_for_default_subdomains(domain_name: str) -> bool:
    """
    Search for default subdomains to filter them out.

    :param domain_name:
    :return:
    """
    pattern = r"^(webmail|webdisk|mail|cpcontacts|cpcalendars|cpanel|autodiscover|pop3|pop|smtp|ftp|servicenow|autodiscover|autoconfig|ns\d*|imap)\."
    return True if match(pattern, domain_name) else False
