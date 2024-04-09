"""Functions related False Positive detection."""

import logging
import os
import pathlib
import re
from typing import Dict, Union

from bs4 import BeautifulSoup
from imagehash import ImageHash, average_hash
from PIL import Image


def determine_empty_page(domain_name: str, html_source: str) -> bool:
    """
    Determine whether a given webpage is almost empty.

    :param domain_name: domain name of the current crawled domain
    :param html_source: HTML source string
    :return: true if empty, otherwise false
    """
    if len(html_source) < 50:
        logging.info(
            f"[{domain_name}] This page is almost empty, likely a false positive."
        )
        return True
    return False


def determine_word_press(domain):
    """
    Return true if the page is a WordPress website.

    :param domain: domain object of the analyzed domain
    :return: true if WP, false otherwise
    """
    if "WordPress" in domain.doc_title:
        return True

    for resource in domain.resources:
        if "wp-includes" in resource or "wp-content" in resource:
            return True

    return False


def determine_default_page(domain_name: str, html_source: str) -> bool:
    """
    Return true if the page looks like a default server page.

    :param domain_name: domain name of the current crawled domain
    :param html_source: HTML source string
    :return: true if a default page is found, false otherwise
    """
    defaults = [
        "Ubuntu",
        "It works",
        "Apache2",
        "The IP address has changed",
        "There has been a server misconfiguration",
        "The site may have been moved",
        "This is the default welcome page",
        "Welcome to nginx",
        "If you see this page",
        "this site is working properly",
        "This is a default index page for a new domain",
        "Parked on the Bun",
        "Namecheap Parking Page",
        "Index of /",
        "If you are the owner of this website",
        "Suspended Domain",
        "This Domain Name Has Expired",
        "Plesk",
        "Future home of a",
        "This domain is for sale",
        "This domain may be for sale",
    ]

    soup = BeautifulSoup(html_source, "html5lib")
    for default_entry in defaults:
        if re.search(default_entry, soup.get_text(), re.IGNORECASE):
            logging.info(f"[{domain_name}] This seems to be a default Web server page!")
            return True

    return False
