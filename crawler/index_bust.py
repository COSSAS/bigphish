"""Find phishing kit fingerprints on the index page."""

import logging
from os import environ
from pathlib import Path
from re import split
from typing import List, Tuple

from bs4 import BeautifulSoup

RELATED_KIT_RATIO_THRESHOLD = float(
    str(environ.get("RELATED_KIT_RATIO_THRESHOLD", 0.1))
)


def find_fingerprints_index_page(
    domain: str, html_source: str, fingerprints
) -> Tuple[List[str], List[str]]:
    """
    Find all kits by searching through the files in an open directory.

    :param domain: domain name
    :param html_source: string of the complete HTML source
    :param fingerprints: dictionary of kit fingerprints
    :return:
    """
    # Initialize return placeholders
    index_bust_identified_kits = set()
    total_matched_urls = set()
    links_to_check = []

    # Parse the HTML source and collect all links to files in this directory
    soup = BeautifulSoup(html_source, features="html5lib")
    for link in soup.findAll("a", href=True):
        links_to_check.append(str(link["href"]))

    # Search for fingerprints of kits on this page
    for kit_name, kit_properties in fingerprints.items():
        matched_urls = []
        kit_pages = kit_properties["pages"].keys()

        for file_link in links_to_check:
            file_name = Path(split(r"[?#]", file_link)[0]).name
            if any(Path(page_url).name == file_name for page_url in kit_pages):
                matched_urls.append(file_link)

        ratio_resolvable = len(matched_urls) / len(kit_pages)

        # When the resolvable ratio is above the threshold and at least 2 urls are matched
        if len(matched_urls) > 1:
            if ratio_resolvable > RELATED_KIT_RATIO_THRESHOLD or len(matched_urls) > 3:
                index_bust_identified_kits.add(kit_name)

        for url in matched_urls:
            total_matched_urls.add(url)

    index_bust_identified_kits_list = list(index_bust_identified_kits)
    logging.info(
        f"[{domain}] Identified kits by index bust: {index_bust_identified_kits_list}"
    )

    return index_bust_identified_kits_list, list(total_matched_urls)
