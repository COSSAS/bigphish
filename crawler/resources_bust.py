"""Categorize entries based on the files loaded on this domain."""

import logging
from os import environ
from pathlib import Path
from re import split
from typing import List, Tuple

RELATED_KIT_RATIO_THRESHOLD = float(
    str(environ.get("RELATED_KIT_RATIO_THRESHOLD", 0.1))
)


def find_kits_by_resource_bust(
    domain: str, domain_resources: List[str], fingerprints: dict
) -> Tuple[List[str], List[str]]:
    """
    Find all kits by searching through the list of loaded resources on the domain.

    :param domain: domain name
    :param domain_resources: list of resources loaded
    :param fingerprints: dictionary of kit fingerprints
    :return:
    """
    logging.info(
        f"[{domain}] Performing a resource analysis searching for kit fingerprints"
    )

    resourcebust_identified_kits = set()
    total_matched_urls = set()

    # For every fingerprint in the kit info dictionary
    if domain_resources:
        for kit_name, kit_properties in fingerprints.items():
            matched_urls = []
            kit_pages = kit_properties["pages"].keys()

            for url in domain_resources:
                file_name = Path(split(r"[?#]", url)[0]).name
                if any(Path(page_url).name == file_name for page_url in kit_pages):
                    matched_urls.append(url)

            ratio_resolvable = len(matched_urls) / len(kit_properties["pages"])

            # When the resolvable ratio is above the threshold and at least 2 urls are matched
            # break afterwards to prevent double detections
            if len(matched_urls) > 1:
                if (
                    ratio_resolvable > RELATED_KIT_RATIO_THRESHOLD
                    or len(matched_urls) > 3
                ):
                    resourcebust_identified_kits.add(kit_name)

            for url in matched_urls:
                total_matched_urls.add(url)

    resourcebust_identified_kits_list = list(resourcebust_identified_kits)
    logging.info(
        f"[{domain}] Identified kits by resource bust: {resourcebust_identified_kits_list}"
    )

    return resourcebust_identified_kits_list, list(total_matched_urls)
