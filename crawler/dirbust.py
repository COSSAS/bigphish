"""Categorize entries based on files (webpages) on the same domain."""

import logging
import pathlib
from os import environ
from typing import Dict, List, Tuple
from urllib.parse import urlparse

import wfuzz
from tld import get_tld
from utils import get_user_agent
from wrapt_timeout_decorator import *

RELATED_KIT_RATIO_THRESHOLD = float(str(environ.get("CRAWLER_RELATED_KIT_RATIO", 0.1)))


@timeout(  # type: ignore
    30, exception_message="Dirbusting this website took more than 30 seconds, aborting"
)
def get_resolvable_urls(url: str, payload: Dict[str, str]) -> list:
    """
    Get resolvable urls, given a URL and payload list.

    :param url: landing url of the given analyzed domain
    :param payload: urls of kit pages (url:content-type)
    :return: list of all urls which returned 200
    """
    resolvable_urls = []
    scan = wfuzz.get_payloads([payload.keys()])
    user_agent = get_user_agent()["User-Agent"]
    content_lengths = set()

    for res in scan.fuzz(
        url=url,
        scanmode=True,
        concurrent=5,
        req_delay=4,
        conn_delay=5,
        headers=[("User-Agent", user_agent)],
    ):
        # If this item is resolved successfully and the Content-Type is correct, mark as resolved
        if res.code == 200 and payload[
            res.description
        ] in res.history.headers.response.store.get("Content-Type", ""):
            resolvable_urls.append(res.url)
            content_lengths.add(res.chars)

    # If all request respond with exactly the same amount of characters, return empty
    if len(content_lengths) == 1 and len(resolvable_urls) > 1:
        return []

    return resolvable_urls


def get_fuzzable_url(url: str) -> str:
    """
    Figure out how this URL should be fuzzed.

    :param url: the landing URL of the analyzed domain
    :return: the to-be fuzzed URL
    """
    parsed = urlparse(url)

    # Easy case (*/)
    if url.endswith("/"):
        return url + "FUZZ"

    # Plain case (*.nl)
    if parsed.path == "":
        return url + "/FUZZ"

    # Hard case: replace */asdf with */FUZZ
    url_without_scheme = parsed.netloc + parsed.path
    parent = pathlib.PosixPath(url_without_scheme).parent
    return f"https://{str(parent)}/FUZZ"


def find_kits_by_dirbust(
    domain: str, landing_url: str, fingerprints: dict
) -> Tuple[List[str], List[str]]:
    """
    Add all possible related kits to the entry for a list of entries.

    :param domain: base domain which we are analyzing
    :param landing_url: landing URL of the analyzed domain
    :param fingerprints: the loaded phishing kit fingerprint information
    :return: the identified kits and the resolved URLs
    """
    # Retrieve the netloc of the landing URL
    landing_url_parsed = get_tld(landing_url, as_object=True).parsed_url  # type: ignore
    landing_url_netloc = f"{landing_url_parsed.scheme}://{landing_url_parsed.netloc}"

    dirbust_identified_kits = []
    total_resolved_urls = set()
    fuzzable_url = get_fuzzable_url(landing_url)
    fuzzable_url_base = get_fuzzable_url(landing_url_netloc)
    resolved_extensions = set()

    # 1. First for the landing URL with respect to the last part of the URL
    # e.g., hxxps://domain.com/path/to/something/FUZZ
    # For every fingerprint in the kit info dictionary
    logging.info(f"[{domain}] Performing a dirbust analysis on {landing_url}")
    for kit_name, kit_properties in fingerprints.items():
        try:
            urls_resolvable = get_resolvable_urls(fuzzable_url, kit_properties["pages"])

        except Exception as error:
            logging.error(f"[{domain}] wFuzz error: {error}")
            urls_resolvable = []

        # Save all file extensions to check if only the same resources have been resolved
        for url in urls_resolvable:
            resolved_extensions.add(url.split(".")[-1])

        # If there is more than 1 url resolved, check if that's enough and return them
        # also, check if not all resources have the same extension.
        num_of_resolved_urls = len(urls_resolvable)
        if num_of_resolved_urls > 1 and not (
            num_of_resolved_urls > 10 and len(resolved_extensions) <= 2
        ):
            logging.debug(f"[{domain}] Resolved URLs: {urls_resolvable}")
            ratio_resolvable = num_of_resolved_urls / len(kit_properties["pages"])
            if (
                ratio_resolvable > RELATED_KIT_RATIO_THRESHOLD
                or num_of_resolved_urls >= 3
            ):
                dirbust_identified_kits.append(kit_name)

        # Add all resolved URLs anyhow
        for url in urls_resolvable:
            total_resolved_urls.add(url)

    # 2. Additionally, for the landing URL with no respect to the last part of the URL
    # e.g., hxxps://domain.com/FUZZ
    if fuzzable_url != fuzzable_url_base:
        logging.info(
            f"[{domain}] Performing a dirbust analysis on {landing_url_netloc}"
        )
        resolved_extensions = set()
        # For every fingerprint in the kit info dictionary
        for kit_name, kit_properties in fingerprints.items():
            try:
                urls_resolvable = get_resolvable_urls(
                    fuzzable_url_base, kit_properties["pages"]
                )

            except Exception as error:
                logging.error(f"[{domain}] wFuzz error: {error}")
                urls_resolvable = []

            # Save all file extensions to check if only the same resources have been resolved
            for url in urls_resolvable:
                resolved_extensions.add(url.split(".")[-1])

            # If there is more than 1 url resolved, check if that's enough and return them
            # also, check if not all resources have the same extension.
            num_of_resolved_urls = len(urls_resolvable)
            if num_of_resolved_urls > 1 and not (
                num_of_resolved_urls > 10 and len(resolved_extensions) <= 2
            ):
                logging.debug(f"[{domain}] Resolved URLs: {urls_resolvable}")
                ratio_resolvable = num_of_resolved_urls / len(kit_properties["pages"])
                if (
                    ratio_resolvable > RELATED_KIT_RATIO_THRESHOLD
                    or num_of_resolved_urls >= 3
                ):
                    dirbust_identified_kits.append(kit_name)

            # Add all resolved URLs anyhow
            for url in urls_resolvable:
                total_resolved_urls.add(url)

    logging.info(f"[{domain}] Identified kits by dirbust: {dirbust_identified_kits}")

    # Check if not too many kits are identified..
    if len(dirbust_identified_kits) > 1:
        maximum_resolvable_kits = min(round(len(fingerprints) / 2), 4)
        if len(dirbust_identified_kits) >= maximum_resolvable_kits:
            logging.warning(
                f"[{domain}] More than half of all kits are resolved, aborting analysis"
            )
            return [], []

    if len(total_resolved_urls) > 20 and len(resolved_extensions) < 2:
        logging.warning(
            f"[{domain}] More than 20 URLs are resolved and just a few extensions, aborting analysis"
        )
        return [], []

    return dirbust_identified_kits, list(total_resolved_urls)
