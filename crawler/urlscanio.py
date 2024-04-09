"""Interact and retrieve domains from URLscan.io."""

import ipaddress
import json
import logging
from os import environ
from re import match
from typing import Set

import requests

API_KEY = environ.get("URLSCANIO_API_KEY")
API_SEARCH_ENDPOINT = "https://urlscan.io/api/v1/search/?q="


def build_urlscanio_query(fingerprints, date: str = "now-80m") -> str:
    """
    Build the query for URLscan.io, given a list of fingerprints.

    :param fingerprints: parsed json file with fingerprints
    :param date: date in elastic format
    :return: created query
    """
    unique_searches = set()
    query = "("

    for _, kit in fingerprints.items():
        if kit.get("searches"):
            for search in kit.get("searches"):
                if search not in unique_searches:
                    unique_searches.add(search)
                    query += f"{search} OR "
    query = query[:-4] + f") AND date:<{date}"

    logging.debug(f"Searching on URLscan.io for: {query}")
    return query if query != "(" else ""


def is_ip(domain: str) -> bool:
    """
    Check if a given domain is an IP address.

    :param domain:
    :return:
    """
    try:
        return True if ipaddress.ip_address(domain) else False
    except ValueError:
        return False


def get_domains_from_urlscanio(fingerprints) -> Set[str]:
    """
    Get new domains from URLscan.io database.

    :param fingerprints: parsed json file all fingerprint information
    :return: set of URLscan domains
    """
    domain_set: Set[str] = set()

    if not API_KEY:
        logging.error("No API key supplied for URLscan.io!")
        return domain_set

    # Build one query with all the searches
    query = build_urlscanio_query(fingerprints)

    # Query URLscan.io database
    try:
        headers = {"API-KEY": API_KEY, "Content-Type": "application/json"}
        res = requests.get(
            url=f"{API_SEARCH_ENDPOINT}{query}", headers=headers, timeout=5
        )
        res_json = json.loads(res.text).get("results")
    except Exception as error:
        logging.error(f"Error retrieving URLs from URLscan.io: {error}")
        return domain_set

    # Process the results
    for hit in res_json:
        domain = hit.get("page", {}).get("domain")
        if not is_ip(domain):
            # Remove www. from URL to prevent double insertions
            if domain.startswith("www."):
                domain = domain[4:]
            domain_set.add(domain)

    logging.info(f"Got {len(domain_set)} domains to analyse from URLscan.io")
    return domain_set
