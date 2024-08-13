"""Utilities to process data."""

import json
import logging
from collections import defaultdict
from datetime import datetime, timezone
from json import dumps
from operator import itemgetter
from os import environ
from typing import Any, Dict, List, Set
from urllib.parse import urlparse

import requests
from tld import get_tld

history_chart_items = {
    "Domain registered": "whois_reg_date",
    "Certificate issued": "date_certificate_issued",
    "First crawled": "first_crawled",
    "Kit installed": "date_kit_installed",
    "Domain online": "date_first_online",
    "Domain offline": "date_offline",
}


class Domain:
    """Domain object."""

    def __init__(self, domain_name):
        """Initialize a new domain object."""
        self.domain = domain_name
        self.landing_url = ""
        self.crawl_date = datetime.now(timezone.utc)
        self.state = "unknown"
        self.identified_as = "unknown"
        self.first_crawled = datetime.now(timezone.utc)
        self.nameservers = []

        # Visual and source information
        self.screenshot_file = ""
        self.screenshot_hash = ""
        self.favicon_hash = ""
        self.doc_title = ""
        self.html_source = ""
        self.html_hash = ""
        self.resources = ""
        self.ip = ""
        self.server_header = ""

        # WHOIS information
        self.whois_source = ""
        self.whois_registrar = ""
        self.whois_reg_date = 0  # int: unix epoch
        self.whois_exp_date = 0  # int: unix epoch
        self.whois_country = ""

        # Phishing kit analysis information
        self.resolved_urls = []
        self.dirbust_identified_kits = []
        self.stringbust_identified_kits = []
        self.resolved_strings = []
        self.resourcebust_identified_kits = []
        self.resolved_resources = []
        self.identified_kits = []

        # uAdmin specific information
        self.uadmin = False
        self.uadmin_login = ""
        self.uadmin_login_title = ""


def is_url(url: str) -> bool:
    """
    Test if a submitted URL is valid or not.

    :param url: submitted URL
    :return: boolean
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False


def process_domain_entries(
    domain: str,
    crawler_entries: List[Dict[Any, Any]],
    domain_index_entry: Dict[Any, Any],
    screenshot_entries: Dict[Any, Any],
    active_domains: Set[str],
    gsb_status: bool,
    location_details,
) -> Dict[Any, Any]:
    """
    Process all the entries for a given domain.

    :param domain: the given domain
    :param crawler_entries: list of entries from crawler_index
    :param domain_index_entry: dictionary containing the domain_index information
    :param screenshot_entries: list of accompanied screenshots
    :param active_domains: list of active domains to determine if online or not
    :return:
    """
    # Set the domain and retrieve all information from the domain_index entries
    output = {
        "domain": domain,
        "score": domain_index_entry.get("score", ""),
        "possible_company": domain_index_entry.get("possible_company", ""),
        "company": domain_index_entry.get("company", ""),
        "sub_domains": domain_index_entry.get("sub_domains", ""),
        "free_ca": domain_index_entry.get("free_ca", ""),
        "extended_validity": domain_index_entry.get("extended_validity", ""),
        "first_crawled": datetime(1970, 1, 1),
        "nameservers": [],
        "uadmin": "",
        "uadmin_login": "",
        "uadmin_login_title": "",
        "whois_registrar": "",
        "whois_country": "",
        "whois_reg_date": "",
        "whois_exp_date": "",
        "whois_source": "",
        "ip": "",
        "ip_country": "",
        "ip_org": "",
        "ip_location": "",
        "server_header": "",
        "phishing_kits_identified": set(),
        "date_certificate_issued": "",
        "date_first_online": datetime.now(timezone.utc),
        "date_kit_installed": datetime.now(timezone.utc),
        "gsb_status": gsb_status,
    }

    if domain_index_entry.get("date"):
        output["date_certificate_issued"] = datetime.fromisoformat(
            domain_index_entry.get("date", "")
        )

    # Set the state of the domain
    output["state"] = "online" if output["domain"] in active_domains else "offline"

    page_history = []
    screenshots_hashes_seen = set()
    set_of_resolved_urls = {f"https://{output['domain']}"}

    for entry in crawler_entries:
        # Get the latest first crawled date (to fix double entries..)
        if datetime.fromisoformat(entry["first_crawled"]) > output["first_crawled"]:
            output["first_crawled"] = datetime.fromisoformat(entry["first_crawled"])

        # Get the nameservers
        output["nameservers"] = (
            entry.get("nameservers", "")
            if entry.get("nameservers", False)
            else output["nameservers"]
        )

        # Get the uAdmin information
        output["uadmin"] = (
            entry.get("uadmin", "") if entry.get("uadmin", False) else output["uadmin"]
        )
        output["uadmin_login"] = (
            entry.get("uadmin_login", "")
            if entry.get("uadmin_login", False)
            else output["uadmin_login"]
        )
        output["uadmin_login_title"] = (
            entry.get("uadmin_login_title", "")
            if entry.get("uadmin_login_title", False)
            else output["uadmin_login_title"]
        )

        # Get the WHOIS information
        output["whois_registrar"] = (
            entry.get("whois_registrar", "")
            if entry.get("whois_registrar", False)
            else output["whois_registrar"]
        )
        output["whois_country"] = (
            entry.get("whois_country", "")
            if entry.get("whois_country", False)
            else output["whois_country"]
        )
        output["whois_reg_date"] = (
            entry.get("whois_reg_date", "")
            if entry.get("whois_reg_date", False)
            else output["whois_reg_date"]
        )
        output["whois_exp_date"] = (
            entry.get("whois_exp_date", "")
            if entry.get("whois_exp_date", False)
            else output["whois_exp_date"]
        )
        output["whois_source"] = (
            entry.get("whois_source", "")
            if entry.get("whois_source", False)
            else output["whois_source"]
        )

        # Retrieve all IP and server information
        output["ip"] = entry.get("ip", "") if entry.get("ip", False) else output["ip"]
        output["server_header"] = (
            entry.get("server_header", "")
            if entry.get("server_header", False)
            else output["server_header"]
        )

        # Add all identified kits to the output dict
        for kit in entry.get("identified_kits", []):
            output["phishing_kits_identified"].add(kit)

        for resolved_url in entry.get("resolved_urls", ""):
            set_of_resolved_urls.add(resolved_url)
        set_of_resolved_urls.add(
            output["uadmin_login"]
        )  # Also add the panel login page

        for resolved_resource in entry.get("resolved_resources", ""):
            set_of_resolved_urls.add(resolved_resource)

        if entry.get("screenshot_hash", False):
            if entry.get("screenshot_hash") not in screenshots_hashes_seen:
                page = {
                    "doc_title": entry.get("doc_title", ""),
                    "crawl_date": datetime.fromisoformat(entry["crawl_date"]),
                    "html_source": entry.get("html_source", ""),
                    "landing_url": entry.get("landing_url", ""),
                    "resources": entry.get("resources", ""),
                    "state": entry.get("state", ""),
                    "identified_as": entry.get("identified_as", ""),
                    "resolved_urls": list(
                        set(
                            entry.get("resolved_resources", [])
                            + entry.get("resolved_urls", [])
                        )
                    ),
                    "identified_kits": entry.get("identified_kits", ""),
                    "screenshot": "",
                }

                # Add screenshot to page dictionary
                if entry.get("screenshot_hash", False):
                    page["screenshot"] = screenshot_entries.get(
                        entry.get("screenshot_hash"), ""
                    )

                # Append to pages history list and add screenshot hash to set of seen hashes
                page_history.append(page)
                screenshots_hashes_seen.add(entry.get("screenshot_hash"))

        # Calculate first online, active and offline timestamps
        crawl_date_timestamp = datetime.fromisoformat(entry["crawl_date"])
        if entry["state"] == "online":
            if crawl_date_timestamp < output["date_first_online"]:
                output["date_first_online"] = crawl_date_timestamp

            if entry["identified_as"] == "kit_identified":
                if crawl_date_timestamp < output["date_kit_installed"]:
                    output["date_kit_installed"] = crawl_date_timestamp

            if output.get("date_offline"):
                if crawl_date_timestamp > output["date_offline"]:
                    del output["date_offline"]

        if (
            entry["state"] == "offline"
            and crawl_date_timestamp > output["date_first_online"]
        ):
            output["date_offline"] = crawl_date_timestamp

    # Handle all time based information
    if output.get("date_offline", False):
        output["total_uptime_hour"] = round(
            (output["date_offline"] - output["date_first_online"]).total_seconds()
            / 3600
        )
        output["date_offline"] = output["date_offline"]
    else:
        output["total_uptime_hour"] = round(
            (datetime.now(timezone.utc) - output["date_first_online"]).total_seconds()
            / 3600
        )
        output["date_offline"] = ""

    output["date_first_online"] = output["date_first_online"]
    output["date_kit_installed"] = output["date_kit_installed"]

    if output["whois_reg_date"]:
        output["whois_reg_date"] = datetime.fromtimestamp(output["whois_reg_date"])
    if output["whois_exp_date"]:
        output["whois_exp_date"] = datetime.fromtimestamp(output["whois_exp_date"])

    output["resolved_urls"] = list(set_of_resolved_urls)
    output["phishing_kits_identified"] = list(output["phishing_kits_identified"])
    output["pages"] = sorted(page_history, key=itemgetter("crawl_date"), reverse=True)

    # Create a sorted history chart
    history_chart = []
    for label, value in history_chart_items.items():
        if output.get(value, None):
            history_chart.append(
                {"label": label, "time": output[value]},
            )
    output["history_chart"] = sorted(history_chart, key=itemgetter("time"))

    # Add IPinfo data to this domain object
    if location_details:
        output["ip_country"] = location_details.get("country_iso_code")
        output["ip_country_name"] = location_details.get("country_name")
        output["ip_location"] = (
            f"{location_details.get('city_name', '')}, {location_details.get('region_name', '')}"
        )
    return output


def generate_trends_statistics(
    aggregations, date_from: str, date_to: str
) -> Dict[Any, Any]:
    """
    Generate and calculate all the trend page statistics.

    :param domains: list of domains to be analysed
    :param false_positives: set of false positives to be excluded
    :param date_from: date from
    :param date_to: date to
    :return:
    """
    # Initialize totals
    kits_per_day: Dict[Any, Any] = defaultdict(dict)
    domains_active_per_day: Dict[Any, Any] = {}
    total_kit_counts_dict: Dict[str, int] = {}
    total_tld_popularity: Dict[str, int] = {}
    all_domains: List[str] = []
    uptimes: List[float] = []
    new_domains = 0

    # Parse the dates
    date_from_parsed = datetime.strptime(date_from, "%Y-%m-%dT%H:%M:%S.%fZ")
    date_to_parsed = datetime.strptime(date_to, "%Y-%m-%dT%H:%M:%S.%fZ")

    # Collect all domains into a list
    for domain in aggregations["all_domains"]["buckets"]:
        all_domains.append(domain["key"])

        # Parse the dates to calculate uptime and to count new domains in view
        first_crawled = datetime.strptime(
            domain["2"]["value_as_string"], "%Y-%m-%dT%H:%M:%S.%fZ"
        )
        first_online = datetime.strptime(
            domain["3"]["value_as_string"], "%Y-%m-%dT%H:%M:%S.%fZ"
        )
        last_online = datetime.strptime(
            domain["4"]["value_as_string"], "%Y-%m-%dT%H:%M:%S.%fZ"
        )

        # Domains that are first crawled within our time frame are considered new
        if first_crawled > date_from_parsed:
            new_domains += 1

            # Domains that have gone offline one day before the end of our time frame
            # are considered offline and we calculate their uptime
            if ((date_to_parsed - last_online).total_seconds() / 3600) > 24:
                uptimes.append((last_online - first_online).total_seconds() / 3600)

    # Collect the kit counts into a dictionary
    for kit in aggregations["kit_totals"]["buckets"]:
        total_kit_counts_dict[kit["key"]] = kit["1"]["value"]

    # Collect the domains active per day into a dictionary
    for kit in aggregations["totals_per_day"]["buckets"]:
        domains_active_per_day[kit["key_as_string"].split("T")[0]] = kit["1"]["value"]

    # Collect the kit counts per day into a dictionary
    for kit in aggregations["kits_per_day"]["buckets"]:
        kit_name = kit["key"]
        for date_key in kit["1"]["buckets"]:
            date = date_key["key_as_string"].split("T")[0]
            kits_per_day[date][kit_name] = date_key["unique_domains"]["value"]

    # Calculate the most popular TLD
    for domain in all_domains:
        tld = str(get_tld(f"http://{domain}", fail_silently=True))
        total_tld_popularity[tld] = total_tld_popularity.get(tld, 0) + 1

    # Return output as a JSON
    return {
        "domains_active_per_day": domains_active_per_day,
        "kits_per_day": kits_per_day,
        "kit_totals": total_kit_counts_dict,
        "domains": all_domains,
        "total_domains": len(all_domains),
        "total_new_domains": new_domains,
        "total_average_time_online": sum(uptimes) / max(len(uptimes), 1),
        "total_popular_tld": (
            max(total_tld_popularity.items(), key=lambda k: k[1])[0]
            if total_tld_popularity
            else "unknown"
        ),
    }


def get_gsb_status(domain_name: str) -> bool:
    """Retrieve the current status from Google Safe Browsing.

    Args:
        domain_name (str): domain name to check

    Returns:
        bool: true if reported, false otherwise
    """
    gsb_api_key = environ.get("GSB_API_KEY", None)

    if not gsb_api_key:
        logging.error("No GSB_API_KEY specified, GSB lookup failed!")
        return False

    gsb_endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key="
    data = {
        "client": {"clientId": "bigphish", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
                "THREAT_TYPE_UNSPECIFIED",
            ],
            "platformTypes": ["ALL_PLATFORMS"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": domain_name}],
        },
    }
    response = requests.post(
        f"{gsb_endpoint}{gsb_api_key}",
        data=dumps(data),
        headers={"Content-Type": "application/json"},
        timeout=2,
    )
    if response.json().get("matches", None):
        return True
    return False


def load_kit_fingerprints() -> list[dict[str, str]]:
    """
    Get the information about the identified phishing kits from fingerprint file.

    :return: output list of dictionaries with phishing kit information
    """
    phishing_kit_fingerprints = []

    try:
        with open("phishing_kit_fingerprints.json", "r", encoding="utf-8") as file:
            phishing_kit_fingerprints = json.load(file)

        logging.debug(
            f"Successfully loaded {len(phishing_kit_fingerprints)} fingerprints"
        )

    except Exception as error:
        logging.error(f"Fingerprint loading went wrong: {error}")

    return phishing_kit_fingerprints


def save_fingerprints(fingerprints: List[Dict[str, str]]) -> None:
    """
    Save a collection of fingerprints to file.

    :param fingerprints:
    :return:
    """
    with open("phishing_kit_fingerprints.json", "w", encoding="utf-8") as file:
        file.write(json.dumps(fingerprints))


def load_api_tokens() -> set[str]:
    """
    Load all valid API tokens from file.

    :return: set of API token strings
    """
    api_tokens = set()

    try:
        with open("api_tokens.json", "r", encoding="utf-8") as file:
            api_tokens_list = json.load(file)
            for token_pair in api_tokens_list:
                api_tokens.add(token_pair.get("token"))

        logging.debug(f"Successfully loaded {len(api_tokens)} API tokens")

    except Exception as error:
        logging.error(f"API token loading went wrong: {error}")

    return api_tokens


def insert_new_token(token: str, organisation: str) -> None:
    """
    Insert a new API token and save to file.

    :return:
    """
    try:
        with open("api_tokens.json", "r", encoding="utf-8") as file:
            api_tokens_list = json.load(file)

        api_tokens_list.append({"name": organisation, "token": token})

        with open("api_tokens.json", "w", encoding="utf-8") as file:
            file.write(json.dumps(api_tokens_list))

    except Exception as error:
        logging.error(f"API token insertion went wrong: {error}")


def check_if_token_is_valid(token: str, token_set: set) -> bool:
    """
    Check if a given token value is allowed to view this API endpoint.

    :param token: X-API-Token value
    :return:
    """
    return True if token in token_set else False
