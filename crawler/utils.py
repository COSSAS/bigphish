"""General purpose utilities."""

import json
import logging
import os
import pathlib
import socket
from re import findall
from time import sleep
from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse

import dns.resolver
import minio_operations
import requests
import tld
import whois
from bs4 import BeautifulSoup
from domain import Domain
from elk_operations import test_elk
from psutil import process_iter


def check_domain_is_up(domain_name: str) -> Tuple[str, str]:
    """
    Check if a domain is online.

    :param domain_name: domain name to be checked
    :return: 'online' if up, otherwise 'offline'
    """
    headers = get_user_agent()
    try:
        response = requests.get(
            f"https://{domain_name}/",
            timeout=3,
            headers=headers,
            verify=False,
            allow_redirects=False,
        )
        # If any server errors are returned, we assume it to be offline and at least not working
        if response.status_code < 500:
            return "online", response.headers.get("Server", "")

    except Exception as error:
        logging.debug(f"[{domain_name}] Could not connect: {error}")

    return "offline", ""


def get_user_agent() -> Dict[str, str]:
    """
    Return a static user agent for all Internet facing functions (Selenium, requests, etc.).

    :return: a user-agent string
    """
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    }


def health_check() -> bool:
    """
    Check if there is a healthy connection with ElasticSearch, Minio and VPN.

    :return: returns true is ready to go, otherwise false
    """
    for try_id in range(1, 21):
        logging.info(f"Performing health check.. #{try_id}")

        # Now make sure that the VPN service is running
        try:
            # Try to establish ElasticSearch connection
            if not test_elk():
                raise Exception("No connection to Elasticsearch")
            logging.info("OK: Elasticsearch connection is established successfully")

            # Check if that ASN matches the one in the configuration
            asn = retrieve_current_asn()
            if asn != os.environ.get("VPN_ASN", "unknown"):
                raise Exception(
                    f"ASN is {asn}, this should be {os.environ.get('VPN_ASN', 'unknown')}"
                )
            logging.info("OK: Active VPN connection established successfully")

            # Check if MinIO connection can be established
            if not minio_operations.test_minio():
                raise Exception("No connection to MinIO")
            logging.info("OK: MinIO connection established successfully")

            # If all good, wait 20s and return True
            logging.info(
                "Connected to VPN, Elasticsearch and MinIO "
                "now waiting 20s for everything to start up.."
            )
            sleep(20)
            return True

        except Exception as error:
            logging.error(f"Something went wrong during health checks: {error}")
            sleep(30)

    return False


def retrieve_current_asn() -> str:
    """
    Try to retrieve the ASN of the current IP connection.

    :return:
    """
    # First try ifconfig.me
    try:
        headers = get_user_agent()
        request = requests.get("https://ifconfig.co/asn", timeout=4, headers=headers)
        asn = request.content.decode("utf-8").rstrip()
        if asn and len(asn) < 12:
            return asn
    except Exception:
        pass

    # If that one is down, try ipinfo.io
    try:
        request = requests.get(
            "https://ipinfo.io",
            timeout=4,
            headers={"User-Agent": "curl"},
        )
        asn = json.loads(request.content)["org"].split(" ")[0]
        if asn and len(asn) < 12:
            return asn
    except Exception:
        pass

    return ""


def url_is_valid_website(domain_name: str, url: str, valid_urls: Set[str]) -> bool:
    """
    Check whether the url is listed in valid websites list.

    :param domain_name: domain currently analyzing
    :param url: the landing URL of a domain object
    :return: true if equal to a benign url, false otherwise
    """
    try:
        fld = tld.get_tld(url, as_object=True).fld  # type: ignore
        if fld in valid_urls:
            logging.debug(
                f"[{domain_name}] Looks like this page redirects to a benign website {url}!"
            )
            return True

    except (tld.exceptions.TldDomainNotFound, tld.exceptions.TldBadUrl):
        logging.error(f"[{domain_name}] {url} does not link to a valid domain name")

    return False


def populate_whois(domain: Domain) -> Domain:
    """
    Get the WHOIS information for a given domain.

    :param domain: domain object in which data is appended
    :return: the updated domain object
    """
    logging.info(f"[{domain.domain}] Acquiring WHOIS for records")

    try:
        main_domain = tld.get_tld(f"https://{domain.domain}", as_object=True).fld  # type: ignore
        whois_record = whois.whois(main_domain)
        domain.whois_source = str(whois_record.text)  # usually very long string

        if whois_record.registrar:
            domain.whois_registrar = whois_record.registrar

        # In case of multiple parsed creation dates, pick the most recent one
        if whois_record.creation_date:
            if isinstance(whois_record.creation_date, list):
                max_value = max(whois_record.creation_date)
                domain.whois_reg_date = max_value.timestamp()
            else:
                domain.whois_reg_date = whois_record.creation_date.timestamp()

        # In case of multiple parsed expiration dates, pick the most recent one
        if whois_record.expiration_date:
            if isinstance(whois_record.expiration_date, list):
                max_value = max(whois_record.expiration_date)
                domain.whois_exp_date = max_value.timestamp()
            else:
                domain.whois_exp_date = whois_record.expiration_date.timestamp()

        if whois_record.country:
            domain.whois_country = whois_record.country

    except Exception:
        logging.warning(
            f"[{domain.domain}] Error obtaining WHOIS records, continuing.."
        )
        return domain

    logging.debug(f"[{domain.domain}] WHOIS records obtained successfully")

    return domain


def combine_dir_resource_busts(
    list_dirbust: List[str], list_resourcebust: List[str]
) -> List[str]:
    """
    Combine the results from all busting activities.

    :param list_dirbust: input list from dirbusting
    :param list_resourcebust: input list from resourcebusting
    :return: output set of all detected phishing kits
    """
    combined = set()
    for bust_list in [list_dirbust, list_resourcebust]:
        for kit in bust_list:
            combined.add(kit)
    return list(combined)


def check_for_kits(url: str, html_source: str, domain: str) -> None:
    """
    Download any phishing kit archive files in an open directory.

    :param domain: the domain name on which we are searching
    :param url: landing URL of the website
    :param html: HTML source of the website including the open directory
    """
    archive_file_types = (".zip", ".tar", ".7z", ".rar", ".tar.gz", ".tgz")

    if "Index of /" in html_source:
        soup = BeautifulSoup(html_source, features="html5lib")
        for link in soup.findAll("a", href=True):
            if link["href"].endswith(archive_file_types):
                headers = get_user_agent()
                request = requests.get(
                    url + link["href"], timeout=30, headers=headers, verify=False
                )
                if request.ok:
                    minio_operations.store_object(
                        request.content, link["href"], "found-phishing-kits"
                    )
                    logging.info(f"[{domain}] Found phishing kit {link['href']}")


def cleanup() -> None:
    """
    Cleanup leftover FireFox processes to keep the memory free.

    :return:
    """
    for process in process_iter():
        if "firefox" in process.name():
            process.kill()
    logging.debug("Cleaned up leftover FireFox processes successfully!")


def search_for_panel_specifics(
    domain_name: str, panel_endpoints: Set[str]
) -> Tuple[str, str]:
    """Search for the panel endpoints on a detected phishing domain.

    Args:
        domain_name (str): domain name to search on
        panel_endpoints (list): list of possible endpoints

    Returns:
        Tuple[str, str]: url, title
    """
    headers = get_user_agent()

    # Try to resolve panel locations
    for panel_endpoint in panel_endpoints:
        try:
            session = requests.Session()
            session.max_redirects = 1

            url = f"https://{domain_name}/{panel_endpoint}"

            response = session.get(url, timeout=5, headers=headers, verify=False)
            if response.status_code == 200:
                page_title = extract_page_title(response.text)
                return response.url, page_title

        except Exception as error:
            logging.error(
                f"[{domain_name}] Something went wrong checking for panel login page: {error}"
            )

    return "", ""


def extract_page_title(html_source: str) -> str:
    """
    Extract the page title from a given login page.

    :param html: text from the HTML response
    :return: the title if found, empty string otherwise
    """
    try:
        return findall(r"<title>([\w\W]+)</title>", html_source)[0].rstrip()
    except Exception:
        return ""


def get_redirected_ip(domain_name: str) -> str:
    """
    Get the IP address of a domain that is redirecting.

    :param domain: domain name, e.g., example.com
    :return: resolved ip address for that domain name
    """
    try:
        return socket.gethostbyname(domain_name)
    except Exception:
        return ""


def is_url(url) -> bool:
    """
    Test if a URL is valid.

    :param url: submitted URL
    :return: boolean
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False


def get_nameservers(domain_name: str) -> List[str]:
    """
    Retrieve the authoritative nameservers for a given domain.

    :param domain_name: domain name
    :return:
    """
    nameservers = []
    try:
        fld = tld.get_tld(f"http://{domain_name}", as_object=True).fld  # type: ignore
        for server in dns.resolver.resolve(fld, "NS"):
            nameservers.append(str(server))
    except Exception as error:
        logging.warning(f"[{domain_name}] Resolving DNS nameserver failed: {error}")
    return sorted(nameservers)


def load_kit_fingerprints() -> List[Dict[str, str]]:
    """
    Get the information about the identified phishing kits from fingerprint file.

    :return: output list of dictionaries with phishing kit information
    """
    phishing_kit_fingerprints = []

    try:
        with open("phishing_kit_fingerprints.json", "r", encoding="utf-8") as file:
            phishing_kit_fingerprints = json.load(file)

        logging.info(
            f"Successfully loaded {len(phishing_kit_fingerprints)} fingerprints"
        )

    except Exception as error:
        logging.error(f"Something went wrong: {error}")

    return phishing_kit_fingerprints
