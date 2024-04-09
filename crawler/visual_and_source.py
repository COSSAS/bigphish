"""Functions related to visual profiling and source of acquired pages."""

import hashlib
import logging
from io import BytesIO
from time import sleep
from typing import List, Set, Tuple, Union

import imagehash
from PIL import Image
from selenium.webdriver.common.utils import find_connectable_ip
from selenium.webdriver.firefox.options import Options
from seleniumwire import webdriver
from utils import Domain, get_user_agent, url_is_valid_website
from wrapt_timeout_decorator import *


@timeout(  # type: ignore
    25, exception_message="Resolving this website took more than 25 seconds, aborting"
)
def browse_to_website(
    domain: Domain, valid_urls=Set[str]
) -> Tuple[bool, Domain, Union[bytes, None]]:
    """
    Perform all visual/source routines for a given domain.

    :param domain: domain object
    :return: updated domain object and a boolean indicating success
    """
    logging.info(f"[{domain.domain}] Profiling domain with Selenium browser...")
    try:
        driver = get_new_webdriver()
    except Exception as error:
        logging.error(f"[{domain.domain}] Failed to initiate a new Webdriver: {error}")
        return False, domain, None
    try:
        logging.debug(f"[{domain.domain}] Webdriver GET website {domain.domain}")
        driver.get(f"https://{domain.domain}")
        sleep(4)

        domain.landing_url = driver.current_url

        # Check if redirected to a known valid website and quit afterwards
        if url_is_valid_website(
            domain.domain, domain.landing_url, valid_urls=valid_urls
        ):
            logging.warning(
                f"[{domain.domain}] Redirect detected to a real bank or something generic: {domain.landing_url}"
            )
            domain.identified_as = "redirected"
            driver.quit()
            return False, domain, None

        domain.doc_title = driver.title
        domain.ip = get_ip(domain.domain)
        domain.resources = get_list_of_resources(driver, domain.domain)
        domain.html_source = get_html_source(driver, domain.domain)
        domain.html_hash = get_html_hash(domain.html_source)
        screenshot_file, domain.screenshot_hash = create_screenshot_and_hash(
            driver, domain.domain
        )

        logging.debug(f"[{domain.domain}] Shutting down selenium instance.")
        driver.quit()

        return True, domain, screenshot_file

    except Exception as error:
        logging.warning(
            f"[{domain.domain}] Error accessing website: {str(error)[:40]}, aborting."
        )
        driver.quit()
        return False, domain, None


def get_html_source(driver: webdriver.Firefox, domain_name: str) -> str:
    """
    Retrieve the current HTML source.

    :param domain_name: the domain that is being analyzed
    :param driver: WebDriver object containing the current session
    :return: HTML source code of the current page
    """
    # Get HTML contents from web driver
    try:
        return driver.page_source
    except Exception as error:
        logging.error(
            f"[{domain_name}] Error encountered while getting page source: {error}"
        )
        return ""


def get_html_hash(html_source: str) -> str:
    """
    Generate the MD5 of the html of the current html source.

    :param html_source: source code of the current HTML page
    :return: hash of the given source code
    """
    md5hash = hashlib.md5()
    md5hash.update(str.encode(html_source))
    html_hash = md5hash.hexdigest()
    return html_hash


def create_screenshot_and_hash(
    driver: webdriver.Firefox, domain_name: str
) -> Tuple[bytes, str]:
    """
    Generate a screenshot of the current page and create an average hash of it.

    :param driver: webdriver object pointing to the current website
    :param domain_name: domain name of the current website
    :return: filepath to the screenshot taken, average hash of it
    """
    # Get the screenshot from WebDriver as binary PNG
    screenshot_data = driver.get_screenshot_as_png()

    # Hash the PNG data object
    screenshot_hash = ""
    try:
        screenshot_hash = str(
            imagehash.average_hash(Image.open(BytesIO(screenshot_data)))
        )
    except Exception as error:
        logging.warning(f"[{domain_name}] Could not create screenshot hash: {error}")

    return screenshot_data, screenshot_hash


def get_list_of_resources(driver: webdriver.Firefox, domain_name: str) -> List[str]:
    """
    Acquire the list of all resources loaded while browsing to the website.

    :param domain_name: the analyzed domain
    :param driver: the Webdriver object
    :return: the list of loaded resources as an array
    """
    loaded_resources = []
    try:
        for request in driver.requests:
            if (
                request.response
                and request.response.status_code == 200
                and "mozilla" not in request.url
            ):
                loaded_resources.append(request.url)

    except Exception:
        logging.warning(f"[{domain_name}] Failed to list the list of resources.")

    return loaded_resources


def get_ip(domain_name: str) -> str:
    """
    Get the resolved IP of a given entry.

    :param domain_name: domain to be resolved
    :return: the IP address or an empty string
    """
    ip = find_connectable_ip(domain_name, 443)
    logging.debug(f"[{domain_name}] Resolved following IP: {ip}")
    return ip if ip else "0.0.0.0"


def get_new_webdriver() -> webdriver.Firefox:
    """
    Instantiate a selenium driver.

    :return: a WebDriver object
    """
    logging.debug("Instantiating Selenium Gecko WebDriver..")

    # Add multiple options to reduce RAM usage
    options = Options()
    options.accept_insecure_certs = True
    options.add_argument("start-maximized")
    options.add_argument("disable-infobars")
    options.add_argument("--headless")
    options.add_argument("--disable-extensions")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-application-cache")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-dev-shm-usage")

    options.set_preference("browser.contentblocking.enabled", False)
    options.set_preference("privacy.trackingprotection.enabled", False)
    options.set_preference("privacy.trackingprotection.pbmode.enabled", False)
    options.set_preference("privacy.trackingprotection.cryptomining.enabled", False)
    options.set_preference("privacy.trackingprotection.fingerprinting.enabled", False)
    options.set_preference("privacy.trackingprotection.socialtracking.enabled", False)

    # disable prefetching
    options.set_preference("network.dns.disablePrefetch", True)
    options.set_preference("network.prefetch-next", False)
    # disable OpenH264 codec downloading
    options.set_preference("media.gmp-gmpopenh264.enabled", False)
    options.set_preference("media.gmp-manager.url", "")
    # disable health reports
    options.set_preference("datareporting.healthreport.service.enabled", False)
    options.set_preference("datareporting.healthreport.uploadEnabled", False)
    options.set_preference("datareporting.policy.dataSubmissionEnabled", False)
    # disable experiments
    options.set_preference("experiments.enabled", False)
    options.set_preference("experiments.supported", False)
    options.set_preference("experiments.manifest.uri", "")
    # disable telemetry
    options.set_preference("toolkit.telemetry.enabled", False)
    options.set_preference("toolkit.telemetry.unified", False)
    options.set_preference("toolkit.telemetry.archive.enabled", False)
    # disable captive portal detection
    options.set_preference("network.captive-portal-service", False)
    options.set_preference("network.connectivity-service", False)

    # Create a fresh profile
    options.set_preference("general.useragent.override", get_user_agent()["User-Agent"])
    options.set_preference("javascript.enabled", True)

    driver = webdriver.Firefox(options=options)
    driver.set_page_load_timeout(8)

    return driver
