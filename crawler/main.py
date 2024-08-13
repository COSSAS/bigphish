"""Main crawler file."""

import argparse
import json
import logging
import sys
from datetime import datetime, timedelta, timezone
from os import environ

import dirbust
import elk_operations as elastic
import exceptions
import fp_detection
import index_bust
import minio_operations
import resources_bust as resbust
import urlscanio as urlscan
import utils
import visual_and_source
from domain import Domain

RESTART_TIMEOUT = float(environ.get("CRAWLER_RESTART_TIMEOUT", 3600))
KIT_FINGERPRINTS = {}
MONITORING_TIME = int(environ.get("CRAWLER_MONITORING_TIME", 5))

# Load the list of valid URLs to ignore while crawling
with open("valid_websites.json", "r", encoding="utf-8") as file:
    VALID_URLS = set(json.load(file))


def main(args) -> None:
    """
    Orchestrate the crawling process.

    :param args:
    :return:
    """
    logging.info("Started a crawler analysis run!")

    # Prepare for running
    minio_operations.check_and_create_buckets(["screenshots", "found-phishing-kits"])

    # Retrieve the latest fingerprints
    global KIT_FINGERPRINTS
    KIT_FINGERPRINTS = utils.load_kit_fingerprints()

    # Now analyse all the retrieved domains!
    for domain_to_be_analyzed in get_domains(
        urlscan_domains=bool(args.urlscan_domains)
    ):
        crawling_process(domain_to_be_analyzed)

    logging.info(f"Finished processing run at: {datetime.now()}")


def get_domains(urlscan_domains=True) -> list:
    """
    Create list for all domains that have to be crawled.

    :param: urlscan_domains: boolean to indicate the use of URLscan.io
    :return:
    """
    input_domains = []
    unique_domains = set()

    # Retrieve all the attributes of a domain
    domain_attributes = Domain("example.com").__dict__.keys()

    # Get all false positives to filter them out
    logging.info("[1/5] Retrieving false positives from Elastic")
    fp_domains = elastic.get_false_positives()

    # Populate list with domains which were online during the previous crawl
    logging.info("[2/5] Retrieving online domains from Elastic")
    for online_domain in elastic.get_online_domains():
        if (
            online_domain.domain not in unique_domains
            and online_domain.domain not in fp_domains
        ):
            cur_domain = Domain(online_domain.domain)
            online_domain_dict = online_domain.to_dict()
            for key in domain_attributes:
                try:
                    setattr(cur_domain, key, online_domain_dict[key])
                except Exception:
                    pass

            input_domains.append(cur_domain)
            unique_domains.add(online_domain.domain)

    # Populate list with domains which have been offline for less than 5 days
    logging.info("[3/5] Retrieving offline domains from Elastic")
    for offline_domain in elastic.get_offline_domains():
        if (
            offline_domain.domain not in unique_domains
            and offline_domain.domain not in fp_domains
        ):
            cur_domain = Domain(offline_domain.domain)
            offline_domain_dict = offline_domain.to_dict()
            for key in domain_attributes:
                try:
                    setattr(cur_domain, key, offline_domain_dict[key])
                except Exception:
                    pass

            input_domains.append(cur_domain)
            unique_domains.add(offline_domain.domain)

    # Populate list with new domains that certscanner found in the last hour
    logging.info(
        "[4/5] Retrieving new domains detected by the certificate scanner from Elastic"
    )
    for cert_domain in elastic.get_new_certscanner_domains():
        if cert_domain not in fp_domains and cert_domain not in unique_domains:
            input_domains.append(Domain(cert_domain))
            unique_domains.add(cert_domain)

    # Populate list with new domains reported to URLscan.io in the last hour
    logging.info("[5/5] Retrieving additional domains from URLscan.io")
    if urlscan_domains:
        for urlscan_domain in urlscan.get_domains_from_urlscanio(KIT_FINGERPRINTS):
            if (
                urlscan_domain not in fp_domains
                and urlscan_domain not in unique_domains
            ):
                input_domains.append(Domain(urlscan_domain))
                unique_domains.add(urlscan_domain)

    number_of_input_domains = len(input_domains)
    logging.info(f"{number_of_input_domains} will be analysed this run")
    if number_of_input_domains > 500:
        logging.warning(
            "The number of domains to be analyzed is high, this could cause an overflow of analyses!"
        )

    return input_domains


def crawling_process(domain: Domain) -> Domain:
    """
    Crawl a domain.

    :param domain: domain object
    :return:
    """
    logging.info(f"[{domain.domain}] Analysis started")

    # Set a new timestamp of the current crawl
    domain.crawl_date = datetime.now(timezone.utc)

    # Store previous properties before updating
    previous_state = domain.state
    previous_identified_as = domain.identified_as
    logging.debug(f"[{domain.domain}] was {previous_state} before crawling")
    previous_screenshot_hash = domain.screenshot_hash
    domain.state = "unknown"

    try:
        # 0. Check if websites is already monitored for five days
        if isinstance(domain.first_crawled, str):
            domain.first_crawled = datetime.fromisoformat(domain.first_crawled)
        if (
            domain.crawl_date - domain.first_crawled
        ).days >= MONITORING_TIME and not domain.identified_kits:
            raise exceptions.MonitoringTimeOut(
                f"[{domain.domain}] Website has been monitored for more than {MONITORING_TIME} days, stop monitoring"
            )
        # but, do monitor identified phishing domains for a longer period
        if (
            domain.crawl_date - domain.first_crawled
        ).days >= MONITORING_TIME + 10 and domain.identified_kits:
            raise exceptions.MonitoringTimeOut(
                f"[{domain.domain}] Website has been monitored for more than {MONITORING_TIME + 10} days, stop monitoring"
            )

        # 1. Check if website is online
        domain.state, domain.server_header = utils.check_domain_is_up(domain.domain)
        if not domain.state == "online":
            raise exceptions.StopException(
                f"[{domain.domain}] Website not online, aborting.."
            )
        if "openresty" in domain.server_header:
            raise exceptions.FalsePositiveException(
                f"[{domain.domain}] This website is a parked website full with ads, not phishing. Skipping.."
            )

        # Retrieve DNS nameservers for this domain
        domain.nameservers = utils.get_nameservers(domain.domain)

        # 2. Crawl website
        success, domain, screenshot_file = visual_and_source.browse_to_website(
            domain, VALID_URLS
        )
        if not success:
            # If unsuccessful, skip further analysis
            if not domain.whois_registrar:
                domain = utils.populate_whois(domain)

            if domain.identified_as == "redirected":
                # Try to get the original IP address (before redirection)
                domain.ip = utils.get_redirected_ip(domain.domain)

                # If the browser is redirected, look for kit fingerprints
                # on the base domain instead of the landing url.
                # To prevent dirbusting every hour, check if not same as last time.
                if arguments.dirbust and previous_identified_as != "kit_identified":
                    # Search for phishing kit FP
                    domain_to_crawl = f"https://{domain.domain}/"
                    (
                        domain.dirbust_identified_kits,
                        domain.resolved_urls,
                    ) = dirbust.find_kits_by_dirbust(
                        domain.domain, domain_to_crawl, KIT_FINGERPRINTS
                    )

                    # Cross-reference both dirbust and resource bust results
                    domain.identified_kits = utils.combine_dir_resource_busts(
                        domain.dirbust_identified_kits,
                        domain.resourcebust_identified_kits,
                    )

                    # Search for more panel information if that is known for this/these phishing kit(s)
                    if domain.identified_kits:
                        possible_panel_endpoints = set()
                        for identified_kit in domain.identified_kits:
                            for endpoint in KIT_FINGERPRINTS[identified_kit].get(
                                "panel"
                            ):
                                possible_panel_endpoints.add(endpoint)
                        (
                            domain.panel_login,
                            domain.panel_login_title,
                        ) = utils.search_for_panel_specifics(
                            domain.domain, possible_panel_endpoints
                        )

                    # And reset other fields to prevent insertions with false information
                    domain.doc_title = ""
                    domain.screenshot_hash = "1111111111111111"
                    domain.html_source = ""
                    domain.html_hash = ""

                # Update the domain's identified as field as phishing
                if domain.identified_kits:
                    domain.identified_as = "kit_identified"

                # Raise the RedirectException to stop further analysis
                raise exceptions.RedirectException(
                    f"[{domain.domain}] Redirected to benign website, skipping further analysis"
                )
            # Else, just stop further analysis
            raise exceptions.StopException(
                f"[{domain.domain}] Unsuccessful to complete website profiling, skipping further analysis"
            )
        if (
            "suspended" in domain.doc_title.lower()
            or "not found" in domain.doc_title.lower()
        ):
            domain.state = "offline"
            raise exceptions.StopException(
                f"[{domain.domain}] This domain is suspended or not found, so categorized as offline"
            )

        # Remove domains filled with Google Ads
        for resource in domain.resources:
            if "adsense/domains/caf.js" in resource:
                raise exceptions.FalsePositiveException(
                    f"[{domain.domain}] This website is a parked domain full with ads. Skipping.."
                )

        # Compare the current screenshot hash with the latest screenshot hash
        # and skip further analysis if nothing changed or insert the current
        # screenshot into a separate Elastic index
        if domain.screenshot_hash == previous_screenshot_hash:
            raise exceptions.NothingChangedException(
                f"[{domain.domain}] Nothing changed on the website, skipping further analysis.."
            )
        if screenshot_file:
            file_path = f"{domain.domain}/{domain.screenshot_hash}.png"
            minio_operations.store_object(screenshot_file, file_path, "screenshots")

        # 3. False Positive checks, first filter out WordPress websites
        if fp_detection.determine_word_press(domain):
            raise exceptions.FalsePositiveException(
                f"[{domain.domain}] This website is a WordPress website, not phishing. Skipping.."
            )

        # Afterwards check for default pages, empty pages
        default_page = fp_detection.determine_default_page(
            domain.domain, domain.html_source
        )
        empty_page = fp_detection.determine_empty_page(
            domain.domain, domain.html_source
        )

        # If this is a default page, skip further analysis, but do check for kit files
        if default_page:
            utils.check_for_kits(domain.landing_url, domain.html_source, domain.domain)
            logging.info(f"[{domain.domain}] This seems to be a default website!")
            domain.identified_as = "default"

        # If this is an empty page, mark as empty, but continue analysis
        elif empty_page:
            logging.info(f"[{domain.domain}] This seems to be an empty website!")
            domain.identified_as = "empty"

        # 4. WHOIS enrichment, fills five more fields of the domain object
        if not domain.whois_registrar:
            domain = utils.populate_whois(domain)

        # If empty page, check for fingerprints in the directory index
        if empty_page and "Index of" in domain.doc_title:
            (
                domain.resourcebust_identified_kits,
                domain.resolved_resources,
            ) = index_bust.find_fingerprints_index_page(
                domain.domain, domain.html_source, KIT_FINGERPRINTS
            )

        # 6. Resource bust
        if not default_page and not empty_page:
            (
                domain.resourcebust_identified_kits,
                domain.resolved_resources,
            ) = resbust.find_kits_by_resource_bust(
                domain.domain, domain.resources, KIT_FINGERPRINTS
            )
        # 7. Dirbust
        if arguments.dirbust and not default_page:
            (
                domain.dirbust_identified_kits,
                domain.resolved_urls,
            ) = dirbust.find_kits_by_dirbust(
                domain.domain, domain.landing_url, KIT_FINGERPRINTS
            )

        # Cross-reference both dirbust and resource bust results
        domain.identified_kits = utils.combine_dir_resource_busts(
            domain.dirbust_identified_kits,
            domain.resourcebust_identified_kits,
        )

        # Search for more panel information if that is known for this phishing kit
        if domain.identified_kits:
            possible_panel_endpoints = set()
            for identified_kit in domain.identified_kits:
                for panel_endpoint in KIT_FINGERPRINTS[identified_kit].get("panel", []):
                    possible_panel_endpoints.add(panel_endpoint)
            (
                domain.panel_login,
                domain.panel_login_title,
            ) = utils.search_for_panel_specifics(domain, possible_panel_endpoints)

        # Update the domain's identified as field as phishing
        if domain.identified_kits:
            domain.identified_as = "kit_identified"

        # 8. Send to ELK
        elastic.send_to_elk(domain)

    # Except all kinds of different errors
    except exceptions.StopException as error:
        logging.info(error)
        if not (previous_state == "offline" and domain.state == "offline"):
            elastic.send_to_elk(domain)

    except exceptions.NothingChangedException as error:
        logging.info(error)
        elastic.send_to_elk(domain)

    except exceptions.RedirectException as error:
        logging.info(error)
        elastic.send_to_elk(domain)

    except exceptions.FalsePositiveException as error:
        if not domain.identified_kits:
            domain.identified_as = "false_positive"
            logging.info(error)
        elastic.send_to_elk(domain)

    except exceptions.MonitoringTimeOut as error:
        logging.info(error)

    # Output the complete Traceback if another error occurred
    except Exception as error:
        logging.exception(f"Unknown error encountered: {error}")

    return domain


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="BigPhish crawler, detects phishing kits on a live website"
    )
    parser.add_argument(
        "-no",
        "--disable_checks",
        action="store_true",
        help="Disable active VPN and Elastic connection checks",
    )
    parser.add_argument(
        "-u",
        "--urlscan_domains",
        action="store_true",
        help="Enable the search for domains with hashes on URLscan.io",
    )
    parser.add_argument(
        "-d",
        "--dirbust",
        action="store_true",
        help="Enable detection based on known urls and paths",
    )
    parser.add_argument(
        "-t",
        "--test_run",
        type=str,
        help="Do a test run on a given domain",
    )
    arguments = parser.parse_args()

    # Initialize logging facilities, define logging format first
    if "DEBUG" in environ.get("LOG_LEVEL", "DEBUG").upper():
        logging_format = logging.Formatter(
            fmt="%(module)-20s:%(lineno)-3s [%(asctime)s] %(levelname)-8s%(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    else:
        logging_format = logging.Formatter(
            "%(asctime)s %(levelname)-8s %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )

    # Attach the right handlers and format to the logger
    CH = logging.StreamHandler()
    CH.setFormatter(logging_format)
    logging.getLogger().handlers.clear()
    logging.getLogger().addHandler(CH)
    logging.getLogger().setLevel(level=environ.get("LOG_LEVEL", "DEBUG").upper())
    logging.getLogger("elasticsearch").setLevel(logging.CRITICAL)
    logging.getLogger("elastic_transport").setLevel(logging.ERROR)
    logging.getLogger("mysql").setLevel(logging.CRITICAL)
    logging.getLogger("seleniumwire").setLevel(logging.CRITICAL)

    # Possibility to do a test run
    if arguments.test_run:
        logging.info(f"Doing a test run on {arguments.test_run}")
        KIT_FINGERPRINTS = utils.load_kit_fingerprints()
        domain = utils.Domain(arguments.test_run)
        print(vars(crawling_process(domain)))
        sys.exit()

    # Record the starting time
    start_time = datetime.now()

    # If health checks are disabled (for testing purposes), just start the main function
    if arguments.disable_checks:
        main(arguments)
    else:
        # Otherwise, first check if ELK and VPN are up and running before starting anything
        if utils.health_check():
            # Execute the main function loop
            main(arguments)
            utils.cleanup()

            # Record duration time and report time of next run, than exit
            time_delta = round((datetime.now() - start_time).total_seconds())
            logging.info(
                f"Next run will start at approximately: "
                f"{datetime.now() + timedelta(seconds=RESTART_TIMEOUT - time_delta - 100)}"
            )
            sys.exit()
