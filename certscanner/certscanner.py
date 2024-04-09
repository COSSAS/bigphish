"""Main tool to get and analyze the certstream."""

import argparse
import logging
from os import environ
from time import sleep

import certstream_client as cs
import elk_operations as elk
from detectors import detect_domain
from tld import exceptions, update_tld_names

# Set certstream server to use
SERVER = "ws://certstream:8080/domains-only"


# Callback function for certstream
def process_callback(message, context):
    """
    Process the callback from the firehose of certs, starts the analysis part.

    :param message:
    :param context:
    :return:
    """
    # For all domains listed in the certificate;
    for domain_name in message.get("data"):
        # Analyze the domain name
        domain = detect_domain(domain_name)

        # Detect and log if above threshold
        if domain.score >= args.threshold:
            domain.no_of_domains = len(message.get("data"))
            logging.debug(f"Detection: {domain.domain}")

            # Insert domain and certificate into Elasticsearch
            if not args.disable_elasticsearch:
                if not elk.check_if_already_inserted(domain.domain):
                    elk.insert_domain_into_elastic(domain)


def start() -> None:
    """Start the actual certificate scanner, by opening the certstream connection."""
    logging.info("Initializing certificate scanner...")
    logging.info(f"  Score threshold: {args.threshold}")
    logging.info(f"  Elasticsearch disabled: {args.disable_elasticsearch}")

    cs.listen_for_events(process_callback, url=SERVER)


def health_check() -> bool:
    """
    Check if Elasticsearch is already up, tries 20 times before returning false.

    :return: true if up and running, false otherwise
    """
    for _ in range(0, 20):
        if elk.test_elastic():
            logging.info("Elasticsearch connection is successfully established")
            return True

        logging.warning(
            "No Elasticsearch connection available, retrying in 5 seconds..."
        )
        sleep(5)
    logging.error("No Elasticsearch connection available, stopping!")
    return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="CertScanner, execute python3 domain_detector.py -h for more information!"
    )
    parser.add_argument(
        "-t",
        "--threshold",
        type=int,
        default=environ.get("CERTSCANNER_THRESHOLD", 110),
        choices=range(30, 500),
        help="specify the suspicious threshold",
    )
    parser.add_argument(
        "-d",
        "--debug",
        default=False,
        action="store_true",
        help="run in debug mode, will show detailed messages",
    )
    parser.add_argument(
        "-e",
        "--disable_elasticsearch",
        default=False,
        action="store_true",
        help="set this flag to disable the Elasticsearch connection",
    )
    args = parser.parse_args()

    # Initiate basic logging facility for cert scanner
    if args.debug:
        logging_format = logging.Formatter(
            fmt="%(module)-20s:%(lineno)-3s [%(asctime)s] %(levelname)-8s%(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    else:
        logging_format = logging.Formatter(
            "%(asctime)s %(levelname)-8s %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )

    # Setup logging
    CH = logging.StreamHandler()
    CH.setFormatter(logging_format)
    logging.getLogger().handlers.clear()
    logging.getLogger().addHandler(CH)
    logging.getLogger().setLevel(logging.DEBUG if args.debug else logging.INFO)
    logging.getLogger("elasticsearch").setLevel(logging.CRITICAL)
    logging.getLogger("elastic_transport").setLevel(logging.CRITICAL)
    logging.getLogger("websocket").setLevel(logging.CRITICAL)
    logging.getLogger("tld").setLevel(logging.CRITICAL)

    # Update the TLD module to include also the most recent TLDs
    logging.info("Updating TLD information...")
    try:
        update_tld_names()
        logging.info("Successfully updated TLD information!")
    except exceptions.TldIOError:
        logging.warning("Unable to update TLDs (no Internet connection?)")

    # Start the program, if Elasticsearch connection is disabled, without the health check
    if not args.disable_elasticsearch:
        if health_check():
            start()
    else:
        start()
