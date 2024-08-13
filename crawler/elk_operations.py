"""Functions to communicate with Elasticsearch instance."""

import logging
from datetime import datetime, timedelta
from os import environ
from typing import List, Set, Union

import requests
from domain import Domain
from elasticsearch.client import IndicesClient, IngestClient
from elasticsearch_dsl import Mapping, Search
from elasticsearch_dsl.response import Hit

from elasticsearch import Elasticsearch  # type: ignore

# Retrieve environment variables for ES connection
ES_HOST = environ.get("ES_HOST", "")
ES_USER = environ.get("ES_USER", "")
ES_PASSWORD = environ.get("ES_PASSWORD", "")
ES_INDEX_NAME = "crawler_index"


def initialize_index(
    index_name: str, es_connection, disabled_fields: List[str]
) -> bool:
    """
    Initialize the necessary index with the right mappings.

    :param index_name: name of the index to make
    :param es_connection: current connection object to Elasticsearch
    :param disabled_fields: list of fields that are not enabled
    :return: boolean
    """
    mapping = Mapping()

    # Disable indexing of the html_source and screenshot_file fields
    for field in disabled_fields:
        mapping.field(field, "object", enabled=False)

    # Save mapping to the index
    result = mapping.save(index_name, using=es_connection)

    # Check if the creation was successful and return that
    if result:
        if result.get("acknowledged", False):
            logging.info(f"Index {index_name} created!")
            return True
    logging.error(f"Unable to create {index_name}..")
    return False


def initialize_indexes(es_connection) -> bool:
    """
    Initialize all indices.

    :param es_connection: current connection object to Elasticsearch
    :return: boolean
    """
    # Check if the ES_INDEX_NAME exists
    if es_connection.indices.exists(index=ES_INDEX_NAME):
        index_exists = True
    else:
        logging.info(f"Index {ES_INDEX_NAME} not present, initializing..")
        index_exists = initialize_index(
            ES_INDEX_NAME, es_connection, ["html_source", "whois_source"]
        )

        # Setup the GeoIP pipeline by default
        ingest_client = IngestClient(es_connection)
        ingest_client.put_pipeline(
            id="geoip",
            description="Add GeoIP information",
            processors=[
                {
                    "geoip": {
                        "field": "ip",
                    }
                }
            ],
        )
        indices_client = IndicesClient(es_connection)
        indices_client.put_settings(
            settings={"index.default_pipeline": "geoip"}, index=ES_INDEX_NAME
        )
        logging.info(f"Added GeoIP processor to {ES_INDEX_NAME} successfully!")

    return index_exists


def test_elk() -> bool:
    """
    Test the ELK connection.

    :return: true is successful, false otherwise
    """
    try:
        # Check if all arguments are present
        if not ES_HOST:
            logging.error("No ES_HOST specified, check your configuration")
            return False

        # Try to reach the Elasticsearch instance
        if ES_HOST.startswith("https"):
            url = ES_HOST
        else:
            url = f"http://{ES_HOST}"
        res = requests.get(url, auth=(ES_USER, ES_PASSWORD), verify=False, timeout=5)
        if res.status_code == 200:
            # Connect to Elasticsearch instance
            elastic = create_elastic_client()

            # Fetch some information
            info = elastic.info()

            logging.debug(
                f'Connected to an ELK stack. Cluster name: {info["cluster_name"]}, '
                f'version: {info["version"]["number"]}'
            )

            # Check if the necessary index is present, otherwise create it
            logging.info(f"Checking if index {ES_INDEX_NAME} is initialized")
            return initialize_indexes(elastic)

    except Exception as error:
        logging.error(f"Elasticsearch error: {error}")
    return False


def get_new_certscanner_domains() -> List[str]:
    """
    Retrieve new domains from the certscanner index.

    :return: list of domains
    """
    new_domains = []

    try:
        # Connect to Elasticsearch instance
        elastic = create_elastic_client()

        # Create a search query to get all new (1h) domains from certscanner
        search = (
            Search(index="domain_index")
            .using(elastic)
            .filter("range", date={"gte": "now-1h", "lt": "now"})
            .source(["domain"])
        )

        # Use s.scan() to get all (+10.000) results from Elasticsearch
        for domain in search.scan():
            new_domains.append(domain.domain)

    except Exception as error:
        logging.error(f"Elasticsearch error: {error}")

    logging.debug(
        f"Got {len(new_domains)} new domains to analyze from the domain_index"
    )
    return new_domains


def get_offline_domains(time_ago: str = "5d") -> List[Hit]:
    """
    Retrieve all offline domains from the last 5 days.

    :return: list of domains
    """
    unique_offline_domains = set()
    offline_domains = []
    time_from = f"now-{time_ago}"

    try:
        # Connect to Elasticsearch instance
        elastic = create_elastic_client()

        # Create a search query to get all offline domains in the
        # last five days (5d) from crawler_index
        search = (
            Search(index=ES_INDEX_NAME)
            .using(elastic)
            .filter("range", crawl_date={"gte": time_from, "lt": "now"})
            .filter("match_phrase", state="offline")
            .exclude("terms", field=["screenshot_file", "html_source"])
        )

        # Use s.scan() to get all (+10.000) results from Elasticsearch
        for domain in search.scan():
            if (
                domain.domain not in unique_offline_domains
                and domain.identified_as != "false_positive"
            ):
                offline_domains.append(domain)
                unique_offline_domains.add(domain.domain)

    except Exception as error:
        logging.error(f"Elasticsearch error: {error}")

    logging.debug(
        f"Got {len(offline_domains)} offline domain hits from the {ES_INDEX_NAME}"
    )
    return offline_domains


def fallback_check() -> Union[str, datetime]:
    """
    Check if the crawler has been stopped and misses something.

    :return: the proper timestamp to search from or 'now-1h'
    """
    try:
        elastic = create_elastic_client()

        # Retrieve the latest record inserted into Elasticsearch
        search = Search(index="crawler_index").using(elastic).sort("-crawl_date")
        search = search[0:1]

        # Execute this search query
        res = search.execute()

        # Calculate the time between this date and current utcnow()
        latest_timestamp = datetime.fromisoformat(res.hits[0].crawl_date)
        if (datetime.utcnow() - latest_timestamp).total_seconds() / 60 > 60:
            logging.warning(
                "Latest record is inserted into Elastic longer than 60 minutes ago!"
            )
            new_date_from_field = latest_timestamp - timedelta(hours=1)
            return new_date_from_field

    except Exception as error:
        logging.error(f"Elasticsearch fallback check failed: {error}")

    return "now-1h"


def get_online_domains() -> List[Hit]:
    """
    Retrieve all online domains from the past hour.

    :return: list of domains
    """
    online_domains = []

    try:
        # Connect to Elasticsearch instance
        elastic = create_elastic_client()
        date_from = fallback_check()

        # Create a search query to get all online domains of the last hour from crawler_index
        search = (
            Search(index=ES_INDEX_NAME)
            .using(elastic)
            .filter("range", crawl_date={"gte": date_from, "lt": "now"})
            .exclude("terms", field=["screenshot_file", "html_source"])
        )

        # Use s.scan() to get all (+10.000) results from Elasticsearch
        fp_domains = set()
        retrieved_domains = []
        for domain in search.scan():
            retrieved_domains.append(domain)
            if domain.identified_as == "false_positive":
                fp_domains.add(domain.domain)

        for domain in retrieved_domains:
            if domain.state == "online" and domain.domain not in fp_domains:
                online_domains.append(domain)

    except Exception as error:
        logging.error(f"Elasticsearch error: {error}")

    logging.debug(
        f"Got {len(online_domains)} online domains to analyze from the {ES_INDEX_NAME}"
    )
    return online_domains


def get_false_positives(time_ago: str = "5M") -> Set[str]:
    """
    Retrieve a list of false positives to filter out afterwards.

    :return: set of domain names
    """
    false_positives = set()

    try:
        # Connect to Elasticsearch instance
        elastic = create_elastic_client()
        time_from = f"now-{time_ago}"

        # Create a search query to get all false positives of the last time_ago from crawler_index
        search = (
            Search(index=ES_INDEX_NAME)
            .using(elastic)
            .filter("range", crawl_date={"gte": time_from, "lt": "now"})
            .filter("match_phrase", identified_as="false_positive")
            .source(["domain"])
        )

        # Use s.scan() to get all (+10.000) results from Elasticsearch
        for domain in search.scan():
            false_positives.add(domain.domain)

    except Exception as error:
        logging.error(f"Elasticsearch error: {error}")

    logging.debug(
        f"Got {len(false_positives)} false positives to filter out from the {ES_INDEX_NAME}"
    )
    return false_positives


def send_to_elk(domain: Domain) -> None:
    """
    Insert domain objects into Elasticsearch.

    :param domain: domain object ready to be inserted
    :return:
    """
    # Don't make the HTML source field to large..
    if len(domain.html_source) > 100000:
        domain.html_source = domain.html_source[:95000]

    try:
        # Connect to Elasticsearch instance
        elastic = create_elastic_client()

        # Execute post to Elasticsearch instance with domain
        elastic.index(index=ES_INDEX_NAME, document=vars(domain))
        logging.info(f"[{domain.domain}] Inserted into {ES_INDEX_NAME} successfully")

    except Exception as error:
        logging.error(f"Elasticsearch error: {error}")


def create_elastic_client() -> Elasticsearch:
    """
    Create a new Elastic client connection and return that object.

    :return: ElasticSearch client
    """
    if not ES_HOST:
        logging.error("Could not create Elasticsearch client! ES_HOST is empty!")

    try:
        client = Elasticsearch(f"http://{ES_HOST}", http_auth=(ES_USER, ES_PASSWORD))
    except Exception as error:
        logging.error(f"Could not create Elasticsearch client {error}")

    return client
