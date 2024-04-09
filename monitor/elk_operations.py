"""Elasticsarch connection and interactions."""

import logging
from datetime import datetime
from os import environ
from typing import Set

from elasticsearch_dsl import A, Search

from elasticsearch import Elasticsearch

ES_HOST = str(environ.get("ES_HOST"))
ES_USER = str(environ.get("ES_USER"))
ES_PASSWORD = str(environ.get("ES_PASSWORD"))


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


def retrieve_kit_installed_date(domain: str) -> datetime:
    """Retrieve the kit installed date for a domain.

    Args:
        domain (str): domain name

    Returns:
        datetime: timestamp at which the kit is installed
    """
    elastic = create_elastic_client()

    search = (
        Search(index="crawler_index")
        .using(elastic)
        .filter("range", crawl_date={"gte": "now-1M", "lt": "now"})
        .filter("match_phrase", domain=domain)
        .filter("exists", field="identified_kits")
    )

    search.aggs.bucket("date_kit_installed", A("min", field="crawl_date"))
    response = search.execute()

    timestamp = datetime.fromtimestamp(
        response.aggregations["date_kit_installed"].value / 1000.0
    )

    return timestamp


def get_active_domains(
    sync_interval: int, country_filter: str | None = None
) -> Set[str]:
    """Retrieve all active domains from the past SYNC_INTERVAL timeframe.

    Args:
        country_filter (str): 2 character ISO country code
        sync_interval (int): search timeframe in minutes

    Returns:
        set[str]: set of domains
    """
    # Connect to Elasticsearch instance
    elastic = create_elastic_client()

    # Create a search query to get all online domains of the last hour from crawler_index
    search = (
        Search(index="crawler_index")
        .using(elastic)
        .filter("range", crawl_date={"gte": f"now-{sync_interval}m", "lt": "now"})
        .filter("match_phrase", state="online")
        .filter("exists", field="identified_kits")
        .source(["domain", "geoip.country_iso_code"])
    )

    # Loop through all active domains
    unique_domains = set()
    for hit in search.scan():
        # And filter the ones hosted in a specific country
        if hit["geoip"]["country_iso_code"] == country_filter:
            unique_domains.add(hit["domain"])

    return unique_domains
