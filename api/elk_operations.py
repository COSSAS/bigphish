"""Connectivity functions to communicate with Elasticsearch."""

import logging
from os import environ
from typing import Any, Dict, List, Set, Tuple, Union

from elasticsearch_dsl import Search
from elasticsearch_dsl.response import Hit
# Retrieve environment variables for ES connection
from utils import Domain

from elasticsearch import Elasticsearch  # type: ignore

ES_HOST = environ.get("ES_HOST")
ES_USER = environ.get("ES_USER")
ES_PASSWORD = environ.get("ES_PASSWORD")
ES_INDEX_NAME = "crawler_index"


def test_elk() -> Tuple[bool, str]:
    """
    Test the ELK connection.

    :return: true is successful, false otherwise
    """
    try:
        # Connect to Elasticsearch instance
        es_connection = create_elastic_client()

        # Fetch some information
        info = es_connection.info()

        logging.info(
            f'Connected to an ELK stack. Cluster name: {info["cluster_name"]}, '
            f'version: {info["version"]["number"]}'
        )
        return True, f"{info['cluster_name']} {info['version']['number']}"
    except Exception as error:
        return False, f"Connection error to host {ES_HOST}, {error}"


def get_active_domains(
    only_identified: bool = True, only_domains: bool = False
) -> Union[Set[str], List[Hit]]:
    """
    Retrieve all active domains from the past hour.

    :param only_identified:
    :param only_domains:
    :return:
    """
    online_domains = []

    # Connect to Elasticsearch instance
    elastic = create_elastic_client()

    # Create a search query to get all online domains of the last hour from crawler_index
    search = (
        Search(index=ES_INDEX_NAME)
        .using(elastic)
        .filter("range", crawl_date={"gte": "now-80m", "lt": "now"})
        .filter("match_phrase", state="online")
        .source(["domain", "screenshot_hash", "resolved_urls", "identified_kits"])
    )

    if only_identified:
        search = search.filter("exists", field="identified_kits")

    # Use s.scan() to get all results from Elasticsearch, make sure that the list is unique
    unique_domains = set()
    for hit in search.scan():
        if hit["domain"] not in unique_domains:
            unique_domains.add(hit["domain"])
            online_domains.append(hit)

    # If only the domain list is requested, return that set of unique domains
    if only_domains:
        return unique_domains

    return online_domains


def send_to_elk(domain: Domain):
    """
    Insert domain objects into ElasticSearch.

    :param domain: domain object ready to be inserted
    :return:
    """
    # Connect to Elasticsearch instance
    elastic = create_elastic_client()

    # Execute post to Elasticsearch instance with domain
    elastic.index(index=ES_INDEX_NAME, document=vars(domain))
    logging.debug(f"Inserted {domain.domain} into crawler_index")


def get_crawler_domain_entries(domain: str) -> List[Dict[Any, Any]]:
    """
    Retrieve all entries from crawler given a domain.

    :return: list of domains
    """
    entries = []

    # Connect to Elasticsearch instance
    elastic = create_elastic_client()

    # Create a search query to get all online domains of the last hour from crawler_index
    search = (
        Search(index=ES_INDEX_NAME)
        .using(elastic)
        .filter("match_phrase", **{"domain.keyword": domain})
        .sort("crawl_date")
    )

    # Use s.scan() to get all results from Elasticsearch
    for hit in search.scan():
        entries.append(hit.to_dict())

    return entries


def get_domain_geoip(domain_name: str) -> Dict[str, str]:
    """Get the GeoIP properties for a given domain.

    Args:
        domain (str): domain name

    Returns:
        dict: city, country, code
    """
    # Connect to Elasticsearch instance
    elastic = create_elastic_client()

    # Search for the latest GeoIP information
    search = (
        Search(index=ES_INDEX_NAME)
        .using(elastic)
        .filter("match_phrase", domain=domain_name)
        .source(["geoip"])[1]
    )

    result = search.sort("crawl_date").execute()
    if result:
        return result[0].to_dict().get("geoip", {})
    return {}


def search_property(
    field: str,
    query: str,
    date_from: str = "now-10y",
    date_to: str = "now",
    only_identified: bool = False,
) -> Set[Tuple[str, str]]:
    """
    Search for a given property in the crawler index.

    :param only_identified: include only identified phishing domains
    :param field: field to search on
    :param query: input query
    :param date_from: timestamp to start searching from
    :param date_to: timestamp to end searching
    :return: list of unique domains found
    """
    entries = set()
    unique_entries = set()
    context = "match_phrase"

    # Connect to Elasticsearch instance
    elastic = create_elastic_client()

    # Use a different search context for domain name search
    if field == "domain":
        search = Search().using(elastic).index(ES_INDEX_NAME)
        search = search.filter("match", domain=query).filter(
            "range", crawl_date={"gte": date_from, "lt": date_to}
        )

    # Create a base search with the given field, query and date range
    search = (
        Search(index=ES_INDEX_NAME)
        .using(elastic)
        .query(context, **{field: query})
        .filter("range", crawl_date={"gte": date_from, "lt": date_to})
        .source(["domain", "identified_kits", "crawl_date", "first_crawled"])
    )

    # When only identified phishing domains must be included, add an additional filter
    if only_identified:
        search = search.filter("exists", field="identified_kits")

    # Sort all entries on crawl_date
    search = search.sort("crawl_date")

    # Use s.scan() to get all results from Elasticsearch
    for hit in search.scan():
        if hit["domain"] not in unique_entries:
            entries.add((hit["domain"], hit["first_crawled"]))
            unique_entries.add(hit["domain"])

    return entries


def get_false_positives(date_from: str = "now-1M", date_to: str = "now") -> Set[str]:
    """
    Retrieve all false positives from ELK.

    :param date_from: date from (YYYY-DD-MM)
    :param date_to: date to (YYYY-DD-MM)
    :return: list of false positives
    """
    entries = set()

    # Connect to Elasticsearch instance
    elastic = create_elastic_client()

    # Create a search query to get
    search = (
        Search(index=ES_INDEX_NAME)
        .using(elastic)
        .filter("match_phrase", identified_as="false_positive")
        .filter("exists", field="identified_kits")
        .filter("range", crawl_date={"gte": date_from, "lt": date_to})
        .source(["domain"])
    )

    # Use s.scan() to get all results from Elasticsearch
    for hit in search.scan():
        entries.add(hit["domain"])

    return entries


def get_domain_index_entry(domain: str) -> Dict[Any, Any]:
    """
    Retrieve the domain_index entry for a given domain.

    :return: list of domains
    """
    # Connect to Elasticsearch instance
    elastic = create_elastic_client()

    # Create a search query to get all online domains of the last hour from domain_index
    search = (
        Search(index="domain_index")
        .using(elastic)
        .filter("match_phrase", domain=domain)
    )

    # Use s.scan() to get all results from Elasticsearch
    for hit in search.scan():
        return hit.to_dict()

    return {}


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


def retrieve_trends_aggregation(
    false_positives,
    date_from: str = "now-1M",
    date_to: str = "now",
    specific_kit: Any = None,
) -> List[Dict[Any, Any]]:
    """
    Retrieve the kits active per day.

    :param specific_kit: filter on a specific kit or include all
    :param date_from: date from (YYYY-DD-MM)
    :param date_to: date to (YYYY-DD-MM)
    :return:
    """
    # Connect to Elasticsearch instance
    elastic = create_elastic_client()

    # Convert the false positives to a valid Elastic query
    fp_list = []
    for fp in false_positives:
        fp_list.append({"match_phrase": {"identified_as": f"{fp}"}})

    # Filter query
    filter_query = [
        {"exists": {"field": "identified_kits"}},
        {"match": {"state": "online"}},
    ]

    # Add additional match criterium when searching for a specific kit
    if specific_kit:
        filter_query.append({"match_phrase": {"identified_kits": f"{specific_kit}"}})

    # Create a search query to get
    response = elastic.search(
        index=ES_INDEX_NAME,
        aggs={
            "kit_totals": {
                "terms": {
                    "field": "identified_kits.keyword",
                    "order": {"1": "desc"},
                    "size": 9,
                },
                "aggs": {"1": {"cardinality": {"field": "domain.keyword"}}},
            },
            "totals_per_day": {
                "date_histogram": {
                    "field": "crawl_date",
                    "calendar_interval": "1d",
                    "time_zone": "Europe/Amsterdam",
                },
                "aggs": {"1": {"cardinality": {"field": "domain.keyword"}}},
            },
            "kits_per_day": {
                "terms": {
                    "field": "identified_kits.keyword",
                    "order": {"2": "desc"},
                    "size": 9,
                },
                "aggs": {
                    "1": {
                        "date_histogram": {
                            "field": "crawl_date",
                            "fixed_interval": "1d",
                            "time_zone": "Europe/Amsterdam",
                        },
                        "aggs": {
                            "unique_domains": {
                                "cardinality": {"field": "domain.keyword"}
                            }
                        },
                    },
                    "2": {"cardinality": {"field": "domain.keyword"}},
                },
            },
            "all_domains": {
                "terms": {
                    "field": "domain.keyword",
                    "order": {"1": "desc"},
                    "size": 1000,
                },
                "aggs": {
                    "1": {"cardinality": {"field": "domain.keyword"}},
                    "2": {"max": {"field": "first_crawled"}},
                    "3": {"min": {"field": "crawl_date"}},
                    "4": {"max": {"field": "crawl_date"}},
                },
            },
        },
        size=0,
        query={
            "bool": {
                "must": [],
                "filter": [
                    {
                        "bool": {
                            "should": filter_query,
                            "minimum_should_match": len(filter_query),
                        }
                    },
                    {
                        "range": {
                            "crawl_date": {
                                "format": "strict_date_optional_time",
                                "gte": f"{date_from}",
                                "lte": f"{date_to}",
                            }
                        }
                    },
                ],
                "should": [],
                "must_not": fp_list,
            }
        },
    )

    return response["aggregations"]
