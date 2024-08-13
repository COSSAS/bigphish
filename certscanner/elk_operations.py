"""Elasticsearch functionalities."""

import hashlib
import logging
from datetime import datetime, timezone
from os import environ
from typing import Any, Dict, Set

import requests
from elasticsearch_dsl import Document
from utils import Domain

from elasticsearch import Elasticsearch, NotFoundError  # type: ignore

# Retrieve environment variables for ES connection
ES_HOST = environ.get("ES_HOST", "")
ES_USER = environ.get("ES_USER", "")
ES_PASSWORD = environ.get("ES_PASSWORD", "")
ES_INDEX = "domain_index"


def fix_set(field: Set[str]) -> str:
    """
    Prepare a set field for ES insertion.

    :param field: list of elements
    :return: a string filled with the elements of a set
    """
    if len(field) > 1:
        return ",".join(field)
    if len(field) == 1:
        return "".join(field)
    return ""


def prepare_domain(domain: Domain) -> Domain:
    """
    Prepare set fields for insertion.

    :param domain: domain object containing these sets
    :return: domain object with prepared fields
    """
    domain.suspicious_keywords = fix_set(domain.suspicious_keywords)
    domain.possible_company = fix_set(domain.possible_company)
    domain.company = fix_set(domain.company)
    domain.free_ca = domain.free_ca.replace("'", "")

    # Remove www. at the start of the URL
    if domain.domain.startswith("www."):
        domain.domain = domain.domain[4:]

    return domain


def test_elastic() -> bool:
    """
    Test the connection to Elasticsearch.

    :return: true is successful, false otherwise
    """
    try:
        # Try to reach the Elasticsearch instance
        if ES_HOST:
            if ES_HOST.startswith("https"):
                url = ES_HOST
            else:
                url = f"http://{ES_HOST}"
            res = requests.get(url, auth=(ES_USER, ES_PASSWORD), verify=False)
            if res.status_code == 200:
                # Connect to Elasticsearch instance
                es_connection = create_elastic_client()

                # Fetch some information
                info = es_connection.info()

                logging.info(
                    f'Connected to Elasticsearch. Cluster name: {info["cluster_name"]}, '
                    f'version: {info["version"]["number"]}'
                )
                return True
            return False
        logging.error(
            "No Elasticsearch credentials specified, run with -e to disable ES connections"
        )
        return False
    except Exception as error:
        logging.error(f"Elasticsearch error: {error}")
        return False


def check_if_already_inserted(domain_name: str, days_ago: int = 14) -> bool:
    """
    Check if a given domain is already in Elasticsearch.

    :param domain_name: domain object to be checked
    :param days_ago: default is 14 days ago
    :return:
    """
    # Connect to Elasticsearch instance
    es_connection = create_elastic_client()

    # Recreate the document_id to check for in the index
    document_id = hashlib.sha1(domain_name.encode("UTF-8")).hexdigest()

    # Get this domain in Elasticsearch
    try:
        document = Document.get(
            id=document_id, index=ES_INDEX, using=es_connection
        ).to_dict()  # type: ignore
        document_date = datetime.fromisoformat(document["date"])
        if (document_date - datetime.now(timezone.utc)).days < days_ago:
            return True

    except NotFoundError:
        logging.debug(f"{domain_name} is not in index.")

    return False


def insert_domain_into_elastic(domain: Domain) -> None:
    """
    Insert a domain into Elasticsearch.

    :param domain: domain object to be inserted
    :return:
    """
    # Connect to Elasticsearch instance
    es_connection = create_elastic_client()

    # Execute post to Elasticsearch instance with domain
    try:
        # Prepare domain
        domain_to_insert = prepare_domain(domain)
        # Set a unique hash of the domain, will be replaced if domain is seen again
        document_id = hashlib.sha1(domain_to_insert.domain.encode("UTF-8")).hexdigest()
        # Push to Elasticsearch
        es_connection.index(
            index=ES_INDEX,
            document=vars(domain_to_insert),
            id=document_id,
        )
        logging.info(f"Inserted {domain.domain} into domain_index")

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
