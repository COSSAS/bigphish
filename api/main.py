"""Magneto API."""

import json
import logging
from os import environ
from typing import Any, AnyStr, Dict
from uuid import uuid4

import elk_operations as elk
import minio_operations
import utils
from fastapi import FastAPI, HTTPException, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader

# Setup logging
logger = logging.getLogger("")
logger.setLevel(logging.INFO)
logging.getLogger("elasticsearch").setLevel(logging.CRITICAL)
logging.getLogger("elastic_transport").setLevel(logging.ERROR)

# Load the extended authentication token
EXTENDED_AUTHENTICATION_API_KEY = environ.get("API_EXTENDED_AUTHENTICATION_KEY")
API_TOKENS = utils.load_api_tokens()

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def get_basic_api_key(
    api_key_header: str = Security(api_key_header),
) -> str:
    """Enable X-API-KEY header security."""
    if (
        api_key_header == EXTENDED_AUTHENTICATION_API_KEY
        or api_key_header in API_TOKENS
    ):
        return api_key_header
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing X-API-Key",
    )


def get_extended_authentication_key(
    api_key_header: str = Security(api_key_header),
) -> str:
    """Enable X-API-KEY header security with extended authentication."""
    if api_key_header == EXTENDED_AUTHENTICATION_API_KEY:
        return api_key_header
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No API access allowed for this endpoint",
    )


app = FastAPI(
    title="BigPhish API",
    description="API for BigPhish",
    version="1.0.0",
)

origins = (
    "http://localhost:3000",
    "http://localhost:8000",
)

app.add_middleware(
    CORSMiddleware, allow_origins=origins, allow_methods=["*"], allow_headers=["*"]
)


@app.get("/api/v1/status", tags=["General"], response_model=dict)
def get_bigphish_status(api_key: str = Security(get_basic_api_key)):
    """Get the current status of the BigPhish API."""
    return {
        "BigPhish API": app.version,
        "Elasticsearch": elk.test_elk()[1],
        "Minio": "Connected" if minio_operations.test_minio() else "Not connected",
    }


@app.get("/api/v1/active_domains", tags=["Domains"])
def get_active_phishing_domains(api_key: str = Security(get_basic_api_key)):
    """Retrieve online and identified phishing domain URLs."""
    active_domains = list(elk.get_active_domains(only_domains=True))
    return {"domains": active_domains, "length": len(active_domains)}


@app.get("/api/v1/active_domains_urls", tags=["Domains"])
def get_active_phishing_domains_urls(api_key: str = Security(get_basic_api_key)):
    """Retrieve online and identified phishing domain URLs and resolved URLs."""
    active_domains = []
    for hit in elk.get_active_domains():
        active_domains.append(
            {"domain": hit["domain"], "resolved_urls": [*hit["resolved_urls"]]}
        )
    return {"domains": active_domains, "length": len(active_domains)}


@app.get("/api/v1/active_domains_summary", tags=["Domains"])
def get_active_phishing_domains_summary(
    api_key: str = Security(get_extended_authentication_key),
):
    """Retrieve the online and identified phishing domains and screenshots."""
    active_domains = []
    for hit in elk.get_active_domains():
        if hit["screenshot_hash"] != "1111111111111111":
            screenshot_file = minio_operations.retrieve_screenshot(
                hit["domain"], hit["screenshot_hash"]
            )
        else:
            screenshot_file = ""
        location_details = elk.get_domain_geoip(hit["domain"])
        active_domains.append(
            {
                "domain_name": hit["domain"],
                "identified_kits": hit["identified_kits"][0],
                "screenshot_path": screenshot_file,
                "location": location_details,
            }
        )
    return {
        "domains": active_domains,
    }


@app.post("/api/v1/new_domain", tags=["Domains"])
def submit_new_domain(
    domain: str, api_key: str = Security(get_extended_authentication_key)
):
    """Submit a new domain to the monitoring."""
    domain_object = utils.Domain(domain)
    domain_object.state = "online"
    elk.send_to_elk(domain_object)
    return {"status": "success"}


@app.post("/api/v1/false_positive", tags=["Domains"])
def submit_false_positive(
    domain: str, api_key: str = Security(get_extended_authentication_key)
):
    """Label a domain as a false positive."""
    domain_object = utils.Domain(domain)
    domain_object.state = "online"
    domain_object.identified_as = "false_positive"
    elk.send_to_elk(domain_object)
    return {"status": "success"}


@app.get("/api/v1/domain_details", tags=["Domains"])
def retrieve_domain_details(
    domain: str, api_key: str = Security(get_extended_authentication_key)
):
    """Retrieve all details of a given domain."""
    # Retrieve all information from different indices
    domain_index_entry = elk.get_domain_index_entry(domain)
    crawler_entries = elk.get_crawler_domain_entries(domain)
    screenshot_entries = minio_operations.retrieve_all_screenshots(domain)

    # Retrieve Google Safe Browsing status
    gsb_status = utils.get_gsb_status(domain)

    # Retrieve the active domains to check if online
    active_domains = elk.get_active_domains(only_domains=True)

    # Retrieve the latest GeoIP information
    location_details = elk.get_domain_geoip(domain)

    # Combine all this information into one JSON
    if crawler_entries:
        return {
            "status": "success",
            "entries": utils.process_domain_entries(
                domain,
                crawler_entries,
                domain_index_entry,
                screenshot_entries,
                active_domains,
                gsb_status,
                location_details,
            ),
        }


@app.get("/api/v1/fp_details", tags=["Phishing kits"])
def retrieve_fp_details(api_key: str = Security(get_extended_authentication_key)):
    """Get the contents of phishing_kits_fingerprints file."""
    return {"status": "success", "kit_fingerprints": utils.load_kit_fingerprints()}


@app.post("/api/v1/fp_details", tags=["Phishing kits"])
def change_fp_details(
    kit_fingerprints: Dict[Any, AnyStr],
    api_key: str = Security(get_extended_authentication_key),
):
    """Modify the contents of phishing_kits_fingerprints file."""
    # Check if the file is well formatted, if length is above 200, something must have gone wrong
    if len(kit_fingerprints.get("kit_fingerprints", [])) > 200:
        raise Exception("JSON file malformatted, not updating fingerprints!")

    # Check if all fingerprints are valid,
    [json.dumps(kit) for kit in kit_fingerprints.get("kit_fingerprints", [])]

    utils.save_fingerprints(kit_fingerprints.get("kit_fingerprints"))  # type: ignore[union-attr]
    return {"status": "success"}


@app.post("/api/v1/create_access_token", tags=["Management"])
def create_access_token(
    organisation: str, api_key: str = Security(get_extended_authentication_key)
):
    """Create a new access token for a given organisation."""
    token = uuid4().hex
    utils.insert_new_token(token, organisation)
    return {"status": "success", "token": token}


@app.get("/api/v1/search", tags=["Search"])
def retrieve_search_results(
    field: str,
    query: str,
    date_from: str,
    date_to: str,
    only_identified: bool = False,
    api_key: str = Security(get_extended_authentication_key),
):
    """Retrieve all domains for a search query."""
    # Retrieve the active domains to check if online
    active_domains = elk.get_active_domains(
        only_identified=only_identified, only_domains=True
    )

    # Search within Elastic for these input parameters
    output = []
    for domain, first_crawled in elk.search_property(
        field=field,
        query=query,
        date_from=date_from,
        date_to=date_to,
        only_identified=only_identified,
    ):
        # And check if online or offline
        output.append(
            {
                "domain": domain,
                "state": "online" if domain in active_domains else "offline",
                "first_crawled": first_crawled,
            }
        )
    return {
        "status": "success",
        "entries": sorted(output, key=lambda x: x["first_crawled"], reverse=True),
    }


@app.get("/api/v1/trends", tags=["Trends"])
def retrieve_trends_statistics(
    date_from: str,
    date_to: str,
    specific_kit: str | None = None,
    api_key: str = Security(get_extended_authentication_key),
):
    """Retrieve all domains for a search query."""
    # First retrieve the false positives
    false_positives = elk.get_false_positives(date_from, date_to)

    # Then query Elastic for all domains in this time window and kit selection
    elastic_results_raw = elk.retrieve_trends_aggregation(
        false_positives, date_from, date_to, specific_kit
    )
    # Process that and return the output
    output = utils.generate_trends_statistics(
        elastic_results_raw,
        date_from,
        date_to,
    )
    return {"status": "success", "entries": output}
