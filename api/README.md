# BigPhish API

The API is designed to allow for easy interaction with the Elasticsearch indices and handle data requests originating from the front-end application. 
It is based on FastAPI and requires no customization.

## Installation

For this module to run, you'll need:

- Python 3.11 or higher and pip
- A working Internet connection

To install the necessary dependencies of this project, just execute

```
pip3 install -r requirements.txt
```

Or just use the [Dockerfile](Dockerfile) to deploy it through Docker.

## Usage

To deploy the API, simply execute `python main.py`. 
Serving it through `uvicorn` is recommended, as is done in the Dockerfile.

The `ES_PASSWORD` and `ES_USER` variables are passed as environment variables due to the dockerized environment of BigPhish. 
Replace these variables manually in `elk_operations.py` to configure them yourself outside of Docker.

The `MINIO_HOST`, `MINIO_ROOT_USER`, and `MINIO_ROOT_PASSWORD` variables are passed as environment variables due to the dockerized environment of BigPhish. 
Replace these variables manually in `minio_operations.py` to configure them yourself outside of Docker.

The environment variable `GSB_API_KEY` is used to request the current Google SafeBrowsing status of a given domain. 
Request an API key [here](https://developers.google.com/safe-browsing/v4/get-started) and place it in the `.env` file to make it work.

## API Functionalities
As the BigPhish API is built upon FastAPI, Swagger documentation can be found at `http://localhost:5000/docs`, as well as a full specification at `http://localhost:5000/openapi.json` as soon as the API is deployed.
Access to the API is secured by using an `X-API-Key` header, which should be present in every request.
Two types of API keys are allowed to access the API, the `API_EXTENDED_AUTHENTICATION_KEY` and regular API keys. 
The `API_EXTENDED_AUTHENTICATION_KEY` is set as an environment variable, is used by the front-end application and is therefore allowed to access all API endpoints.
Other API keys can be made using the `/api/v1/create_access_token` endpoint or specified in the `/config/api_tokens.json` file.
All parameters are passed as query parameters in the URL. 

#### General
**`GET /api/v1/status`**
Get the current status of the BigPhish API. 
Returns a JSON with API, Elasticsearch and Minio status information.

#### Domains

**`GET /api/v1/active_domains`**
Retrieve a list of active domains. Returns a JSON including a list of all domains that are currently active.

**`GET /api/v1/active_domains_urls`**
Retrieve a list of active domains. Returns a JSON including a list of all domains that are currently active and the resolved URLs containing phishing kit fingerprints.

**`GET /api/v1/active_domains_summary`**
Retrieve a list of active domains. Returns a JSON including a list of all domains that are currently active, the names of the identified kits, a screenshot of the home page and the geolocation of the domain.

**`POST /api/v1/new_domain`**
Submit a new domain to the monitoring

**`POST /api/v1/false_positive`**
Mark a domains as a false positive

**`GET /api/v1/domain_details`**
Retrieve Domain Details

#### Phishing kits

**`GET /api/v1/fp_details`**
Retrieve all phishing kit fingerprints

**`POST /api/v1/fp_details`**
Change phishing kit fingerprints

#### Management

**`POST /api/v1/create_access_token`**
Create a new API access token

#### Search

**`GET /api/v1/search`**
Retrieve domains based on a search query

#### Trends

**`GET /api/v1/trends`**
Retrieve trends statistics for the trends page in the front-end

## Tests
Some very limited tests are included and can be evaluated by executing:

```
python -m pytest test_api.py 
```