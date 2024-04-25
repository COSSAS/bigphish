<div align="center">
<a href="https://gitlab.com/cossas/bigphish/-/tree/master"><img src="bigphish-logo.jpg"/>


# BigPhish


[![https://cossas-project.org/portfolio/SOARCA/](https://img.shields.io/badge/website-cossas--project.org-orange)](https://cossas-project.org/portfolio/bigphish/)
[![pipeline status](https://gitlab.com/cossas/bigphish/badges/main/pipeline.svg)](https://gitlab.com/cossas/bigphish/badges/-/commits/main)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Latest Release](https://gitlab.com/cossas/bigphish/-/badges/release.svg)](https://gitlab.com/cossas/bigphish/-/releases)
</div></a>

<hr style="border:2px solid gray"> </hr>
<div align="center">
An all-in-one solution to identify and monitor phishing kit deployment
</div>
<hr style="border:2px solid gray"> </hr>

_All COSSAS projects are hosted on [GitLab](https://gitlab.com/cossas/bigphish/) with a push mirror to GitHub. For issues/contributions check [CONTRIBUTING.md](CONTRIBUTING.md)_ 

## What is it?
BigPhish is an application developed for Internet researchers and law enforcement professionals to study the deployment of phishing kits in the wild. 
This software product originates from a [2021 USENIX paper](https://www.usenix.org/conference/usenixsecurity21/presentation/bijmans), which proposed a method to discover new phishing domains by leveraging Certificate Transparency (CT) logs. 
By continuously monitoring these logs and crawling potential phishing domains, it can identify and monitor domains that have been setup up with a phishing kit. 
Phishing kits are identified by searching for fingerprints, which are unique file paths associated with those kits.
BigPhish offers an all-in-one solution for monitoring CT logs, crawling domains, storing them in Elasticsearch and a Web application to interact with the results.

### System architecture

![System architecture](architecture.png)

BigPhish consists of 10 modules, some off-the-shelf and some custom build. 
Each module functions within its own Docker container:

1. **Certscanner** detects potential phishing domains from a stream of TLS certificates. Read more about this module in the respective [README](certscanner/README.md).
2. **Crawler** automatically visits the potential phishing domains, analyzes them, and tries to identify the used phishing kit. Read more about this module in the respective [README](crawler/README.md).
3. **Elasticsearch** index storage to store all gathered information.
4. **Kibana** for easy interaction with Elasticsearch.
5. **VPN** routes the requests from the crawler through a VPN connection. Read more about this module in the respective [README](vpn/README.md).
6. **API** to allow for easy and secure access to the phishing data. Read more about this module in the respective [README](api/README.md).
7. **NodeJS** serves as a front-end Web application to interact nicely with the data.
8. **NGINX** serves a bunkerized NGINX container located in front of the API to secure Internet-facing connections. Read more about this module on their [Github](https://github.com/bunkerity/bunkerweb).
9. **MinIO** object storage to store objects like screenshots and downloaded phishing kits.
10. **Monitor** service that monitors the phishing domains and sends out notifications about new domains.

## Installation

To run BigPhish, you'll need [Docker](https://docs.docker.com/get-docker/) including [Docker-compose](https://docs.docker.com/compose/) on a powerful server.
We recommend at least 4 CPUs and 8GB of RAM for smooth operations. 
Also, make sure to have at least 500GB of disk storage space available, as the data collection can become large.

With your hardware ready, first clone this repository by executing:

```
git clone git@gitlab.com:cossas/bigphish.git
```

Create a `.env` file that stores all the credentials and parameters as environment variables within the Docker containers.
An example is supplied in the `.env-example` file.
The most convenient way is to copy that file and customize it afterward.
This table explains all the environment variables.

| **Variable**   	| **Explanation**  	| **Default**  	|
|---	|---	|---	|
| `TZ`  	| Time zone for all containers.  	|  `Europe/Amsterdam`	|
| `CERTSCANNER_THRESHOLD` 	| The threshold score [0-500] for a domain to be marked as potentially malicious 	| `120`  	| 
| `CRAWLER_RELATED_KIT_RATIO`  	| The percentage of a phishing kit fingerprint that has be to resolved to be marked as a hit  	| `0.2` 	|
| `CRAWLER_RESTART_TIMEOUT`  	| Amount of seconds before a new run of the crawler starts  	| `3600`  	|
| `CRAWLER_MONITORING_TIME`  	| Amount of days that the crawler keeps monitoring a domain 	| `5`  	|
| `VPN_USER` 	| Email or username for the used VPN provider   	|   	|
| `VPN_PASS`  	| Password for the used VPN provider      	|   	|
| `VPN_ASN`  	| The ASN belonging to the VPN provider. This is used to check if a succesful connection through the VPN provider is made  	|   	|
| `NODE_VERSION`  	| Version of Node to run the front-end application   	| `18.5.0`  	|
| `ES_VERSION`  	| Version of Elasticsearch to be used  	|  `7.16.3` 	|
| `ES_USER`  	| Username for connections with Elasticsearch  	| `elastic`  	|
| `ES_PASSWORD`  	| Password for connections with Elasticsearch    	|   	|
| `ES_HOST` 	| Location of Elasticsearch  	| `elasticsearch:9200`  	|
| `XPACK_REPORTING_KEY`  	| Random key of 32 characters to be used by XPACK within Elasticsearch  	|   	|
| `API_EXTENDED_AUTHENTICATION_KEY`  	| The API key used by the front-end application. Must be a valid UUID4   	|   	|
| `API_URL_ENDPOINT`  	| Location of the API including the API version path 	| `http://api:5000/api/v1/`  	|
| `NETCRAFT_REPORT_EMAIL`  	| Email address to receive NetCraft confirmation on. [More information](https://report.netcraft.com/report)  	|   	|
| `GSB_API_KEY`  	| Google Safebrowsing API key to submit reports. [More information](https://developers.google.com/safe-browsing/v4/get-started)   	|   	|
| `URLSCANIO_API_KEY`  	| API key used to search and retrieve domains from URLscan.io  [More information](https://urlscan.io/) 	|   	|
| `SERVER_NAME`  	| Domain name where the NGINX container runs externally 	|   	|
| `AUTHENTICATION_SESSION_SECRET_KEY` 	| Session secret key used to manage authenticated sessions. Must be 32 characters. 	|   	|
| `MINIO_HOST` 	| Location of MinIO  	| `minio:9000`  	|
| `MINIO_ROOT_USER` 	| Minio username  	|   	|
| `MINIO_ROOT_PASSWORD`	| Minio password |   	|
| `NOTIFICATION_EMAIL_PORT`  	| Port number of the used mail server for sending out notifications  	|   	|
| `NOTIFICATION_EMAIL_SERVER`  	| Server address of the used mail server for sending out notifications 	|   	|
| `NOTIFICATION_EMAIL_SENDER`  	| Email address the used for sending out notifications 	|   	|
| `NOTIFICATION_EMAIL_RECEIVER`  	| Email address receiving notifications 	|   	|
| `NOTIFICATION_EMAIL_PASSWORD`  	| Password of the email address the used for sending out notifications 	|   	|
| `FRONT_END_USERNAME`  	|  	| `admin`  	|
| `FRONT_END_PASSWORD`  	|  	| `admin`  	|
| `MONITOR_COUNTRY_FILTER`  	| two-character ISO country code to specify notification for a certain country 	|   	|

## Configuration
BigPhish is a signature-based tool that requires some finetuning before it's operational.
Fortunately, all configuration can be done by modifying simple JSON files in the `config` folder.

### `api_tokens.json`
This file contains all the API tokens that can access the BigPhish API. 
It follows this structure, containing a name for the token, as well as a hexadecimal representation of a UUIDv4. 
New tokens created using the `/api/v1/create_access_token` endpoint will be appended to this file. 
No modification is needed for the initial setup, as the extended authentication token is configured in the `.env` file.

```
[
    {
        "name": "test-organisation",
        "token": "fe7e8ccd76dc4b539636db512f4da7a2"
    }
]
```

### `phishing_kit_fingerprints.json`
This file stores the fingerprints of all known phishing kits. It is a list of key, value pairs, in which each list item is a phishing kit. 

`Pages` contains the filenames that are part of the fingerprint, including their MIME type. 
Every entry does *NOT* start with a forward slash and *MUST* contain a valid (partial) MIME type. 
Hence, specify JavaScript resources as `application/javascript` and text files as `text/plain`. 
As the MIME type checker in crawler uses partial matching, MIME types can also be specified partially. E.g., defining an image as `image`. 

`Searches` contains entries related to [URLscan.io](https://urlscan.io/) searches. 
As many phishing websites are submitted to this sandbox, it can be used to discover and identify known phishing kits. 
A list of hash searches related to known phishing kits can be added here. `hash:xxxxxxx` relates to the hash known by URLscan.

`Panel` contains a list of possible panel login pages associated with this phishing kit. 
Many phishing kits allow the attacker to log in to their phishing panels on these pages. 
The details mentioned on these login pages allow for more specific actor (groups) attributions. 
File extensions and MIME types are not required here.

```
"Phishing kit1": {
        "pages": {
            "img/undraw_rocket.svg": "image",
            "js/overview.js": "application/javascript"
        },
        "searches":{
            "hash:xxxx": "filename.html"
        },
        "panel": [
            "login",
            "dashboard"
        ]
    }
```

### `lists/companies.json`   
The list of companies, or brands, to monitor can be specified here. 
Include the full name as well as possible abbreviations and award them a score. 
This score is used by the certificate scanner to assign each incoming certificate and its listed domains a score. 
As soon as a threshold score is reached, a domain is marked as potentially malicious and forwarded to the crawler.

```
{
    "paypal": {
        "paypal" : 150,
        "payp": 70
    }
}
```

### `lists/fp.json`
Since crawling the Web for potential malicious domains can result in a large number of false positives, a list of known false positives strings can be added to this file. 
Domains partially matching these strings will be omitted from further analysis.

```
[
    "amazonaws",
    "amazonservices",
    "speedtest",
    "ooklaserver",
]
```

### `lists/malicious_keywords.json` 
Similar to the brands to monitor, specify words that could indicate phishing activity in this file. When one of the words in this file is present in a domain name, the score will be increased by 50 and as soon as a threshold value is reached, a domain is marked as potentially malicious and forwarded to the crawler.

```
[
    "register",
    "update",
    "payment",
    "verify",
    "decline"
]
```

### `lists/malicious_tlds.json`
A list of TLDs that are known to be hosting phishing pages can be defined here. Inspiration for such TLDs can be gathered from the [Spamhaus TLD list](https://www.spamhaus.org/reputation-statistics/).
Entries do NOT start with a period.

```
[
  "tk",
  "ga",
  "gq",
  "cc",
  "biz",
  "co"
]
```

### `lists/valid_websites.json`
To prevent unnecessary crawls of benign company websites, specify the legitimate domain(s) of the brand(s) monitored here. These domains will be omitted from further analysis. Subdomains do not have to be specified, they are automatically excluded. 

```
[
    "paypal.com"
]
```

## Usage

To deploy BigPhish with all its services, run the following command:

`docker compose up --build -d`

After a few moments, all services are now running in the following locations:

| Service             | Location                               | Exposed |
|---------------------|----------------------------------------|---------|
| Elasticsearch       | `localhost:9200`                       | no      |
| Kibana              | `localhost:5601`                       | no      |
| API                 | `localhost:5000`                       | no      |
| NodeJS              | `localhost:3000`                       | no      |
| NGINX               | `:80` and `:443`                       | yes     |
| MinIO               | `localhost:9000` <br> `localhost:9001` | no      |
| Crawler             |                                        | no      |
| Certscanner         |                                        | no      |
| VPN                 |                                        | no      |
| Monitor             |                                        | no      |

### Testing environment

Deploying not all services allows for easier testing of BigPhish. To deploy such an environment, run the following command:

`docker compose up --build -d elasticsearch kibana minio api crawler certscanner certstream`

This will not spin up the NGINX server and the monitor.

### Elasticsearch indices
Two indices are automatically created within your Elasticsearch instance. These are:

- `domain_index` stores the potential phishing domains originating from the CertScanner.
- `crawler_index` stores all the information related to the crawls.

### MinIO buckets
Two buckets are created within your MinIO instance:

- `screenshots` stores all the screenshots taken.
- `found-phishing-kits` stores all the gathered phishing kits.

### API deployment
To deploy the API behind an NGINX reverse proxy and a secured HTTPS connection, please do the following.

Create a folder to store the Let's Encrypt certificates, e.g.
```
mkdir letsencrypt
chown root:101 letsencrypt
chmod 770 letsencrypt
```

By starting the NGINX container, certificates will be created automatically. 

### Export data

To dump all the data within the ElasticSearch instance, use [elasticsearch-dump](https://github.com/elasticsearch-dump/elasticsearch-dump).
If you want to dump the complete `crawler_index` in your `/data` directory use:

```
docker run --net=host --rm -ti -v /data:/tmp elasticdump/elasticsearch-dump \
  --input=http://user:password@localhost:9200/crawler_index \
  --output=/tmp/crawler_export.json \
  --type=data
```

## Contributing
Contributions to BigPhish are highly appreciated and more than welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for more information about our contributions process. 

### Setup development environment
To create a development environment to contribute, follow these steps:

### Requirements
- Python >= 3.11
- Node >= 18.5.0
- Docker

### Setup

```bash
# checkout this repository
git clone git@gitlab.com:cossas/bigphish.git
cd bigphish

# install pre-commit hooks
pre-commit install

# select subproject you want to work on and install requirements.txt
cd api
pip install -r requirements.txt

# make your changes and push to your branch
git commit -m "my awesome changes"
```

## Roadmap for further development
For further development and operationalization of BigPhish, we suggest the following roadmap:

1. **Enable parallelization in the crawling process.** 
Now, one single crawler has to perform all the crawling alone, which causes long execution times, sometimes even longer than the crawling interval. 
To solve this, we should create an independent queue that retrieves the domains that should be crawled in regular intervals. 
Multiple crawlers pick jobs from this queue and execute them. 

2. **Improve the modification of phishing kit signatures in the front-end interface.**
This can now be done with a simple modal displaying a giant JSON file. 
Errors are easily made, which results in hard-to-fix errors. 
This can be improved by showing a nicely formatted table in which it is easy to change or add (new) fingerprints.

3. **Introduce a database of crawled domains with their status instead of only the Elasticsearch index.**
All information about the crawled domains is now stored in Elasticsearch. 
So, when the user requests information about a domain, all information regarding that domain is gathered and analyzed. 
However, most of this information is pretty static, so could well be kept in a database. 
This allows for much faster queries and fewer data duplications. 

4. **Switch fingerprint format to IoK**. 
The Indicator of Kit ([IOK](https://github.com/phish-report/IOK)) language nicely specifies indicators that can be used to detect a phishing kit. 
This is a better-defined language than our JSON format. 

5. **Incorporate random user agents for improved cloaking aversion.** 
Some kits contain advanced cloaking mechanisms to hide themselves from crawlers deployed by security researchers.
One way to do that is to block certain UserAgent strings. 
BigPhish uses a static recent Chrome UserAgent by default, which might lead to detection by phishers in the future.
Additionally, some phishing kits block all non-mobile UserAgents. 
Randomizing this string could yield better detection results.

6. **Optimize Elastic queries.** 
Elasticsearch knowledge was lacking when most queries were written.
As a result, we do not leverage most of the capabilities of Elasticsearch yet.
Optimizations can be achieved by writing better queries.

7. **Add support for specific paths in the URL**
Due to the origin of domains (from the certificate transparency logs), BigPhish works on domains instead of URLs.
Therefore, specific paths are ignored when crawling phishing pages.
Some kits do not host anything on the root but only on certain paths and are now missed as a result.
Adding support for specific paths would increase detection rates.

## About
BigPhish is developed by [TNO](https://tno.nl) and released under [COSSAS](https://cossas-project.org)