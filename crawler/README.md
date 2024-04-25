# BigPhish Crawler

> Identifying phishing kits on live phishing websites

This is the second step of BigPhish, which tries to identify the used phishing kit on a website based on a collection of fingerprints of known phishing kits. 
It uses an Elasticsearch index to query input from and store its output. 
Every hour, the crawler retrieves new domains from Elasticsearch, actively crawls the retrieved URLs and tries to identify the used phishing kit. 

## Installation

For this module to run, you'll need:

- Python 3.8 or higher and pip
- Firefox together with geckodriver
- A working Internet connection

To install the necessary dependencies of this project, just execute

```
pip3 install -r requirements.txt
```

But it is better to use the accompanied [Dockerfile](Dockerfile).

## Setup

As mentioned in the main [README](../README.md), customization is critical before deployment. 
The crawler relies on a given set of resources to detect phishing kits on live websites.
Therefore, one should modify at least the following files in `/config/lists`:

| File           	| Purpose                                                                                                       	| Example                                                                       	|
|----------------	|---------------------------------------------------------------------------------------------------------------	|-------------------------------------------------------------------------------	|
| **phishing_kit_fingerprints.json** 	| This file stores the fingerprints of all known phishing kits. It is a list of key, value pairs, in which each list item is a phishing kit.  	| `"Phishing kit1": { "pages": { "img/undraw_rocket.svg": "image", "js/overview.js": "application/javascript" }, "searches":{ "hash:xxxx": "filename.html" }, "panel": [ "login", "dashboard" ] }` 	|
| **valid_websites.json** 	| Add all the valid domains for this company	| `["paypal.com"] `	|

## Usage

To use the crawler, these are the arguments you can use:

```
usage: main.py [-h] [-no] [-u] [-d] [-t TEST_RUN]

BigPhish crawler, detects phishing kits on a live website

optional arguments:
  -h, --help            show this help message and exit
  -no, --disable_checks
                        Disable active VPN and Elastic connection checks
  -u, --urlscan_domains
                        Enable the search for domains with hashes on URLscan.io
  -d, --dirbust         Enable detection based on known urls and paths
  -t, --test_run TEST_RUN
                        Do a test run on a given domain
```

The `ES_PASSWORD` and `ES_USER` variables are passed as environment variables due to the dockerized environment of BigPhish. 
Replace these variables in `elk_operations.py` to configure them yourself to use it outside of Docker.

## Tests
The application can be tested by using PyTest, although the application lacks proper test cases, unfortunately. 
To execute the tests, run:

```
pytest test_crawler.py
```