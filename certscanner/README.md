# Phishing Certificate scanner

> Detecting phishing domains by observing and analyzing SSL/TLS Transparency Logs. 

This is the first step of BigPhish, which analyses a real-time stream of SSL/TLS transparency logs for suspicious domains. 
Based on several features, which can be found in `detectors.py`, each domain is given a score.
Once that score is above a customizable threshold, the domain will be flagged as malicious and stored in an Elasticsearch instance for further analysis.

## Installation

For this module to run, you'll need:

- Python 3.8 or higher and pip
- A working Internet connection

To install the necessary dependencies of this project, just execute

```
pip3 install -r requirements.txt
```

Or just use the [Dockerfile](Dockerfile) to deploy it through Docker.

## Setup

As mentioned in the main [README](README.md), customization is critical before deployment. 
This phishing detector relies on a given set of resources to detect potential phishing domains from a stream of TLS certificates.
Therefore, one should modify at least the following files in `/config/lists`:

| File           	| Purpose                                                                                                       	| Example                                                                       	|
|----------------	|---------------------------------------------------------------------------------------------------------------	|-------------------------------------------------------------------------------	|
| **companies.json** 	| Add the companies to monitor for in this file, together with abbrevations or shortened versions of their name 	| `{      "paypal" : {          "paypal"  :  150 ,          "payp" :  70     } }` 	|
| **malicious_keywords.json** 	| Add keywords to this file that relate to the companies monitored 	| `[ "register", "update", "payment", "verify", "decline"] `	|
| **valid_websites.json** 	| Add all the valid domains for this company	| `["paypal.com"] `	|
| **malicious_tlds.json** 	| Add a list of suspicious TLDs	| `["xyz", "tk"] `	|


## Usage

To use the certificate scanner, these are the arguments you can use:

```
CertScanner, execute python3 domain_detector.py -h for more information!

optional arguments:
  -h, --help            show this help message and exit
  -t, --threshold       specify the suspicious threshold (range: 30-499, default: 110)
  -s, --save            set this flag to save the certificates
  -v, --verbose         set this flag to enable more logging and output
  -e, --disable_elasticsearch
                        set this flag to disable the Elasticsearch connectio
```

The `ES_PASSWORD` and `ES_USER` variables are passed as environment variables 
due to the dockerized environment of BigPhish. 
Replace these variables manually in `elk_operations.py` to configure them yourself outside of Docker.

## Tests
The complete application can be tested by using PyTest:

```
pytest test_scanner.py
```