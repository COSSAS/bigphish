"""Domain object class."""

from datetime import datetime


class Domain:
    """Domain object."""

    def __init__(self, domain_name):
        """Initialize a new domain object."""
        self.domain = domain_name
        self.landing_url = ""
        self.crawl_date = datetime.now(timezone.utc)
        self.state = "unknown"
        self.identified_as = "unknown"
        self.first_crawled = datetime.now(timezone.utc)
        self.nameservers = []

        # Visual and source information
        self.screenshot_file = ""
        self.screenshot_hash = ""
        self.doc_title = ""
        self.html_source = ""
        self.html_hash = ""
        self.resources = ""
        self.ip = "0.0.0.0"
        self.server_header = ""

        # WHOIS information
        self.whois_source = ""
        self.whois_registrar = ""
        self.whois_reg_date = 0  # int: unix epoch
        self.whois_exp_date = 0  # int: unix epoch
        self.whois_country = ""

        # Phishing kit analysis information
        self.resolved_urls = []
        self.dirbust_identified_kits = []
        self.resourcebust_identified_kits = []
        self.resolved_resources = []
        self.identified_kits = []

        # Kit panel specifics
        self.panel_login = ""
        self.panel_login_title = ""
