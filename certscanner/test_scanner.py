from json import loads

from utils import search_for_default_subdomains, unconfuse


def test_unconfuse():
    with open(f"confusables.json", "r", encoding="utf-8") as file:
        CONFUSABLES = loads(file.read())

    domain_unconfused, _ = unconfuse("𝘉eterbed.nl", CONFUSABLES)
    assert domain_unconfused == "beterbed.nl"

    domain_unconfused, _ = unconfuse("xn--diseolatinoamericano-66b.com", CONFUSABLES)
    assert domain_unconfused == "diseñolatinoamericano.com"

    domain_unconfused, _ = unconfuse("xn--d1acufc.xn--p1ai", CONFUSABLES)
    assert domain_unconfused == "дoмeh.pф"

    domain = "xn--123-og4btf9f5iscu662bon1efqqbnhl.xyz"
    unconfused_domain, unicode = unconfuse(domain, CONFUSABLES)
    assert unicode is True or unconfused_domain != domain

    domain = "xn--sns-0k4b3b5e2h.xyz"
    unconfused_domain, unicode = unconfuse(domain, CONFUSABLES)
    assert unicode is True or unconfused_domain != domain

    domain = "xn--jobs-fr-dessau-rolau-rwb04d"
    unconfused_domain, unicode = unconfuse(domain, CONFUSABLES)
    assert unicode is True or unconfused_domain != domain

    domain = "xn--d1acufc.xn--p1ai"
    unconfused_domain, unicode = unconfuse(domain, CONFUSABLES)
    assert unicode is True or unconfused_domain != domain

    domain = "xn--meine-groe-chance-eob"
    unconfused_domain, unicode = unconfuse(domain, CONFUSABLES)
    assert unicode is True or unconfused_domain != domain

    domain = "testdomain.com"
    unconfused_domain, unicode = unconfuse(domain, CONFUSABLES)
    assert unicode is False and unconfused_domain == domain


def test_search_for_default_subdomains():
    input_domain = "autodiscover.testdomain.com"
    assert search_for_default_subdomains(input_domain) is True

    input_domain = "ns1.testdomain.com"
    assert search_for_default_subdomains(input_domain) is True

    input_domain = "ns.testdomain.com"
    assert search_for_default_subdomains(input_domain) is True

    input_domain = "ns24.testdomain.com"
    assert search_for_default_subdomains(input_domain) is True

    input_domain = "webmail.testdomain.com"
    assert search_for_default_subdomains(input_domain) is True

    input_domain = "something.mail.testdomain.com"
    assert search_for_default_subdomains(input_domain) is False

    input_domain = "autodiscoverzonderpunt.testdomain.com"
    assert search_for_default_subdomains(input_domain) is False

    input_domain = "webmailen.nl"
    assert search_for_default_subdomains(input_domain) is False
