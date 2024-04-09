"""Various detection methods for retrieving features from certificates."""

from re import split, sub

from lists import get_all_lists
from nltk import edit_distance
from tld import get_tld
from utils import Domain, search_for_default_subdomains, unconfuse

(
    COMPANIES,
    FALSE_POSITIVES,
    MALICIOUS_WORDS,
    SUSPICIOUS_TLDS,
    VALID_WEBSITES,
    CONFUSABLES,
) = get_all_lists()


def detect_domain(domain_name: str) -> Domain:
    """
    Analyze the domain listed in the certificate and searches for malicious ones.

    :param domain_name: domain name as a string
    :return: a domain object with all extracted information
    """
    # Instantiate a new domain object
    cur_domain = Domain()

    # Fix wildcard subdomains
    if domain_name.startswith("*."):
        domain_name = domain_name[2:]

    # Add domain name to score dictionary for output
    cur_domain.domain = domain_name

    # Omit default and widely used subdomains
    if search_for_default_subdomains(domain_name):
        return cur_domain

    # Filter out production, testing and other false positive domains
    for false_positive in FALSE_POSITIVES:
        if false_positive in domain_name:
            cur_domain.reset_score()
            return cur_domain

    # Contains non unicode characters?
    cur_domain.domain_unconfused, confused_characters = unconfuse(
        domain_name, CONFUSABLES
    )
    if domain_name != cur_domain.domain_unconfused or confused_characters:
        cur_domain.unicode = True
        cur_domain.increase_score(30)
        domain_name = cur_domain.domain_unconfused

    # Detect fake www in hostname of subdomains
    if "www" in (domain_name[4:] if domain_name.startswith("www.") else domain_name):
        cur_domain.fake_www = True
        cur_domain.increase_score(45)

    # Contains lots of subdomains '.', only increase score if more than 2
    count = domain_name.count(".") - 1
    if domain_name.startswith("www."):
        count -= 1
    if 1 < count < 5:
        cur_domain.increase_score(count * 2)
    if (
        count > 5
    ):  # Domains with 6 or more subdomains are not considered phishing (never happened)
        cur_domain.reset_score()
        return cur_domain

    cur_domain.sub_domains = count

    # Get only the domain name to analyze afterwards
    try:
        res = get_tld(
            domain_name, as_object=True, fail_silently=True, fix_protocol=True
        )
        domain_name = sub(rf"\.{res.tld}$", "", domain_name)  # type: ignore
        cur_domain.tld = res.tld  # type: ignore

        # If domain is equal to the real company domain name, report as FP
        if res.fld in VALID_WEBSITES:  # type: ignore
            cur_domain.reset_score()
            return cur_domain

    except AttributeError:
        cur_domain.tld = None

    # Free or malicious top-level domains used?
    if cur_domain.tld in SUSPICIOUS_TLDS:
        cur_domain.suspicious_tld = cur_domain.tld  # type: ignore
        cur_domain.increase_score(20)

    # Split all the words in this domain for easy word searching
    words_in_domain = split(r"\W+", domain_name)

    # Contains a fake TLD as used by one of the companies
    list_of_fake_tlds = ["com", "de"]
    for word in words_in_domain:
        if word in list_of_fake_tlds:
            cur_domain.fake_tld = word
            cur_domain.increase_score(20)

    # Save the domain name as a temporary variable to remove
    # detections from it later on
    temp_domain = domain_name

    # Contains keywords from Dutch companies?
    for company, search_words in COMPANIES.items():
        for word in words_in_domain:
            for company_word, value in search_words.items():
                # For small words, only match exactly
                # If company is exactly one of the words
                if word == company_word:
                    cur_domain.increase_score(value)
                    cur_domain.company.add(company)
                    temp_domain = temp_domain.replace(company_word, "")
                    break

                # If company name is within one of the words
                if company_word in word:
                    if len(company_word) > 4:
                        cur_domain.increase_score(value - 20)
                        cur_domain.company.add(company)
                        temp_domain = temp_domain.replace(company_word, "")
                        break
                    if word.startswith(company_word):
                        cur_domain.increase_score(value - 20)
                        cur_domain.company.add(company)
                        temp_domain = temp_domain.replace(company_word, "")
                        break

                # Or if the company name is very similar
                if edit_distance(word, company_word) <= 1 and len(company_word) > 4:
                    cur_domain.increase_score(value - 40)
                    cur_domain.possible_company.add(company)
                    break

    # Contains possible malicious keywords?
    for malicious_word in MALICIOUS_WORDS:
        for word in words_in_domain:
            if malicious_word in word:
                cur_domain.increase_score(50)
                cur_domain.suspicious_keywords.add(malicious_word)
                temp_domain = temp_domain.replace(malicious_word, "")
                break

            if edit_distance(word, malicious_word) <= 1 and len(word) > 4:
                cur_domain.increase_score(40)
                cur_domain.suspicious_keywords.add(malicious_word)
                break

    # If the remaining temp_domain string is now very short, increase the score
    if len(temp_domain) < 5:
        cur_domain.increase_score(25)

    # If the length of the domain is above 55 characters (mean of identified
    # domains is 24, so double the average size), decrease the score
    if len(domain_name) > 55:
        cur_domain.decrease_score(20)

    # Contains lots of -'s, only increase score if more than 2
    count = domain_name.count("-")
    if 2 >= count < 6 and "xn--" not in domain_name:
        cur_domain.increase_score(count * 3)
    cur_domain.dashes = count

    return cur_domain
