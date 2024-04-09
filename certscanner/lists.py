"""All the lists required."""

from json import loads


def load_list(file_name):
    """
    Load a json list from file.

    :param file_name: file path pointing to that list
    :return: the list parsed as a valid JSON
    """
    with open(file_name, "r", encoding="utf-8") as file:
        return loads(file.read())


def get_all_lists():
    """
    Load all the necessary lists.

    :return: all lists as ready-to-use lists
    """
    # List of all companies that are monitored
    list_of_companies = load_list("lists/companies.json")

    # List of all False Positives
    false_positives = load_list("lists/companies.json")

    # List possibly malicious keywords, often seen in phishing URLs
    list_of_possible_malicious_words = load_list("lists/malicious_keywords.json")

    # List of malicious Top Level Domains
    list_of_suspicious_tlds = load_list("lists/malicious_tlds.json")

    # List of all the valid websites, to filter out FP
    valid_websites = load_list("lists/valid_websites.json")

    # Dictionary of confusables, used to detect typosquatting etc.
    confusables = load_list("confusables.json")

    return (
        list_of_companies,
        false_positives,
        list_of_possible_malicious_words,
        list_of_suspicious_tlds,
        valid_websites,
        confusables,
    )
