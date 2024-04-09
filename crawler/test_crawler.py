import dirbust
import index_bust
import utils
from domain import Domain


def test_combine_kits():
    assert utils.combine_dir_resource_busts([], []) == []
    assert utils.combine_dir_resource_busts([], set()) == []


def test_get_fuzzable_url():
    assert (
        dirbust.get_fuzzable_url("https://domain.nl/login") == "https://domain.nl/FUZZ"
    )
    assert dirbust.get_fuzzable_url("https://domain.nl/") == "https://domain.nl/FUZZ"
    assert (
        dirbust.get_fuzzable_url("https://domain.nl/retail/login")
        == "https://domain.nl/retail/FUZZ"
    )
    assert dirbust.get_fuzzable_url("https://domain.nl") == "https://domain.nl/FUZZ"
    assert (
        dirbust.get_fuzzable_url("https://domain.nl/very/deep/down/the/link")
        == "https://domain.nl/very/deep/down/the/FUZZ"
    )
    assert (
        dirbust.get_fuzzable_url("https://sub.domain.things.domain.nl")
        == "https://sub.domain.things.domain.nl/FUZZ"
    )
    assert (
        dirbust.get_fuzzable_url("https://sub.domain.things.domain.nl/login.php")
        == "https://sub.domain.things.domain.nl/FUZZ"
    )
    assert (
        dirbust.get_fuzzable_url("https://sub.domain.things.domain.nl/files/login.php")
        == "https://sub.domain.things.domain.nl/files/FUZZ"
    )
    assert (
        dirbust.get_fuzzable_url(
            "https://sub.domain.things.domain.nl/files/login.php?query=VALUE&post=TRUE"
        )
        == "https://sub.domain.things.domain.nl/files/FUZZ"
    )
    assert (
        dirbust.get_fuzzable_url("https://uat.oya.tikki.online/#/")
        == "https://uat.oya.tikki.online/#/FUZZ"
    )


def test_whois():
    domain = Domain("google.com")
    domain = utils.populate_whois(domain)
    assert "MarkMonitor" in domain.whois_registrar


def test_index_bust():
    html = """
    <html><head>
    <title>Index of /</title>
    </head>
    <body>
    <h1>Index of /</h1>
    <table>
    <tbody><tr><th valign="top">&nbsp;</th><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th><th><a href="?C=D;O=A">Description</a></th></tr>
    <tr><th colspan="5"><hr></th></tr>
    <tr><td valign="top">&nbsp;</td><td><a href="cgi-bin/">cgi-bin/</a>               </td><td align="right">2020-07-13 12:56  </td><td align="right">  - </td><td>&nbsp;</td></tr>
    <tr><td valign="top">&nbsp;</td><td><a href="panel3.0 2.zip">panel3.0 2.zip</a> </td><td align="right">2020-07-13 12:43  </td><td align="right"> 14M</td><td>&nbsp;</td></tr>
    <tr><td valign="top">&nbsp;</td><td><a href="panel%20(2)%202/">panel (2) 2/</a>    </td><td align="right">2020-07-13 18:35  </td><td align="right">  - </td><td>&nbsp;</td></tr>
    <tr><td valign="top">&nbsp;</td><td><a href="text_file_to_detect.txt">text_file_to_detect.txt</a>    </td><td align="right">2020-07-13 18:35  </td><td align="right">  - </td><td>&nbsp;</td></tr>
    <tr><td valign="top">&nbsp;</td><td><a href="file_to_detect.jpg">file_to_detect.jpg</a>    </td><td align="right">2020-07-13 18:35  </td><td align="right">  - </td><td>&nbsp;</td></tr>
    <tr><th colspan="5"><hr></th></tr>
    </tbody></table>

    </body></html>
        """
    domain = "test.com"
    fingerprints = {
        "test_kit": {
            "pages": {
                "text_file_to_detect.txt": "text/html",
                "panel3.0 2.zip": "text/html",
                "file_to_detect.jpg": "image",
            },
            "searches": {},
            "panel": {},
        },
        "not_test_kit": {
            "pages": {"bestand_to_detect2.jpg": "text/html"},
            "searches": {},
            "panel": {},
        },
    }

    detected_kit, detected_urls = index_bust.find_fingerprints_index_page(
        domain, html, fingerprints
    )
    assert detected_kit == ["test_kit"]
    assert sorted(detected_urls) == sorted(
        ["panel3.0 2.zip", "file_to_detect.jpg", "text_file_to_detect.txt"]
    )
