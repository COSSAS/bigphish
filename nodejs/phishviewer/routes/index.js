var express = require('express');
var router = express.Router();
const axios = require('axios');
var dejson = require('json-destringify');
var ensureLoggedIn = require('connect-ensure-login').ensureLoggedIn;

// Set the X-API-Key for all API requests
axios.defaults.headers.common = {
    "X-API-Key" : process.env.API_EXTENDED_AUTHENTICATION_KEY,
    "Content-Type": "application/json",
    "User-Agent": "BigPhish"
}

const apiEndpoint = process.env.API_URL_ENDPOINT;

/* GET home page. */
router.get('/', ensureLoggedIn(), async function(req, res, next) {
    try{
        axios.get(apiEndpoint + 'active_domains_summary')
            .then(resp => {res.render('index', {page:'Home', menuId:'home', active_domains:resp.data.domains, user:req.user}) } )
            .catch( err => { 
                res.render('index', {page:'Home', menuId:'home', active_domains:[], user:req.user}) 
                console.log(err) 
        });
    } catch(err) {
        res.render('index', {page:'Home', menuId:'home', active_domains:[], user:req.user});
    }
});

/* GET list page. */
router.get('/list', ensureLoggedIn(), async function(req, res, next) {
    try{
        axios.get(apiEndpoint + 'active_domains_summary')
            .then(resp => {res.render('list', {page:'List', menuId:'list', active_domains:resp.data.domains, user:req.user}) } )
            .catch( err => { 
                res.render('list', {page:'List', menuId:'list', active_domains:[], user:req.user}) 
                console.log(err) 
        });
    } catch(err) {
        res.render('list', {page:'List', menuId:'list', active_domains:[], user:req.user});
    }
});

/* GET domain page. */
router.get('/domain', ensureLoggedIn(), async function(req, res) {
    try{
        axios.get(apiEndpoint + 'domain_details', {
            params: {
              domain: req.query.domain
            }
        }).then(resp => {
            res.render('domain', {page:'Domain', menuId:'domain', domain_details:resp.data.entries});
        });
    } catch(err) {
        console.log(err);
        res.render('domain', {page:'Domain', menuId:'domain'});
    }
});

/* POST domain page. */
router.post('/domain', ensureLoggedIn(), async function(req, res) {
    try{
        axios.get(apiEndpoint + 'domain_details', {
            params: {
              domain: req.body.domain
            }
        }).then(resp => {
            res.render('domain', {page:'Domain', menuId:'domain', domain_details:resp.data.entries});
        });
    } catch(err) {
        console.log(err);
        res.render('domain', {page:'Domain', menuId:'domain'});
    }
});

/* POST domain as false positive. */
router.post('/domain_fp', ensureLoggedIn(), async function(req, res) {
    try{
        axios.post(apiEndpoint + 'false_positive', {
          domain: req.body.domain
        })
        .then((response) => {
          res.status(200).send();
        }, (err) => {
          console.log(err);
          res.status(500).send({ error: err });
        });
    }
    catch(err) {
        console.log(err);
        res.status(500).send({ error: err });
    }
});

/* POST add a new domain. */
router.post('/new_domain', ensureLoggedIn(), async function(req, res) {
    try{
        axios.post(apiEndpoint + 'new_domain', {
          domain: req.body.domain
        })
        .then((response) => {
          res.status(200).send();
        }, (err) => {
          console.log(err);
          res.status(500).send({ error: err });
        });
    }
    catch(err) {
        console.log(err);
        res.status(500).send({ error: err });
    }
});

/* POST execute a XSS attack. */
router.post('/xss_uadmin', ensureLoggedIn(), async function(req, res) {
    try{
        axios.post(apiEndpoint + 'xss_uadmin_domain', {
          url: req.body.url
        })
        .then((response) => {
          res.status(200).send();
        }, (err) => {
          console.log(err);
          res.status(500).send({ error: err });
        });
    }
    catch(err) {
        console.log(err);
        res.status(500).send({ error: err });
    }
});

/* POST execute flooding attack. */
router.post('/flood_uadmin', ensureLoggedIn(), async function(req, res) {
    try{
        axios.post(apiEndpoint + 'flood_uadmin_domain', {
          url: req.body.url
        })
        .then((response) => {
          res.status(200).send();
        }, (err) => {
          console.log(err);
          res.status(500).send({ error: err });
        });
    }
    catch(err) {
        console.log(err);
        res.status(500).send({ error: err });
    }
});

/* POST report to NetCraft. */
router.post('/report_netcraft', ensureLoggedIn(), async function(req, res) {
    try{
        axios({
            method: "post",
            url: "https://report.netcraft.com/api/v3/report/urls",
            data: { 
                "email": process.env.NETCRAFT_REPORT_EMAIL,
                "reason": "This is a phishing website",
                "urls": [
                            {
                                "country:" : "NL",
                                "url" : req.body.url
                            }
                        ]
                    },
        })
        .then((response) => {
            res.status(200).send(response.data.uuid);
            }, (err) => {
            console.log(err);
            res.status(500).send({ error: err, reason: err.error });
            });
        
    }
    catch(err) {
        console.log(err);
        res.status(500).send({ error: err });
    }
});

/* POST report to Google SafeBrowsing. */
router.post('/report_gsb', ensureLoggedIn(), async function(req, res) {
    try{
        axios({
            method: "post",
            url: "https://safebrowsing.google.com/safebrowsing/clientreport/crx-report",
            data: [req.body.url],
        })
            .then((response) => {
            res.status(200).send();
            }, (err) => {
            console.log(err);
            res.status(500).send({ error: err, reason: response.error });
            });
    }
    catch(err) {
        console.log(err);
        res.status(500).send({ error: err });
    }
});

/* GET search page. */
router.get('/search', ensureLoggedIn(), async function(req, res) {
    if (Object.keys(req.query).length != 0) {
        try{
            axios.get(apiEndpoint + 'search', {
                params: {
                  field: req.query.field,
                  query: req.query.query
                }
            }).then(resp => {
                res.render('search', {page:'Search', menuId:'search', query_results:resp.data.entries, searched_for:req.query.query});
            });
        } catch(err) {
            console.log(err);
            res.render('search', {page:'Search', menuId:'search'});
        }
    } else {
        res.render('search', {page:'Search', menuId:'search'});
    }
});

/* POST search page. */
router.post('/search', ensureLoggedIn(), async function(req, res) {
    try{
        axios.get(apiEndpoint + 'search', {
            params: {
              field: req.body.field,
              query: req.body.query,
              date_from: new Date(req.body.daterange.split(" - ")[0]),
              date_to: new Date(req.body.daterange.split(" - ")[1]),
              only_identified: req.body.only_identified,
            }
        }).then(resp => {
            res.render('search', {page:'Search', menuId:'search', query_results:resp.data.entries, searched_for:req.body.query});
        });
    } catch(err) {
        console.log(err);
        res.render('search', {page:'Search', menuId:'search'});
    }
});

/* GET trends page. */
router.get('/trends', ensureLoggedIn(), async function(req, res) {
    try{
        axios.get(apiEndpoint + 'trends', {
            params: {
              date_from: new Date(new Date().setDate(new Date().getDate() - 4)),
              date_to: new Date()
            }
        }).then(resp => {
            renderTrendPage(resp,res);
        });
    } catch(err) {
        console.log(err);
        res.render('trends', {page:'Trends', menuId:'trends'});
    }
});

/* POST trends page. */
router.post('/trends', ensureLoggedIn(), async function(req, res) {
    try{
        axios.get(apiEndpoint + 'trends', {
            params: {
              date_from: new Date(req.body.daterange.split(" - ")[0]),
              date_to: new Date(req.body.daterange.split(" - ")[1]), 
              specific_kit: req.body.specificKit
            }
        }).then(resp => {
            renderTrendPage(resp,res);
        });
    } catch(err) {
        console.log(err);
        res.render('trends', {page:'Trends', menuId:'trends'});
    }
});

/* GET fingerprints modal. */
router.get('/fp_details', ensureLoggedIn(), async function(req, res) {
    try{
        axios.get(apiEndpoint + 'fp_details').then(resp => {
            res.status(200).send(resp.data);
        });
    } catch(err) {
        console.log(err);
        res.status(500).send({ error: err, reason: resp.error });
    }
});

/* POST fingerprints changes. */
router.post('/fp_details', ensureLoggedIn(), async function(req, res) {
    try{
        axios.post(apiEndpoint + 'fp_details', {
            kit_fingerprints: dejson.destringify(req.body.kit_fingerprints).result,
        }).then(resp => {
            res.status(200).send();
        }, (err) => {
            console.log(err);
            res.status(500).send({ error: err });
        });
    } catch(err) {
        console.log(err);
        res.status(500).send({ error: err, reason: err });
    }
});

// Render the contents of the Trends page 
function renderTrendPage(resp,res) {
    date_from = resp.config.params.date_from.toISOString().split('T')[0];
    date_to = resp.config.params.date_to.toISOString().split('T')[0];
    counts_per_kit = getSortedKitCounts(resp.data.entries['kit_totals'])
    stacked_bar_graph = createStackedBarData(resp.data.entries);

    res.render('trends', {page:'Trends', menuId:'trends',
        counts_per_kit:counts_per_kit,
        stacked_bar_graph:stacked_bar_graph,
        average_time_online:Math.round(resp.data.entries['total_average_time_online']),
        domains_active_per_day:Object.values(resp.data.entries['domains_active_per_day']),
        total_domains:resp.data.entries['total_domains'],
        total_new_domains:resp.data.entries['total_new_domains'],
        total_popular_tld:resp.data.entries['total_popular_tld'],
        domains:resp.data.entries['domains'],
        date_from:date_from,
        date_to:date_to
    });
}

// Make a stacked bar chart
function createStackedBarData(data) {
    var all_kits = Object.keys(data['kit_totals'])
    var counts_per_kit = {};

    for (const kit of all_kits) {
        counts_per_kit[kit] = [];
    }

    for (const date in data['kits_per_day']) {
        for (const kit of all_kits) {
            if (Object.keys(data['kits_per_day'][date]).includes(kit)){
                counts_per_kit[kit].push(data['kits_per_day'][date][kit])
            } else {
                counts_per_kit[kit].push(0)
            }
        }
    }

    var stacked_bar_graph = {
        date_series: Object.keys(data['kits_per_day']),
        kit_counts: counts_per_kit
    }
    return stacked_bar_graph;
}

// Sort the kit counts
function getSortedKitCounts(data) {
    const sorted = Object.fromEntries(
        Object.entries(data).sort(([,a],[,b]) => b-a)
    );

    return sorted
}


module.exports = router;
