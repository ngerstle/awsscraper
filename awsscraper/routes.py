import time
import json
import base64
import random
import dnsscraper
from flask import Flask, render_template, make_response
from flask_caching import Cache



def loadconfig(configlocation='teams.config'):
    """ Import config from json file at (default) 'teams.config' """
    awsaccounts = {}
    with open(configlocation, 'r') as conffile:
        awsaccounts = json.load(conffile)
    teamnames = [name for name in awsaccounts]
    return dict(
        AWSACCOUNTS=awsaccounts,
        TEAMNAMES=teamnames
    )

APP = Flask(__name__)
APP.config.update(loadconfig())
CACHE = Cache(APP, config={'CACHE_TYPE': 'simple'})
UICACHETIME = 600
APICACHETIME = 60
MOCK_SCAN = False

def to_jsonc(data, tablename):
    """ converts a set of data to json """
    raw_json = json.dumps(
        {tablename: data})
    return raw_json.encode()

def to_csv(data, headers):
    """ convert a set of data to a csv, based on header column names"""
    rows = [",".join(headers)]
    for datarow in data:
        rowdata = [str(datarow.get(h, "")) for h in headers]
        rows += [",".join(rowdata)]
    csv = "\n".join(rows)
    return csv.encode()

def to_b64(bytestring):
    """" return a base64 encoded string"""
    return base64.b64encode(bytestring).decode('utf8')

APP.jinja_env.filters['b64encode'] = to_b64
APP.jinja_env.filters['toCSV'] = to_csv
APP.jinja_env.filters['tojsonc'] = to_jsonc


@APP.route("/")
def index():
    """ And index page... """
    return render_template("index.html", teamnames=APP.config['TEAMNAMES'])


def scan(team_name):
    """ Scans the provided team using the dnsscraper module,
    return the results and itme of completion"""
    if MOCK_SCAN:
        return  mock_scan(team_name)

    all_dns = {}
    all_tld = {}
    all_eip = {}

    def gatherresults(account, dns_list, tld_list, eip_list, filterfunc):
        """ function to collect data passed to scraper """
        filtered_dns_list = filter(filterfunc, dns_list)
        all_dns[account] = [i.get_dict() for i in filtered_dns_list]
        all_tld[account] = [{'TLD': t} for t in tld_list]
        all_eip[account] = [i.get_dict() for i in eip_list]

    dnsscraper.scrape_aws(APP.config['AWSACCOUNTS'], team_name, {
        "function": gatherresults,
        "filterfunc": lambda d: True
    })

    etime = time.time()
    return {"dns": flatten_d_dict(all_dns, 'Account'),
            "tld": flatten_d_dict(all_tld, 'Account'),
            "eip": flatten_d_dict(all_eip, 'Account'),
            "time": etime}

def flatten_d_dict(dic, name):
    """ flatten {account1:[o1...],account2:[o2,...],...} to [o1,o2,...] with
    account names in the object attributes """
    result = []
    for keyname in dic:
        for i in dic[keyname]:
            i[name] = keyname
            result += [i]
    return result

def mock_scan(team_name):
    """ Provides static data to mock the results of calling dnsscraper.scraperoute53
    """
    accountnames = [i[0] for i in APP.config["AWSACCOUNTS"][team_name]]
    regions = ["eu-north-1111", "eu-west-5", "af-east-2"]


    return {
        "dns": [
            {"Name":"www.tld1.net", "Type":"A", "IP":"1.1.1.1",
             "Public":True, "Private":False, "Unresolved":False,
             'Account': random.choice(accountnames)},
            {"Name":"test.tld1.net", "Type":"CNAME", "IP":"2.2.2.2",
             "Public":False, "Private":True, "Unresolved":False,
             'Account': random.choice(accountnames)},
            {"Name":"bobdev.tld2.org", "Type":"A", "IP":"",
             "Public":False, "Private":False, "Unresolved":True,
             'Account': random.choice(accountnames)},
            {"Name":"ace234a119.randtld2.asd.org", "Type":"TXT", "IP":"",
             "Public":False, "Private":False, "Unresolved":True,
             'Account': random.choice(accountnames)},
            {"Name":"doc.tld2.org", "Type":"CNAME", "IP":"3.3.3.3",
             "Public":True, "Private":False, "Unresolved":False,
             'Account': random.choice(accountnames)}
        ],
        "tld": [
            {'TLD':'tld1.net', 'Account': random.choice(accountnames)},
            {'TLD':'tld2.org', 'Account': random.choice(accountnames)},
            {'TLD':'randtld2.asd.org', 'Account': random.choice(accountnames)}
        ],
        "eip": [
            {"Region":random.choice(regions),
             "PublicIp": "1.1.1.1",
             "PrivateIp": "192.192.999.888",
             "InstanceId": "ec2:122555:qefqef:1323",
             'Account': random.choice(accountnames)},
            {"Region":random.choice(regions),
             "PublicIp": "2.2.2.2",
             "PrivateIp": None,
             "InstanceId": "ec2:122386:vinras:1111",
             'Account': random.choice(accountnames)},
            {"Region":random.choice(regions),
             "PublicIp": "3.3.3.3",
             "PrivateIp": None,
             "InstanceId": None,
             'Account': random.choice(accountnames)},
        ],
        "time": 123123123123.1}

@APP.route('/api/_/alljson')
@CACHE.cached(timeout=APICACHETIME)
def all_json():
    """ Returns results of scanning ALL teams in json"""
    results = {}
    for team_name in APP.config['TEAMNAMES']:
        try:
            results[team_name] = scan(team_name)
            results[team_name]["error"] = str(False)
        except Exception as unknownexception:
            results[team_name] = {"error": str(True),
                                  "errorvalue": str(unknownexception)}

    response_content = json.dumps(results)

    resp = make_response(response_content)
    resp.mimetype = "application/json"
    return resp


@APP.route('/api/json/<string:team_name>')
@CACHE.cached(timeout=APICACHETIME)
def teamjson(team_name):
    """ Return a result set for the team in json"""
    if team_name not in APP.config['TEAMNAMES']:
        return render_template("error.html",
                               teamnames=APP.config['TEAMNAMES'],
                               error="No such team")

    response_content = None
    try:
        scanresults = scan(team_name)

        dnss = scanresults["dns"]
        tlds = scanresults["tld"]
        eips = scanresults["eip"]
        scantime = scanresults["time"]

        response_content = json.dumps(
            {"dns": dnss, "tlds": tlds,
             "eips": eips, "scantime": scantime,
             "teamname": team_name})

    except Exception as unknownexception:
        response_content = json.dumps(
            {"error": str(True),
             "errorvalue": str(unknownexception)}
        )


    resp = make_response(response_content)
    resp.mimetype = "application/json"
    return resp


@APP.route('/api/_/allcsv')
@CACHE.cached(timeout=APICACHETIME)
def all_csv():
    """ returns result of scanning ALL teams as a csv"""
    results = {}
    for team_name in APP.config['TEAMNAMES']:
        try:
            results[team_name] = scan(team_name)  #TODO add try/catch for scan errors
        except Exception as ignoredexception:
            print("Ignoring exception in generating csv")
            print(ignoredexception)


    dnss = [] #flatten_d_dict([],'Team')
    dnss = flatten_d_dict({teamname: results[teamname]['dns'] for teamname in results}, 'Team')
    eips = flatten_d_dict({teamname: results[teamname]['eip'] for teamname in results}, 'Team')
    tlds = flatten_d_dict({teamname: results[teamname]['tld'] for teamname in results}, 'Team')
    scan_time = max([results[i]["time"] for i in results])

    resp = make_response(render_template('allteams.csv',
                                         dnss=dnss,
                                         tlds=tlds,
                                         eips=eips,
                                         scan_time=scan_time))
    resp.headers['Content-type'] = 'text/csv'
    resp.headers['Content-Disposition'] = 'attachment; filename=allteams.csv'
    return resp


@APP.route('/api/csv/<string:team_name>')
@CACHE.cached(timeout=APICACHETIME)
def teamcsv(team_name):
    """ Return a result set for the team in csv"""

    if team_name not in APP.config['TEAMNAMES']:
        return render_template("error.html",
                               teamnames=APP.config['TEAMNAMES'],
                               error="No such team")

    scanresults = scan(team_name)  #TODO add try/catch for scan errors

    dnss = scanresults["dns"]
    tlds = scanresults["tld"]
    eips = scanresults["eip"]
    scantime = scanresults["time"]

    resp = make_response(render_template('team.csv',
                                         teamnames=APP.config['TEAMNAMES'],
                                         dnss=dnss,
                                         tlds=tlds,
                                         eips=eips,
                                         team_name=team_name,
                                         scan_time=scantime))

    resp.headers['Content-type'] = 'text/csv'
    resp.headers['Content-Disposition'] = 'attachment; filename=' + team_name + '.csv'
    return resp

@APP.route('/team/<string:team_name>')
@CACHE.cached(timeout=UICACHETIME)
def team(team_name):
    """ Displays a (potentially cached) version of a scan of
    the DNS results from a team, provided as input. """

    if team_name not in APP.config['TEAMNAMES']:
        return render_template("error.html",
                               teamnames=APP.config['TEAMNAMES'],
                               error="No such team")

    scanresults = scan(team_name)  #TODO add try/catch for scan errors

    dnss = scanresults["dns"]
    tlds = scanresults["tld"]
    eips = scanresults["eip"]
    scantime = scanresults["time"]

    return render_template('team.html',
                           teamnames=APP.config['TEAMNAMES'],
                           dnss=dnss,
                           tlds=tlds,
                           eips=eips,
                           team_name=team_name,
                           scan_time=scantime)


if __name__ == "__main__":
    # APP.run(debug=True)
    loadconfig()
    APP.run(host='0.0.0.0', port='5000', debug=False)
