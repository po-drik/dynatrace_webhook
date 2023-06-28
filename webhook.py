# -*- coding: utf-8 -*-
# Required Libraries.
from __future__ import print_function
from flask import Flask, request, flash, render_template
from flask import Markup
from flask_basicauth import BasicAuth
#from datetime import datetime
from datetime import timedelta
from os import listdir
from os.path import isfile, join
from twilio.rest import Client
import getpass
import sys
import os
import re
import datetime
import json
import socket
import timeit
import logging
import subprocess
import requests
import traceback
import urllib3

#######################
# Dynatrace Webhook API Custom Integration 
# based on Flask, a Python Web Microframework.
# This sample application receives a JSON Payload 
# and calls an executable on the OS with parameters, 
# it also sends an SMS and finally posts the results
# in the problem comments in Dynatrace for collaboration.
#######################

# Uptime variable
start_time = timeit.default_timer()

urllib3.disable_warnings()

# Problems received variable
prob_count = 0

# API Endpoints 
API_ENDPOINT_PROBLEMS = "/api/v2/problems"
UI_PROBLEM_DETAIL_BY_ID = "/#problems/problemdetails;pid="

# Time intervals to poll prob_count via API
RELATIVETIMES = ['1h', '2h', '6h', '1d', '1w', '1m']

# JSON Files in memory
PROBLEMS_SENT = {}

# Read Configuration and assign the variables
config = json.load(open('config.json'))

# Github repository (fork me!!)
GITHUB_REPO = config['github']['repository']

# Tenant variables
TENANT_HOST = config['dynatrace']['tenant']
API_TOKEN = config['dynatrace']['api_token']

# Basic Authorization
USERNAME = config['webhook']['username']
PASSWORD = config['webhook']['password']

# Let the Microservice listen to all interfaces 
# to the port of your choice with 0.0.0.0
WEBHOOK_INTERFACE = config['webhook']['interface']
WEBHOOK_PORT = config['webhook']['port']
WEBHOOK_USERNAME = getpass.getuser()

# Use proxies when behind a firewall
PROXY_CONFIGURATION = config['proxies']['active']

# Program to call with the notification
INCIDENT_NOTIFICATION = config['incident_notification']['active']
INCIDENT_HANDLER = config['incident_notification']['script']

SMS_NOTIFICATION = config['sms_notification']['active']
TWILIO_ACCOUNT = config['sms_notification']['twilio_account']
TWILIO_TOKEN = config['sms_notification']['twilio_token']
TWILIO_NUMBER = config['sms_notification']['twilio_number']
TO_NUMBER = config['sms_notification']['to_number']

LOGFILE = config['log_file']
LOG_DIR = config['log_dir']

# Directory where the received JSON Problems are saved
DIR_RECEIVED = config['dir_received']
# Directory where the sent Problems are saved (full details of the problem)
DIR_SENT = config['dir_sent']

PROXIES = {
    "http"  : config['proxies']['http_proxy'],
    "https" : config['proxies']['https_proxy'],
    "ftp"   : config['proxies']['ftp_proxy']
}

def check_create_dir(dir_name):
    if not os.path.exists(dir_name):
        os.makedirs(dir_name)

# Logging configuration
# Create log directory at initialization
check_create_dir(LOG_DIR)
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', filename=LOG_DIR + '/' + LOGFILE,
                    level=logging.INFO)

# Add logging also to the console of the running program
logging.getLogger().addHandler(logging.StreamHandler())
# Set Twilio logging to warning. 
logging.getLogger("twilio").setLevel(logging.WARNING)
# Set server logging to debug. 
#logging.getLogger("waitress").setLevel(logging.DEBUG)
#logging.getLogger("werkzeug").setLevel(logging.DEBUG)


# Initiate Flask Microservice with basic authentication
app = Flask(__name__)
app.secret_key = "super_secret_key"
app.config['BASIC_AUTH_USERNAME'] = USERNAME
app.config['BASIC_AUTH_PASSWORD'] = PASSWORD

# Protect your entire site with basic access authentication,
# app.config['BASIC_AUTH_FORCE'] = True
basic_auth = BasicAuth(app)

# Flask listener for POST Method with authorization
@app.route('/', methods=['POST'])
@basic_auth.required
def handle_post():
    try:
        global prob_count 
        prob_count += 1
        problem_simple = json.loads(request.data)
        logging.info('Notification received from ' + request.remote_addr);
        
        # JSON Payload will be saved in a directory
        save_request(problem_simple)
        if "999" in problem_simple['ProblemID']:
            logging.info('Test message successfully received. No integration will be called')
            return "OK"

        # Integrations will be called
        call_integration(problem_simple['PID'])
        
    except Exception as e:
        logging.error("There was an error handling the Request")
        logging.error(traceback.format_exc())
    return "OK"


# Will return the uptime in seconds, minutes, hours and days
def get_uptime():
    return str(timedelta(seconds=timeit.default_timer() - start_time))


def break_dic_in_rows(values):
    row = ''
    for key, value in values.items():
        row += key + ':' + str(value) + '<br>'
    return row


def break_list_in_rows(values):
    row = ''
    for value in values:
        row += str(value) + '<br>'
    return row


def get_timestamp_to_date(millisec):
    if millisec < 0 :
        return 'still open'
    else: 
        sec = millisec / 1000
        return datetime.datetime.utcfromtimestamp(sec).strftime('%Y-%m-%d %H:%M:%S')


# Will return either a date, string, list or an html table
def get_proper_value(key, value):
    
    if 'problemId' == key:
        if value.endswith('V2'):
            value = value[:-2]
        return '<a target="_blank" href="{0}{1}{2}">{2}</a>'.format(TENANT_HOST, UI_PROBLEM_DETAIL_BY_ID, value)

    if 'time' in key.lower() and isinstance(value, int):
        return get_timestamp_to_date(value)
    
    if isinstance(value, dict):
        return break_dic_in_rows(value) 
    
    elif isinstance(value, (list, tuple)):
        if len(value) > 0:
            if isinstance(value[0], dict):
                return get_table_from_list(value)
            
            # List inside list
            elif isinstance(value[0], list): 
                return str(value)
            # List of strings
            elif isinstance(value[0], str):
                return break_list_in_rows(value)
            else: 
                return str(value)
        
        return str(value)
    else:
        return str(value)

def get_thead():
    global x
    if 'x' not in globals():
        x = '<thead class="sticky"><tr>'
    else:
        x = '<thead class="inner"><tr>'
        
    return x 

# Returns an HTML table from a dictionary
def get_table_from_list(items):
    rows = ''
    row  = 0
    for item in items:
        row += 1
        td = '<tr>'
        if row == 1:
            th = get_thead()

        for key, value in item.items():
            td += '<td>' + get_proper_value(key, value) + '</td>'
            if row == 1:
                if key == 'problemId':
                    th += '<td>Open ' + key + ' in Dynatrace</td>'
                else:
                    th += '<td>' + key + '</td>'
            
        td += '</tr>'
        if row == 1:
            th += '</tr></thead>'
            rows += th + '<tbody>' + td 
        else:
            rows += td
    return '<table class="sent">' + rows + '</tbody></table>'
    

def get_table():
    # TODO Get only the table when a problem comes. save it in memory and actualize it?
    if len(PROBLEMS_SENT.values()) == 0:
        return 'No problems polled nor received.'
    
    # Populate the table
    table = ''
    try:
        table = get_table_from_list(PROBLEMS_SENT.values())
    except Exception as e:
        logging.error("There was an error generating the html Table:" + str(e))
        logging.error(traceback.format_exc())
        
    return table


def get_buttons_from_relativetimes():
    buttons  = ''
    endpoint = TENANT_HOST + API_ENDPOINT_PROBLEMS
    apitoken = API_TOKEN.split('.')[2]
    for t in RELATIVETIMES:
        buttons += "<div><button onclick='pollProblems(\"{0}\",\"{1}\",\"{2}\")'>{2}</button></div>".format(endpoint, apitoken, t)
    return buttons


# Flask listener for GET Method
# with public access
@app.route('/', methods=['GET'])
def handle_get():
    time_option = request.args.get('relativeTime')
    
    flash(Markup("<h2>Python Flask Webhook endpoint</h2>"))
    flash(Markup("<div class=\"container\">"))
    flash(Markup("<div><button id=\"btn_usage\" onclick=\"showHideById('usage')\">Show usage</button></div>"))
    flash(Markup("<div><button id=\"btn_stats\" onclick=\"showHideById('stats')\">Show stats</button></div>"))
    flash(Markup("</div>"))
    flash(Markup("<div id=\"usage\" class=\"usage\">"))
    flash(Markup("{0}".format(get_usage_as_html())))
    flash(Markup("</div></div>"))
    flash(Markup("<div id=\"stats\" class=\"stats\">"))
    flash(Markup("<div class=\"container\">"))
    flash(Markup("<div class=\"item-2\">Documentation:</div>"))
    flash(Markup("<div class=\"item-2\"><a target=\"_blank\" href=\"{0}\">{0}</a></div></div>".format(GITHUB_REPO)))
    flash(Markup("<div class=\"container\">"))
    flash(Markup("<div class=\"item-2\">Dynatrace Environment:</div>"))
    flash(Markup("<div class=\"item-2\"><a target=\"_blank\" href=\"{0}\">{0}</a></div></div>".format(TENANT_HOST)))
    flash(Markup("<div class=\"container\">"))
    flash(Markup("<div class=\"item-2\">Flask Web Microservice:</div>"))
    flash(Markup("<div class=\"item-2\">https://{0}:{1}</div></div>".format(WEBHOOK_INTERFACE, WEBHOOK_PORT)))
    flash(Markup("<div class=\"container\">"))
    flash(Markup("<div class=\"item-2\">Received notifications:</div>"))
    flash(Markup("<div class=\"item-2\">{0}</div></div>".format(prob_count)))
    flash(Markup("<div class=\"container\">"))
    flash(Markup("<div class=\"item-2\">Path:</div>"))
    flash(Markup("<div class=\"item-2\">{0}</div></div>".format(os.getcwd())))
    flash(Markup("<div class=\"container\">"))
    flash(Markup("<div class=\"item-2\">Host:</div>"))
    flash(Markup("<div class=\"item-2\">{0}</div></div>".format(socket.gethostname())))
    flash(Markup("<div class=\"container\">"))
    flash(Markup("<div class=\"item-2\">User:</div>"))
    flash(Markup("<div class=\"item-2\">{0}</div></div>".format(WEBHOOK_USERNAME)))
    flash(Markup("<div class=\"container\">"))
    flash(Markup("<div class=\"item-2\">PID:</div>"))
    flash(Markup("<div class=\"item-2\">{0}</div></div>".format(os.getpid())))
    flash(Markup("<div class=\"container\">"))
    flash(Markup("<div class=\"item-2\">Uptime:</div>"))
    flash(Markup("<div class=\"item-2\">{0}</div></div></div>".format(get_uptime())))
    # TODO JQuery efect
    
    flash(Markup("<div class=\"container\">"))
    flash(Markup("<div class=\"item-x\">Poll the problems via API for the last:&nbsp;</div>"))
    flash(Markup(get_buttons_from_relativetimes()))
    flash(Markup("</div>"))
        
    if time_option:
        data = get_problemsfeed_by_time(time_option)
        flash(Markup("<br><button id=\"btn_table_poll\" onclick=\"showHideById('table_poll')\">Show table</button>"))
        flash(Markup("<div id=\"table_poll\" class=\"table_poll\">"))
        flash(Markup("<div>There were {0} problems found during the selected timeframe '{1}'</div>".format(
                len(data['problems']), time_option)))
        flash(Markup("<div><h3>Dynatrace has monitored the following entities in the last '{0}':</h3></div>".format(time_option)))
        flash(Markup("<div>APPLICATION:\t {:6}</div>".format(data['problems']['APPLICATION'])))
        flash(Markup("<div>SERVICE:\t {:6}</div>".format(data['problems']['SERVICES'])))
        flash(Markup("<div>INFRASTRUCTURE:\t {:6}</div>".format(data['problems']['INFRASTRUCTURE'])))
        flash(Markup(get_table_from_list(data['problems'])))
        flash(Markup("</div>"))
        
    flash(Markup("<br><button id=\"btn_table_saved\" onclick=\"showHideById('table_saved')\">Hide table</button>"))
    flash(Markup("<div id=\"table_saved\"><h3>Successfully sent problems</h3>"))
    flash(Markup("<div class=\"scroll_div\"><p>JSON files saved in {0}/{1}:</p>".format(os.getcwd(), DIR_SENT)))
    flash(Markup(get_table()))
    flash(Markup("</div></div>"))
    return render_template('index.html')


def get_usage_as_html():
    str_with_divs = ''
    div_container = ''
    for line in get_usage_as_string().splitlines():
        if '  = ' in line:
            replaced_line = re.sub('=', '</div><div class="item-3">', line)
            div_container = '<div class="container">'
            line_with_div = '<div class="item-2">' + replaced_line + '</div>'
        else:
            div_container = '<div>'
            if '---' in line:
                line_with_div = '<hr>'
            else:
                line_with_div = line
        str_with_divs += div_container + line_with_div + '</div>'
    return str_with_divs


# For handling Tenants with an invalid SSL Certificate just set it to false.
def verifyRequest():
    return False


def handle_response_status(msg, response):
    if response.status_code != 200:
        err_msg = "There was an {0} error {1}. HTTP CODE[{2}] \n " \
                  "Response Payload:{3}".format(response.reason, msg, response.status_code, response.content)
        logging.error(err_msg)
        raise Exception(err_msg)


def getAuthenticationHeader():
    return {"Authorization": "Api-Token " + API_TOKEN}


def get_problemsfeed_by_time(time_option):
    msg = "fetching prob_count for '" + time_option + "' - " + API_ENDPOINT_PROBLEMS
    logging.info(msg)
    if PROXY_CONFIGURATION:
        response = requests.get(TENANT_HOST + API_ENDPOINT_PROBLEMS + "?from=now-" + time_option,
                                headers=getAuthenticationHeader(), verify=verifyRequest(), proxies=PROXIES)
    else:
        response = requests.get(TENANT_HOST + API_ENDPOINT_PROBLEMS + "?from=now-" + time_option,
                                headers=getAuthenticationHeader(), verify=verifyRequest())

    handle_response_status(msg, response)
    data = json.loads(response.text)
    logging.debug('Reponse content: ' + str(response.content))
    return data


def get_problem_by_id(problemid):
    msg = "fetching problem id " + str(problemid)
    logging.info(msg)
    response = requests.get(TENANT_HOST + API_ENDPOINT_PROBLEMS + '/' + problemid, headers=getAuthenticationHeader(),
                            verify=verifyRequest(), proxies=PROXIES)
    handle_response_status(msg, response)
    data = json.loads(response.text)
    logging.info("Problem ID " + problemid + " fetched")
    return data


def is_new_problem(problem):
    if problem['displayId'] in PROBLEMS_SENT:
        if PROBLEMS_SENT.get(problem['displayId'])['status'] == problem['status']:
            logging.info(
                "Problem {0} has already been submitted to the Incident Software. To do it again delete the file {0}.json in the directory {1}".format(problem['displayId'], DIR_SENT))
            return False
        else:
            return True
    # Problem is not in the Dictionary
    return True


def get_program_argument(problem_details):
    """
    In here you can make the mapping and translation of the different
    parameter values and attributes for the Incident Software of your desire
    """

    for evidence_details in problem_details['evidenceDetails']['details']:
        evType = evidence_details['evidenceType']

        if evType == 'EVENT':
            p_nr     = problem_details['displayId']
            p_svc    = evidence_details['displayName']
            p_entity = evidence_details['entity']['name']
            p_status = evidence_details['data']['status']
            impact   = problem_details['impactLevel']
            msg_dict = { "ProblemID": p_nr, "Status": p_status, "EntityName": p_entity, "DisplayName": p_svc }

        else:
            logging.info("Skipping {0} evidenceType. Details [{1}]".format(evType, evidence_details))
    
    return msg_dict


def post_incident_result_in_problem_comments(problem, return_code, error):
    p_nr = problem['problemId']
    logging.info('Problem {0} will be commented in Dynatrace'.format(p_nr))
    data = {}
    if error:
        data['comment'] = "The problem {0} could not been sent to the Incident Software. Return Code [{1}]".format(p_nr, return_code)
    else:
        data['comment'] = "The problem {0} has been sent to the Incident Software. Calls made: {1}".format(p_nr, len(return_code))

    data['user'] = WEBHOOK_USERNAME
    data['context'] = 'Incident Software Custom Integration'
    
    
    r = post_in_comments(problem, data);

    if r.status_code == 200:
        logging.info('Problem {0} was commented successfully in Dynatrace'.format(p_nr))
        logging.debug('Content:{1}'.format(p_nr, data))
    else:
        logging.error(
            'Problem {0} could not be commented in Dynatrace. Reason {1} - {2}. Content: {3}'.format(p_nr,
                                                                                                     r.reason,
                                                                                                     r.status_code,
                                                                                                     data))
    return

def post_in_comments(problem, data):
    # Define header
    headers = {'content-type': 'application/json', "Authorization": "Api-Token " + API_TOKEN}
    # Make POST Request
    r = requests.post(TENANT_HOST + API_ENDPOINT_PROBLEMS + "/" + problem['displayId'] + "/comments", json=data,
                      headers=headers, verify=verifyRequest())
    # Return response
    return r


# In this method are the integrations defined and called
def call_integration(problem_id):
    
    # Fetch all the details of the Problem
    problem_details = get_problem_by_id(problem_id)
        
    # Notify the incident software and comment the result in Dynatrace
    if INCIDENT_NOTIFICATION: 
        call_incident_software(problem_details)
    
    # Send an SMS message and comment in Dynatrace
    if SMS_NOTIFICATION: 
        call_sms_integration(problem_details)
    
    # Problems will be sent two times, when open and closed.
    # Update the dictionary e.g. when a Problem is closed. The problemNr is the key of the dictionary
    PROBLEMS_SENT[problem_details["displayId"]] = problem_details
    
    # Persist the sent notifications
    persist_problem(problem_details)
    return


def call_sms_integration(problem_details):
    
    # SMS Client initialized with the Twilio Account (SID and Auth-Token)
    sms_client = Client(TWILIO_ACCOUNT, TWILIO_TOKEN)
    
    level = problem_details["impactLevel"]
    p_nr =  problem_details["displayId"]
    pid = problem_details["problemId"]
    status = problem_details["status"]
    
    # change the "from_" number to your Twilio number and the "to" number
    # to the phone number you signed up for Twilio with, or upgrade your
    # account to send SMS to any phone number
    body = "Dynatrace notification - {0} problem ({1}) {5}. Open in Dynatrace:{2}{3}{4}".format(level.lower(), p_nr, 
                                                                                                TENANT_HOST, 
                                                                                                UI_PROBLEM_DETAIL_BY_ID, 
                                                                                                pid, status.lower())
    sms_client.messages.create(to=TO_NUMBER, from_=TWILIO_NUMBER, body=body)
     
    TO_NUMBER
    # Post SMS result in the comments
    data = {}
    data['comment'] = "Mobile number has been notified: {0}".format(anonymize_numer(TO_NUMBER))
    data['user'] = WEBHOOK_USERNAME
    data['context'] = 'Twilio Custom Integration'
    r = post_in_comments(problem_details, data)
    # Log to the console
    logging.info('{0}: {1} sent from {2}'.format(data['context'] , data['comment'], TWILIO_NUMBER))
    return

def anonymize_numer(number):
    return str(number[0:3] + '*****' + number[-4:])

def call_incident_software(problem_details):
    problem_nr = problem_details['displayId']

    argument_list = get_program_argument(problem_details)
    #arguments     = " ".join(str(x) for x in argument_list)
    arguments     = str(argument_list)
    #print(json.dumps(arguments, indent=2))

    #return_codes = []
    return_code = (subprocess.call([INCIDENT_HANDLER, arguments]))
    logging.info('Incident Software called for ProblemID [{0}] Return Code [{1}]'.format(str(problem_nr), return_code))

    return


# This will save the json notification in a directory
def save_request(data):
    if not os.path.exists(DIR_RECEIVED):
        os.makedirs(DIR_RECEIVED)
    try:
        problemnr = data['ProblemID']
        state = data['State']
        filename = problemnr + '-' + state + '.json'
        with open(DIR_RECEIVED + '/' + filename, 'w') as f:
            json.dump(data, f, ensure_ascii=False)
    except Exception as e:
        now = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
        logging.error("There was an error saving the json sent from Dynatrace")
        log_error = "save_request_error-" + now + ".json"

        with open(LOG_DIR + '/' + log_error, 'w') as f:
            json.dump(data, f, ensure_ascii=False)
    return

# Poll the errors
def poll_problems(time_option):
    logging.info("----------------------------------------------")
    logging.info("Polling problems for {0}{1} with Key'{2}' and relativeTime '{3}'".format(TENANT_HOST,
                                                                                           API_ENDPOINT_PROBLEMS,
                                                                                           API_TOKEN, time_option))
    try:
        data = get_problemsfeed_by_time(time_option)
        # Print the amount of errors and monitored entities.
        logging.info("There were {0} problems found during the selected timeframe '{1}'".format(
            len(data['problems']), time_option))
        logging.info("Dynatrace has monitored the following entities in the last '{0}':".format(time_option))

        app = 0
        inf = 0
        svc = 0

        for ent in data['problems']:
          if ent['impactLevel'] == "APPLICATION":
            app += 1
          elif ent['impactLevel'] == "SERVICES":
            svc += 1
          elif ent['impactLevel'] == "INFRASTRUCTURE":
            inf += 1

        logging.info("APPLICATION:\t {:6}".format(app))
        logging.info("SERVICES:\t {:6}".format(svc))
        logging.info("INFRASTRUCTURE:\t {:6}".format(inf))

        if (data and data['problems']):
            for problem_details in data['problems']:
                if is_new_problem(problem_details):
                    call_integration(problem_details['problemId'])
    except Exception as e:
        logging.error("There was an error polling the problems")
        logging.error(traceback.format_exc())
    return


def persist_problem(problem_details):
    check_create_dir(DIR_SENT)
    filename = DIR_SENT + '/' + problem_details["displayId"] + '.json'
    with open(filename, 'w') as f:
        json.dump(problem_details, f)


def load_problems():
    global PROBLEMS_SENT
    check_create_dir(DIR_SENT)
    jsonfiles = [f for f in listdir(DIR_SENT) if isfile(join(DIR_SENT, f))]
    for file in jsonfiles:
        with open(DIR_SENT + '/' + file, 'r') as f:
            problem_details = json.load(f)
            PROBLEMS_SENT[problem_details["displayId"]] = problem_details
            

def main():
    
    load_problems()
    
    logging.info("Dynatrace Custom Webhook Integration")
    command = ""
    printUsage = False
    if len(sys.argv) >= 2:
        command = sys.argv[1]
        
        if command == "run":
            logging.info("----------------------------------------------")
            logging.info("Starting the Flask Web Microservice")
            from waitress import serve
            serve(app, host=WEBHOOK_INTERFACE, port=WEBHOOK_PORT)

        elif command == "poll":
            if len(sys.argv) == 3:
                option = sys.argv[2]
                if option in RELATIVETIMES:
                    poll_problems(option)
                else:
                    printUsage = True

            elif len(sys.argv) == 2:
                poll_problems(RELATIVETIMES[0])
            else:
                printUsage = True
        else:
            printUsage = True
    else:
        printUsage = True

    if printUsage:
        doUsage(sys.argv)
    else:
        print("Bye")
    exit


def get_usage_as_string():
    return """
Dynatrace Custom Webhook Integration 
--------------------------------------------------------------------------------------------------------
Usage: webhook.py command [ option ]

  command:  help         = Prints this help screen.  
  command:  run          = Starts the web server.
  command:  poll         = Polls the API for any problems in the last hour and calls the Incident Software.
  command:  poll option  = Polls with relativeTime. Values: 1h(our), 2h, 6h, 1d(ay), 1w(eek), 1m(onth). Default: 1h
--------------------------------------------------------------------------------------------------------
"""


def doUsage(args):
    "Just printing Usage"
    usage = get_usage_as_string()
    print(usage)
    exit


# Start Main
if __name__ == "__main__": main()

