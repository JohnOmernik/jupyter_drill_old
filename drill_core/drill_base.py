#!/usr/bin/python

import requests
import socket
import json
from getpass import getpass
import sys
import os
import time
from IPython.core.magic import (Magics, magics_class, line_magic, cell_magic, line_cell_magic)
from requests.packages.urllib3.exceptions import SubjectAltNameWarning, InsecureRequestWarning
from requests_toolbelt.adapters import host_header_ssl
requests.packages.urllib3.disable_warnings(SubjectAltNameWarning)
from collections import OrderedDict
from IPython.core.display import HTML

#import IPython.display
from IPython.display import display_html, display, Javascript, FileLink, FileLinks, Image
import ipywidgets as widgets
import pandas as pd

@magics_class
class Drill(Magics):
    # Static Variables
    myip = None
    mysession = None
    drill_connected = False
    drill_pass = ""

    debug = False

    # Variables Dictionary
    drill_opts = {}

    # Option Format: [ Value, Description]

    # Pandas Variables
    drill_opts['pd_display_idx'] = [False, "Display the Pandas Index with output"]
    drill_opts['pd_replace_crlf'] = [True, "Replace extra crlfs in outputs with String representations of CRs and LFs"]
    drill_opts['pd_max_colwidth'] = [50, 'Max column width to display']
    drill_opts['pd_display.max_rows'] = [1000, 'Number of Max Rows']
    drill_opts['pd_display.max_columns'] = [None, 'Max Columns']


    pd.set_option('display.max_columns', drill_opts['pd_display.max_columns'][0])
    pd.set_option('display.max_rows', drill_opts['pd_display.max_rows'][0])
    pd.set_option('max_colwidth', drill_opts['pd_max_colwidth'][0])

    # Get Env items (User and/or Base URL)
    try:
        tuser = os.environ['JPY_USER']
    except:
        tuser = ''
    try:
        turl = os.environ['DRILL_BASE_URL']
    except:
        turl = ""

    # Drill specific variables
    drill_opts['drill_user'] = [tuser, "User to connect with drill - Can be set via ENV Var: JPY_USER otherwise will prompt"]
    drill_opts['drill_base_url'] = [turl, "URL to connect to Drill server. Can be set via ENV Var: DRILL_BASE_URL"]
    drill_opts['drill_base_url_host'] = ["", "Hostname of drill connection derived from drill_base_url"]
    drill_opts['drill_base_url_port'] = ["", "Port of drill connection derived from drill_base_url"]
    drill_opts['drill_base_url_scheme'] = ["", "Scheme of drill connection derived from drill_base_url"]

    drill_opts['drill_pin_to_ip'] = [False, "Obtain an IP from the name and connect directly to that IP"]
    drill_opts['drill_pinned_ip'] = ["", "IP of pinned connection"]
    drill_opts['drill_rewrite_host'] = [False, "When using Pin to IP, rewrite the host header to match the name of base_url"]
    drill_opts['drill_inc_port_in_rewrite'] = [False, "When rewriting the host header, include :%port% in the host header"]
    drill_opts['drill_headers'] = [{}, "Customer Headers to use for Drill connections"]
    drill_opts['drill_url'] = ['', "Actual URL used for connection (base URL is the URL that is passed in as default"]
    drill_opts['drill_verify'] = ['/etc/ssl/certs/ca-certificates.crt', "Either the path to the CA Cert validation bundle or False for don't verify"]
    drill_opts['drill_ignore_ssl_warn'] = [False, "Supress SSL warning upon connection - Not recommended"]



    # Class Init function - Obtain a reference to the get_ipython()
    def __init__(self, shell, drill_pin_to_ip=False, drill_rewrite_host=False,*args, **kwargs):
        super(Drill, self).__init__(shell)
        self.myip = get_ipython()
        self.drill_opts['drill_pin_to_ip'][0] = drill_pin_to_ip
        self.drill_opts['drill_rewrite_host'][0] = drill_rewrite_host

    def retStatus(self):

        print("Current State of Drill Interface:")
        print("")
        print("{: <30} {: <50}".format(*["Connected:", str(self.drill_connected)]))
        print("{: <30} {: <50}".format(*["Debug Mode:", str(self.debug)]))

        print("")
        print("Display Properties:")
        print("-----------------------------------")
        for k, v in self.drill_opts.items():
            if k.find("pd_") == 0:
                try:
                    t = int(v[1])
                except:
                    t = v[1]
                if v[0] is None:
                    o = "None"
                else:
                    o = v[0]
                myrow = [k, o, t]
                print("{: <30} {: <50} {: <20}".format(*myrow))
                myrow = []


        print("")
        print("Drill Properties:")
        print("-----------------------------------")
        for k, v in self.drill_opts.items():
            if k.find("drill_") == 0:
                if v[0] is None:
                    o = "None"
                else:
                    o = str(v[0])
                myrow = [k, o, v[1]]
                print("{: <30} {: <50} {: <20}".format(*myrow))
                myrow = []


    def setvar(self, line):
        pd_set_vars = ['pd_display.max_columns', 'pd_display.max_rows', 'pd_max_colwidth']
        allowed_opts = pd_set_vars + ['pd_replace_crlf', 'pd_display_idx', 'drill_base_url', 'drill_verify', 'drill_pin_to_ip', 'drill_rewrite_host', 'drill_ignore_ssl_warn', 'drill_inc_port_in_rewrite']

        tline = line.replace('set ', '')
        tkey = tline.split(' ')[0]
        tval = tline.split(' ')[1]
        if tval == "False":
            tval = False
        if tval == "True":
            tval = True
        if tkey in allowed_opts:
            self.drill_opts[tkey][0] = tval
            if tkey in pd_set_vars:
                try:
                    t = int(tval)
                except:
                    t = tval
                pd.set_option(tkey.replace('pd_', ''), t)
        else:
            print("You tried to set variable: %s - Not in Allowed options!" % tkey)


    def disconnectDrill(self):
        if self.drill_connected == True:
            print("Disconnected Drill Session from %s" % self.drill_opts['drill_url'][0])
        else:
            print("Drill Not Currently Connected - Resetting All Variables")
        self.mysession = None
        self.drill_pass = None
        self.drill_connected = False
        self.drill_opts['drill_url'][0] = ''
        self.drill_opts['drill_base_url_host'][0] = ''
        self.drill_opts['drill_base_url_port'][0] = ''
        self.drill_opts['drill_base_url_scheme'][0] = ''
        self.drill_opts['drill_pinned_ip'][0] = ''
        self.drill_opts['drill_headers'][0] = {}





    def connectDrill(self, prompt=False):
        global tpass
        if self.drill_connected == False:
            if prompt == True or self.drill_opts['drill_user'][0] == '':
                print("User not specified in JPY_USER or user override requested")
                tuser = input("Please type user name if desired: ")
                self.drill_opts['drill_user'][0] = tuser
            print("Connecting as user %s" % self.drill_opts['drill_user'][0])
            print("")

            if prompt == True or self.drill_opts['drill_base_url'][0] == '':
                print("Drill Base URL not specified in DRILL_BASE_URL or override requested")
                turl = input("Please type in the full Drill URL: ")
                self.drill_opts['drill_base_url'][0] = turl
            print("Connecting to Drill URL: %s" % self.drill_opts['drill_base_url'][0])
            print("")
            myurl = self.drill_opts['drill_base_url'][0]
            ts1 = myurl.split("://")
            self.drill_opts['drill_base_url_scheme'][0] = ts1[0]
            t1 = ts1[1]
            ts2 = t1.split(":")
            self.drill_opts['drill_base_url_host'][0] = ts2[0]
            self.drill_opts['drill_base_url_port'][0] = ts2[1]

            print("Please enter the password you wish to connect with:")
            tpass = ""
            self.myip.ex("from getpass import getpass\ntpass = getpass(prompt='Drill Connect Password: ')")
            tpass = self.myip.user_ns['tpass']

            self.drill_pass = tpass
            self.myip.user_ns['tpass'] = ""

            if self.drill_opts['drill_ignore_ssl_warn'][0] == True:
                print("Warning: Setting session to ignore SSL warnings - Use at your own risk")
                requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            result = -1
            result = self.authDrill()
            if result == 0:
                self.drill_connected = True
                print("%s - Drill Connected!" % self.drill_opts['drill_url'][0])
            else:
                print("Connection Error - Perhaps Bad Usename/Password?")

        else:
            print("Drill is already connected - Please type %drill for help on what you can you do")

        if self.drill_connected != True:
            self.disconnectDrill()

    def runQuery(self, query):
        if query.find(";") >= 0:
            print("WARNING - Do not type a trailing semi colon on queries, your query will fail (like it probably did here)")

        if self.drill_connected == True:
            url = self.drill_opts['drill_url'][0] + "/query.json"
            payload = {"queryType":"SQL", "query":query}
            cur_headers = self.drill_opts['drill_headers'][0]
            cur_headers["Content-type"] = "application/json"
            starttime = int(time.time())
            r = self.mysession.post(url, data=json.dumps(payload), headers=cur_headers, verify=self.drill_opts['drill_verify'][0])
            endtime = int(time.time())
            query_time = endtime - starttime
            return r, query_time

    def authDrill(self):

        self.mysession = None
        self.mysession = requests.Session()
        self.mysession.allow_redirects = False
        if self.drill_opts['drill_pin_to_ip'][0] == True:
                self.drill_opts['drill_pinned_ip'][0] = self.getipurl(self.drill_opts['drill_base_url'][0])
                print("")
                print("Pinning to IP for this session: %s" % self.drill_opts['drill_pinned_ip'][0])
                print("")
                self.drill_opts['drill_url'][0] = "%s://%s:%s" % ( self.drill_opts['drill_base_url_scheme'][0],  self.drill_opts['drill_pinned_ip'][0] ,  self.drill_opts['drill_base_url_port'][0])
                if self.drill_opts['drill_rewrite_host'][0] == True:
                    self.mysession.mount("https://", host_header_ssl.HostHeaderSSLAdapter())
                    if self.drill_opts['drill_inc_port_in_rewrite'][0] == True:
                        self.drill_opts['drill_headers'][0]['host'] = self.drill_opts['drill_base_url_host'][0] + ":" + self.drill_opts['drill_base_url_port'][0]
                    else:
                        self.drill_opts['drill_headers'][0]['host'] = self.drill_opts['drill_base_url_host'][0]
                    if self.debug:
                        print("Headers in connectDrill: %s" % self.drill_opts['drill_headers'][0])
        else:
            self.drill_opts['drill_url'][0] = self.drill_opts['drill_base_url'][0]

        myurl = self.drill_opts['drill_url'][0] + "/j_security_check"
        if self.debug:
            print("")
            print("Connecting URL: %s" % myurl)
            print("")
        login = {'j_username': self.drill_opts['drill_user'][0], 'j_password': self.drill_pass}
        result = -1
        if self.debug:
            print("")
            print("Headers in authDrill: %s" % self.drill_opts['drill_headers'][0])
            print("")
        if self.debug:
            print("Adapters: %s" % self.mysession.adapters)
        r = self.mysession.post(myurl, allow_redirects=False, data=login, headers=self.drill_opts['drill_headers'][0], verify=self.drill_opts['drill_verify'][0])

        if r.status_code == 200:
            if r.text.find("Invalid username/password credentials") >= 0:
                result = -2
                raise Exception("Invalid username/password credentials")
            elif r.text.find('<li><a href="/logout">Log Out (') >= 0:
                pass
                result = 0
            else:
                raise Exception("Unknown HTTP 200 Code: %s" % r.text)
        elif r.status_code == 303:
            pass
            result = 0
        else:
            raise Exception("Status Code: %s - Error" % r.status_code)
        return result

    def displayHelp(self):
        print("jupyter_drill is a interface that allows you to use the magic function %drill to interact with an Apache Drill installation.")
        print("")
        print("jupyter_drill has two main modes %drill and %%drill")
        print("%drill is for interacting with a Drill installation, connecting, disconnecting, seeing status, etc")
        print("%%drill is for running queries and obtaining results back from the Drill cluster")
        print("")
        print("%drill functions available")
        print("###############################################################################################")
        print("")
        print("{: <30} {: <80}".format(*["%drill", "This help screen"]))
        print("{: <30} {: <80}".format(*["%drill status", "Print the status of the Drill connection and variables used for output"]))
        print("{: <30} {: <80}".format(*["%drill connect", "Initiate a connection to the Drill cluster, attempting to use the ENV variables for Drill URL and Drill Username"]))
        print("{: <30} {: <80}".format(*["%drill connect alt", "Initiate a connection to the Drill cluster, but prompt for Username and URL regardless of ENV variables"]))
        print("{: <30} {: <80}".format(*["%drill disconnect", "Disconnect an active Drill connection and reset connection variables"]))
        print("{: <30} {: <80}".format(*["%drill set %variable% %value%", "Set the variable %variable% to the value %value%"]))
        print("{: <30} {: <80}".format(*["%drill debug", "Sets an internal debug variable to True (False by default) to see more verbose info about connections"]))
        print("")
        print("Running queries with %%drill")
        print("###############################################################################################")
        print("")
        print("When running queries with %%drill, %%drill will be on the first line of your cell, and the next line is the query you wish to run. Example:")
        print("")
        print("%%drill")
        print("select * from `dfs`.`root`.`mytable`")
        print("")
        print("Some query notes:")
        print("- If the number of results is less than pd_display.max_rows, then the results we be diplayed in your notebook")
        print("- You can change pd_display.max_rows with %drill set pd_display.max_rows 2000")
        print("- The results, regardless of display will be place in a Pandas Dataframe variable called prev_drill")
        print("- prev_drill is overwritten every time a successful query is run. If you want to save results assign it to a new variable")



    @line_cell_magic
    def drill(self, line, cell=None):
        if cell is None:
            line = line.replace("\r", "")
            if line == "":
                self.displayHelp()
            elif line.lower() == "status":
                self.retStatus()
            elif line.lower() == "debug":
                print("Toggling Debug from %s to %s" % (self.debug, not self.debug))
                self.debug = not self.debug
            elif line.lower() == "disconnect":
                self.disconnectDrill()
            elif line.lower() == "connect alt":
                self.connectDrill(True)
            elif line.lower() == "connect":
                self.connectDrill(False)
            elif line.lower() .find('set ') == 0:
                self.setvar(line)
            else:
                print("I am sorry, I don't know what you want to do, try just %drill for help options")
        else:
            cell = cell.replace("\r", "")
            if self.drill_connected == True:
                res, qtime = self.runQuery(cell)
                if res == "notconnected":
                    pass
                else:
                    if res.status_code == 200:
                        if res.text.find("Invalid username/password credentials.") >= 0:
                            print("It looks like your Drill Session has expired, please run %drill connect to resolve")
                            self.disconnectDrill()
                            self.myip.set_next_input("%drill connect")
                        else:
                            try:
                                jrecs = json.loads(res.text, object_pairs_hook=OrderedDict)
                            except:
                                print("Error loading: %s " % res.text)
                            cols = jrecs['columns']
                            myrecs = jrecs['rows']
                            df = pd.read_json(json.dumps(myrecs))
                            df = df[cols]

                            self.myip.user_ns['prev_drill'] = df
                            mycnt = len(df)
                            print("%s Records in Approx %s seconds" % (mycnt,qtime))
                            print("")
                            #button = widgets.Button(description="Cur Results")
                            #button.on_click(self.myip.user_ns['drill_edwin_class'].resultsNewWin)
                            #display(button)

                            if mycnt <= self.drill_opts['pd_display.max_rows'][0]:
                                if self.debug:
                                    print("Testing max_colwidth: %s" %  pd.get_option('max_colwidth'))
                                display(HTML(df.to_html(index=self.drill_opts['pd_display_idx'][0])))
                            else:
                                print("Number of results (%s) greater than pd_display_max(%s)" % (mycnt, self.drill_opts['pd_display.max_rows'][0]))


                    else:
                        print("Error Returned - Code: %s" % res.status_code)
                        emsg = json.loads(res.text, object_pairs_hook=OrderedDict)
                        print("Error Text:\n%s" % emsg['errorMessage'])
            else:
                print("Drill is not connected: Please see help at %drill  - To Connect: %drill connect")

    #Helper Functions

    def getipurl(self, url):
        ts1 = url.split("://")
        scheme = ts1[0]
        t1 = ts1[1]
        ts2 = t1.split(":")
        host = ts2[0]
        port = ts2[1]
        try:
            ip = socket.gethostbyname(host)
        except:
            print("Failure on IP Lookup - URL: %s Host: %s Port: %s" % (url, host, port))
        return ip



    #Display Only functions


    def replaceHTMLCRLF(self, instr):
        gridhtml = instr.replace("<CR><LF>", "<BR>")
        gridhtml = gridhtml.replace("<CR>", "<BR>")
        gridhtml = gridhtml.replace("<LF>", "<BR>")
        gridhtml = gridhtml.replace("&lt;CR&gt;&lt;LF&gt;", "<BR>")
        gridhtml = gridhtml.replace("&lt;CR&gt;", "<BR>")
        gridhtml = gridhtml.replace("&lt;LF&gt;", "<BR>")
        return gridhtml
    def resultsNewWin(self, b):

        max_col = pd.get_option('max_colwidth')
        max_rows = pd.get_option('display.max_rows')

        pd.set_option('max_colwidth', 100000)
        pd.set_option('display.max_rows', None)

        df = self.myip.user_ns['prev_drill']

        gridhtml = df.to_html(index=self.pd_display_idx)
        if self.pd_replace_crlf == True:
            outhtml = self.replaceHTMLCRLF(gridhtml)
        else:
            outhtml = gridhtml

        window_options = "toolbar=no, location=no, directories=no, status=no, menubar=no, scrollbars=yes, resizable=yes, width=1024, height=800, top=0, left=0"
        base = """var win = window.open("", "&~&", "*~*");
        win.document.body.innerHTML = `%~%`;
        """
        JS = base.replace('%~%', outhtml)
        JS = JS.replace('&~&', "Current Results")
        JS = JS.replace('*~*', window_options)

        j = Javascript(JS)
        display(j)

        pd.set_option('max_colwidth', max_col)
        pd.set_option('display.max_rows', max_rows)
