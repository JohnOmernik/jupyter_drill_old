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
    session = None
    drill_connected = False
    drill_pass = ""

    # Other Variables Dictionary
    drill_opts = {}

    # Option Format: [ Value, Description]
    drill_opts['pd_display_idx'] = [False, "Display the Pandas Index with output"]
    drill_opts['pd_replace_crlf'] = [True, "Replace extra crlfs in outputs with String representations of CRs and LFs"]
    drill_opts['pd_max_colwidth'] = [50, 'Max column width to display']
    drill_opts['pd_display.max_rows'] = [1000, 'Number of Max Rows']
    drill_opts['pd_display.max_columns'] = [None, 'Max Columns']

    pd.set_option('display.max_columns', drill_opts['pd_display.max_columns'][0])
    pd.set_option('display.max_rows', drill_opts['pd_display.max_rows'][0])
    pd.set_option('max_colwidth', drill_opts['pd_max_colwidth'][0])




    drill_opts['drill_host'] = ['', "Not sure"]
    try:
        tuser = os.environ['JPY_USER']
    except:
        tuser = ''
    drill_opts['drill_user'] = [tuser, "User to connect with drill - Can be set via ENV Var: JPY_USER otherwise will prompt"]
    try:
        turl = os.environ['DRILL_BASE_URL']
    except:
        turl = ""
    drill_opts['drill_base_url'] = [turl, "URL to connect to Drill server. Can be set via ENV Var: DRILL_BASE_URL"]
    drill_opts['drill_pin_to_ip'] = [True, "Obtain an IP from the name and connect directly to that IP"]
    drill_opts['drill_headers'] = [{}, "Customer Headers to use for Drill connections"]
    drill_opts['drill_url'] = ['', "Actual URL used for connection (base URL is the URL that is passed in as default"]
    drill_opts['drill_verify'] = ['/etc/ssl/certs/ca-certificates.crt', "Either the path to the CA Cert validation bundle or False for don't verify"]


    def setvar(self, line):
        pd_set_vars = ['pd_display.max_columns', 'pd_display.max_rows', 'pd_max_colwidth']
        allowed_opts = pd_set_vars + ['pd_replace_crlf', 'pd_display_idx', 'drill_base_url', 'drill_verify', 'drill_pin_to_ip']

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
            

    def __init__(self, shell, *args, **kwargs):
        super(Drill, self).__init__(shell)
        self.myip = get_ipython()

    def retStatus(self):
        print("Current State of Drill Interface:")
        print("Connected: %s" % self.drill_connected)
        print("")
        print("Display Properties:")
        for k, v in self.drill_opts.items():
            if k.find("pd_") == 0:
                try:
                    t = int(v[1])
                except:
                    t = v[1]
                print("%s: %s\t\t\t\t%s" % (k, v[0], t))


        print("")
        print("Drill Properties:")
        for k, v in self.drill_opts.items():
            if k.find("drill_") == 0:
                print("%s: %s\t\t\t\t%s" % (k, v[0], v[1]))

    def disconnectDrill(self):
        if self.drill_connected == True:
            print("Disconnected Drill Session from %s" % self.drill_opts['drill_url'][0])
            self.session = None
            self.drill_pass = None
            self.drill_connected = False
            self.drill_opts['drill_url'][0] = ''
        else:
            print("Drill Not Currently Connected")

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

            print("Please enter the password you wish to connect with:")
            tpass = ""
            self.myip.ex("from getpass import getpass\ntpass = getpass(prompt='Drill Connect Password: ')")
            tpass = self.myip.user_ns['tpass']
            self.session = requests.Session()

            if self.drill_opts['drill_pin_to_ip'][0] == True:
                tipurl = self.getipurl(self.drill_opts['drill_base_url'][0])
                print("")
                print("Pinning to IP for this session: %s" % tipurl)
                print("")
                self.drill_opts['drill_url'][0] = tipurl
                self.session.mount(tipurl, host_header_ssl.HostHeaderSSLAdapter())
                self.drill_opts['drill_verify'][0] = False
                requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            else:
                self.drill_opts['drill_url'][0] = self.drill_opts['drill_base_url'][0]
            self.drill_pass = tpass
            self.myip.user_ns['tpass'] = ""
            try:
                self.session = self.authDrill()
                self.drill_connected = True
                print("%s - Drill Connected!" % self.drill_opts['drill_url'][0])
            except:
                print("Connection Error - Perhaps Bad Usename/Password?")

        else:
            print("Drill is already connected - Please type %drill for help on what you can you do")



    def runQuery(self, query):
        if query.find(";") >= 0:
            print("WARNING - Do not type a trailing semi colon on queries, your query will fail (like it probably did here)")

        if self.drill_connected == True:
            url = self.drill_opts['drill_url'][0] + "/query.json"
            payload = {"queryType":"SQL", "query":query}
            cur_headers = self.drill_opts['drill_headers'][0]
            cur_headers["Content-type"] = "application/json"
            starttime = int(time.time())
            r = self.session.post(url, data=json.dumps(payload), headers=cur_headers, verify=self.drill_opts['drill_verify'][0])
            endtime = int(time.time())
            query_time = endtime - starttime
            return r, query_time

    def authDrill(self):
        url = self.drill_opts['drill_url'][0] + "/j_security_check"
        login = {'j_username': self.drill_opts['drill_user'][0], 'j_password': self.drill_pass}

        r = self.session.post(url, data=login, headers=self.drill_headers, verify=self.drill_opts['drill_verify'][0])
        if r.status_code == 200:
            if r.text.find("Invalid username/password credentials") >= 0:
                raise Exception("Invalid username/password credentials")
            elif r.text.find('<li><a href="/logout">Log Out (') >= 0:
                pass
            else:
                raise Exception("Unknown HTTP 200 Code: %s" % r.text)
        else:
            raise Exception("Status Code: %s - Error" % r.status_code)
        return self.session



    @line_cell_magic
    def drill(self, line, cell=None):
        if cell is None:
            line = line.replace("\r", "")
            if line == "":
                print("Help with Drill Functions")
                print("%drill            - This Help")
                print("%drill connect    - Connect to your instance of Drill") 
                print("%drill connect alt   - Connect to a different drill cluster or use a different user (will prompt)")
                print("%drill status     - Show the Connection Status of Drill")
                print("%drill disconnect - Disconnect from your instance of Drill")
                print("")
                print("Run Drill Queries")
                print("%%drill")
                print("select * from your table")
                print("")
                print("Ran with two % and a query, it queries a table and returns a df")
                print("The df is displayed but also stored in variable called prev_drill")
                print("")
            elif line.lower() == "status":
                self.retStatus()
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
        ip = socket.gethostbyname(host)
        self.drill_host = host
        self.drill_ip = ip
        ipurl = "%s://%s:%s" % (scheme, ip, port)
        self.drill_headers = {}
        #self.drill_headers = {"Host": self.drill_host}
        return ipurl


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
