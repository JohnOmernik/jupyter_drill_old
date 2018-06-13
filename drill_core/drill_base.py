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
pd.set_option('display.max_columns', None)

@magics_class
class Drill(Magics):
    myip = None
    session = None
    drill_connected = False
    pd_display_idx = False
    pd_display_max = 1000
    pd_replace_crlf = True
    drill_host = ""
    drill_pinned_ip = ""
    drill_user = ""
    drill_pass = ""
    drill_base_url = ""
    drill_pin_to_ip = True
    drill_headers = {}

    def __init__(self, shell, *args, **kwargs):
        super(Drill, self).__init__(shell)
        self.myip = get_ipython()


    def retConnStatus(self):
        if self.drill_connected == True:
            print("Drill is currrently connected to %s" % self.drill_base_url)
        else:
            print("Drill is not connected")
    def disconnectDrill(self):
        if self.drill_connected == True:
            print("Disconnected Drill Session from %s" % self.drill_base_url)
            self.session = None
            self.drill_base_url = None
            self.drill_pass = None
            self.drill_connected = False
        else:
            print("Drill Not Currently Connected")

    def connectDrill(self):
        global tpass
        if self.drill_connected == False:
            try:
                tuser = os.environ['JPY_USER']
            except:
                raise Exception("Could not find user at ENV JPY_USER - Please use '%drill connect alt' to specify")
            print("Connecting as user %s" % tuser)

            try:
                turl = os.environ['DRILL_BASE_URL']
            except:
                raise Exception("No DRILL_BASE_URL specified in ENV - Please use '%drill connect alt' to specify")
            print("Connecting to Drill URL: %s" % turl)

            print("")
            print("Now, please enter the password you wish to connect with:")

            tpass = ""
            self.myip.ex("from getpass import getpass\ntpass = getpass(prompt='Drill Connect Password: ')")
            tpass = self.myip.user_ns['tpass']
            self.session = requests.Session()

            if self.drill_pin_to_ip == True:

                tipurl = self.getipurl(turl)
                print("")
                print("Pinning to IP for this session: %s" % tipurl)
                print("")
                self.drill_base_url = tipurl
                self.session.mount(tipurl, host_header_ssl.HostHeaderSSLAdapter())

            else:
                self.drill_base_url = turl
            self.drill_user = tuser
            self.drill_pass = tpass
            self.myip.user_ns['tpass'] = ""
            #try:
            if 1 == 1:
                self.session = self.authDrill()
                self.drill_connected = True
                print("%s - Drill Connected!" % self.drill_base_url)
            #except:
            #    print("Connection Error - Perhaps Bad Usename/Password?")

        else:
            print("Drill is already connected - Please type %drill for help on what you can you do")


    def connectDrillAlt(self):
        global tpass
        if self.drill_connected == False:
            try:
                tuser = os.environ['JPY_USER']
            except:
                tuser = ""
            print("Currently, the user is set to %s" % tuser)
            print("To use this user, just press enter at the prompt, otherwise type a different user name")
            tmp = input("Please type new user name if desired: ")
            if tmp != "":
                tuser = tmp
            try:
                turl = os.environ['DRILL_BASE_URL']
            except:
                turl = ""
            print("Currently the drill base url is set to %s" % turl)
            print("To use this URL, please press enter at the prompt, otherwise type a different url to connect with")
            tmpu = input("Please type a new URL if desired:")
            if tmpu != "":
                turl = tmpu
            print("Now, please enter the password you wish to connect with:")
            tpass = ""
            self.myip.ex("from getpass import getpass\ntpass = getpass(prompt='Drill Connect Password: ')")
            tpass = self.myip.user_ns['tpass']
            self.session = requests.Session()

            if self.drill_pin_to_ip == True:

                tipurl = self.getipurl(turl)
                print("")
                print("Provided Host: %s" % turl)
                print("")
                print("Pinning to IP for this session: %s" % tipurl)
                print("")
                self.drill_base_url = tipurl
                self.session.mount(tipurl, host_header_ssl.HostHeaderSSLAdapter())

            else:
                self.drill_base_url = turl
            self.drill_user = tuser
            self.drill_pass = tpass
            self.myip.user_ns['tpass'] = ""
            #try:
            if 1 == 1:
                self.session = self.authDrill()
                self.drill_connected = True
                print("%s - Drill Connected!" % self.drill_base_url)
            #except:
            #    print("Connection Error - Perhaps Bad Usename/Password?")

        else:
            print("Drill is already connected - Please type %drill for help on what you can you do")

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

    def runQuery(self, query):
        if query.find(";") >= 0:
            print("WARNING - Do not type a trailing semi colon on queries, your query will fail (like it probably did here)")
        if self.drill_pin_to_ip == True:
            verify = False
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        else:
            verify = "/etc/ssl/certs/ca-certificates.crt"

        if self.drill_connected == True:
            url = self.drill_base_url + "/query.json"
            payload = {"queryType":"SQL", "query":query}
            cur_headers = self.drill_headers
            cur_headers["Content-type"] = "application/json"
            starttime = int(time.time())
            r = self.session.post(url, data=json.dumps(payload), headers=cur_headers, verify=verify)
            endtime = int(time.time())
            query_time = endtime - starttime
            return r, query_time


    def authDrill(self):
        url = self.drill_base_url + "/j_security_check"
        login = {'j_username': self.drill_user, 'j_password': self.drill_pass}

        verify = "/etc/ssl/certs/ca-certificates.crt"

        if self.drill_pin_to_ip == True:
            verify = False
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        else:
            verify = "/etc/ssl/certs/ca-certificates.crt"

        r = self.session.post(url, data=login, headers=self.drill_headers, verify=verify)
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
                self.retConnStatus()
            elif line.lower() == "disconnect":
                self.disconnectDrill()
            elif line.lower() == "connect alt":
                self.connectDrillAlt()
            elif line.lower() == "connect":
                self.connectDrill()
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
                            button = widgets.Button(description="Cur Results")
                            button.on_click(self.myip.user_ns['drill_edwin_class'].resultsNewWin)
                            display(button)
                            if mycnt <= self.pd_display_max:
                                display(HTML(df.to_html(index=self.pd_display_idx)))
                            else:
                                print("Number of results (%s) greater than pd_display_max(%s) - Press button to see results in new window" % (mycnt, self.pd_display_max))


                    else:
                        print("Error Returned - Code: %s" % res.status_code)
                        emsg = json.loads(res.text, object_pairs_hook=OrderedDict)
                        print("Error Text:\n%s" % emsg['errorMessage'])
            else:
                print("Drill is not connected: Please see help at %drill  - To Connect: %drill connect")






