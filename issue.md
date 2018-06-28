# Issue in requests toolbelt as seen in Jupyter_Drill
The code for the issue below is seen in

https://github.com/johnomernik/jupyter_drill

## Setup


I have 3 Apache Drill bits. They are each their own webserver, but coordinate on queries. In my setup, each Drillbit has the same config, and certificates pointing to the name drillprod-prod.marathon.slaves.mesos running on port 20004. 
The connection URL would be https://drillprod-prod.marathon.slave.mesos:20004  You can see this in the drill_base_url variable. 

This is a nice setup because it allows me to have one name, create one certificate, and run multiple instances of Drill bits.  The name resolves to all three drillbits, and which ever is returned first is the IP address of the bit that Python will use. 

The issue that occurs is since I am using sessions with requests, the first request is a authentication request (using %drill connect magic function)  This creates a session, does the authentication, and keeps the session in the Drill class in my jupyter_drill module. It's important to keep session, not only for authentication, but for settings within in the data environment and to allow users to do things like "use schema" and have that SQL statement stick. 

The issue, is based on cache TTL, Python may or may not make another DNS request after the login, if the DNS returns a different IP address, then Python will connect there, and that Drillbit will NOT be aware of the session, losing settings, and forcing a relogin and bad user experience. 

## Approach to fix

First, let me say this out of the gate: the option to ignore certificate warnings is NOT acceptable. We need strong security here. 

To fix this, my thought process was to do a IP lookup at authentcation, get an IP Address from DNS, and then "pin" the session to that Drillbit.  This actually works pretty well from a logistics standpoint. My sessions no longer fail for no reason, and thus it fixed one problem, however, it introduced another problem: Certificate Naming.  

If I convert https://drillprod-prod.marathon.slave.mesos:20004 to https:192.168.0.103:20004 for my requests, that's very cool, however, my certificate (which is generated from a trusted internal CA, now causes a error due to mismatch. 

Yes, I can disable verification (I put that option in, not an option long term) And even then I still get warnings  (To which I put an option into surpress those warnings).  These are not solution, just something I put in to work with. 

I don't want to issue a certificate for every server, becuase the drillbits are started dynamically. Thus, I may run 3 drillbits today, and they run on Nodes 1, 4, and 6, and tomorrow they may be on 1, 2, and 8.  The name records are updated automagically by my orchestrator at startup.  So certificates persever means I have to generate a certificate that includes names for EVERY IP Adress I could run this on. Not an option. 

After lots of research, I stumbled across the HostHeaderSSLAdapter in requests_toolbelt:

https://github.com/requests/toolbelt/blob/master/requests_toolbelt/adapters/host_header_ssl.py#L38

Essentially, if I am reading this correctly, I should be able to use a URL for connection that has an IP instead of a name, but specify a Host header that will be used by the SSL stack to do the hostname verification. (If I am reading this wrong, please let me know)


This SHOULD work, but as you can see below, it does not. 



```python

# This can be included in a module Basic instantiation stuff. 
#import sys
#sys.path.append("/home/jomernik/jupyter_drill")
from plotly.offline import download_plotlyjs, init_notebook_mode, plot, iplot
init_notebook_mode(connected=True)
from drill_core import Drill
ip = get_ipython()
Drill = Drill(ip)
ip.register_magics(Drill)
```


<script>requirejs.config({paths: { 'plotly': ['https://cdn.plot.ly/plotly-latest.min']},});if(!window.Plotly) {{require(['plotly'],function(plotly) {window.Plotly=plotly;});}}</script>


### %drill debug toggles debug mode on and off.  %drill status shows the status of all the internal variables used for connection


```python
%drill debug
```

    Toggling Debug from False to True



```python
%drill status
```

    Current State of Drill Interface:
    
    Connected:                     False                                             
    Debug Mode:                    True                                              
    
    Display Properties:
    -----------------------------------
    pd_display_idx                 0                                                  Display the Pandas Index with output
    pd_replace_crlf                1                                                  Replace extra crlfs in outputs with String representations of CRs and LFs
    pd_max_colwidth                50                                                 Max column width to display
    pd_display.max_rows            1000                                               Number of Max Rows  
    pd_display.max_columns         None                                               Max Columns         
    
    Drill Properties:
    -----------------------------------
    drill_user                     jomernik                                           User to connect with drill - Can be set via ENV Var: JPY_USER otherwise will prompt
    drill_base_url                 https://drillprod-prod.marathon.slave.mesos:20004  URL to connect to Drill server. Can be set via ENV Var: DRILL_BASE_URL
    drill_base_url_host                                                               Hostname of drill connection derived from drill_base_url
    drill_base_url_port                                                               Port of drill connection derived from drill_base_url
    drill_base_url_scheme                                                             Scheme of drill connection derived from drill_base_url
    drill_pin_to_ip                False                                              Obtain an IP from the name and connect directly to that IP
    drill_pinned_ip                                                                   IP of pinned connection
    drill_rewrite_host             False                                              When using Pin to IP, rewrite the host header to match the name of base_url
    drill_inc_port_in_rewrite      False                                              When rewriting the host header, include :%port% in the host header
    drill_headers                  {}                                                 Customer Headers to use for Drill connections
    drill_url                                                                         Actual URL used for connection (base URL is the URL that is passed in as default
    drill_verify                   /etc/ssl/certs/ca-certificates.crt                 Either the path to the CA Cert validation bundle or False for don't verify
    drill_ignore_ssl_warn          False                                              Supress SSL warning upon connection - Not recommended


### My first connnection: Defaults
In this setup, I will be using defaults i.e. the DNS name of the drill cluster. 

This will work, and is designed to show, that from an SSL perspective, the connection WILL work, the certificate is valid and trusted by the notebook kernel, and no warnings are thrown.



```python
%drill connect
```

    Connecting as user jomernik
    
    Connecting to Drill URL: https://drillprod-prod.marathon.slave.mesos:20004
    
    Please enter the password you wish to connect with:
    
    Headers in authDrill: {}
    
    https://drillprod-prod.marathon.slave.mesos:20004 - Drill Connected!



```python
%%drill
use dfs.prod
```

    1 Records in Approx 1 seconds
    
    Testing max_colwidth: 50



<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th>ok</th>
      <th>summary</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>true</td>
      <td>Default schema changed to [dfs.prod]</td>
    </tr>
  </tbody>
</table>


So everything works. It's hard to show time passing, but eventually, I will try to run a query and it will fail because the session got routed to a different server. 


```python
%drill disconnect
```

    Disconnected Drill Session from https://drillprod-prod.marathon.slave.mesos:20004


### Pin to IP

The next step, I will set the variable drill_pin_to_ip to True. The full stack trace is below, but I think it's obvious that the issue that is occuring.

Essentially, the error

```
SSLError: HTTPSConnectionPool(host='192.168.0.103', port=20004): Max retries exceeded with url: /j_security_check (Caused by SSLError(CertificateError("hostname '192.168.0.103' doesn't match 'drillprod-prod.marathon.slave.mesos'",),))
```
Is saying that pinning to IP, and then connecting with that IP is problematic as the host header of the IP  makes it so the certificate assigned to drillprod-prod.marathon.slave.mesos doesn't match causing an SSL incompatibility. 


```python
%drill set drill_pin_to_ip True
```


```python
%drill status
```

    Current State of Drill Interface:
    
    Connected:                     False                                             
    Debug Mode:                    True                                              
    
    Display Properties:
    -----------------------------------
    pd_display_idx                 0                                                  Display the Pandas Index with output
    pd_replace_crlf                1                                                  Replace extra crlfs in outputs with String representations of CRs and LFs
    pd_max_colwidth                50                                                 Max column width to display
    pd_display.max_rows            1000                                               Number of Max Rows  
    pd_display.max_columns         None                                               Max Columns         
    
    Drill Properties:
    -----------------------------------
    drill_user                     jomernik                                           User to connect with drill - Can be set via ENV Var: JPY_USER otherwise will prompt
    drill_base_url                 https://drillprod-prod.marathon.slave.mesos:20004  URL to connect to Drill server. Can be set via ENV Var: DRILL_BASE_URL
    drill_base_url_host                                                               Hostname of drill connection derived from drill_base_url
    drill_base_url_port                                                               Port of drill connection derived from drill_base_url
    drill_base_url_scheme                                                             Scheme of drill connection derived from drill_base_url
    drill_pin_to_ip                True                                               Obtain an IP from the name and connect directly to that IP
    drill_pinned_ip                                                                   IP of pinned connection
    drill_rewrite_host             False                                              When using Pin to IP, rewrite the host header to match the name of base_url
    drill_inc_port_in_rewrite      False                                              When rewriting the host header, include :%port% in the host header
    drill_headers                  {}                                                 Customer Headers to use for Drill connections
    drill_url                                                                         Actual URL used for connection (base URL is the URL that is passed in as default
    drill_verify                   /etc/ssl/certs/ca-certificates.crt                 Either the path to the CA Cert validation bundle or False for don't verify
    drill_ignore_ssl_warn          False                                              Supress SSL warning upon connection - Not recommended



```python
%drill connect
```

    Connecting as user jomernik
    
    Connecting to Drill URL: https://drillprod-prod.marathon.slave.mesos:20004
    
    Please enter the password you wish to connect with:
    
    Pinning to IP for this session: 192.168.0.108
    
    
    Headers in authDrill: {}
    



    ---------------------------------------------------------------------------

    CertificateError                          Traceback (most recent call last)

    /opt/conda/lib/python3.6/site-packages/urllib3/connectionpool.py in urlopen(self, method, url, body, headers, retries, redirect, assert_same_host, timeout, pool_timeout, release_conn, chunked, body_pos, **response_kw)
        599                                                   body=body, headers=headers,
    --> 600                                                   chunked=chunked)
        601 


    /opt/conda/lib/python3.6/site-packages/urllib3/connectionpool.py in _make_request(self, conn, method, url, timeout, chunked, **httplib_request_kw)
        342         try:
    --> 343             self._validate_conn(conn)
        344         except (SocketTimeout, BaseSSLError) as e:


    /opt/conda/lib/python3.6/site-packages/urllib3/connectionpool.py in _validate_conn(self, conn)
        848         if not getattr(conn, 'sock', None):  # AppEngine might not have  `.sock`
    --> 849             conn.connect()
        850 


    /opt/conda/lib/python3.6/site-packages/urllib3/connection.py in connect(self)
        375                 )
    --> 376             _match_hostname(cert, self.assert_hostname or hostname)
        377 


    /opt/conda/lib/python3.6/site-packages/urllib3/connection.py in _match_hostname(cert, asserted_hostname)
        385     try:
    --> 386         match_hostname(cert, asserted_hostname)
        387     except CertificateError as e:


    /opt/conda/lib/python3.6/ssl.py in match_hostname(cert, hostname)
        324             "doesn't match %r"
    --> 325             % (hostname, dnsnames[0]))
        326     else:


    CertificateError: hostname '192.168.0.108' doesn't match 'drillprod-prod.marathon.slave.mesos'

    
    During handling of the above exception, another exception occurred:


    MaxRetryError                             Traceback (most recent call last)

    /opt/conda/lib/python3.6/site-packages/requests/adapters.py in send(self, request, stream, timeout, verify, cert, proxies)
        444                     retries=self.max_retries,
    --> 445                     timeout=timeout
        446                 )


    /opt/conda/lib/python3.6/site-packages/urllib3/connectionpool.py in urlopen(self, method, url, body, headers, retries, redirect, assert_same_host, timeout, pool_timeout, release_conn, chunked, body_pos, **response_kw)
        637             retries = retries.increment(method, url, error=e, _pool=self,
    --> 638                                         _stacktrace=sys.exc_info()[2])
        639             retries.sleep()


    /opt/conda/lib/python3.6/site-packages/urllib3/util/retry.py in increment(self, method, url, response, error, _pool, _stacktrace)
        397         if new_retry.is_exhausted():
    --> 398             raise MaxRetryError(_pool, url, error or ResponseError(cause))
        399 


    MaxRetryError: HTTPSConnectionPool(host='192.168.0.108', port=20004): Max retries exceeded with url: /j_security_check (Caused by SSLError(CertificateError("hostname '192.168.0.108' doesn't match 'drillprod-prod.marathon.slave.mesos'",),))

    
    During handling of the above exception, another exception occurred:


    SSLError                                  Traceback (most recent call last)

    <ipython-input-9-0102b7eb8d56> in <module>()
    ----> 1 get_ipython().magic('drill connect')
    

    /opt/conda/lib/python3.6/site-packages/IPython/core/interactiveshell.py in magic(self, arg_s)
       2156         magic_name, _, magic_arg_s = arg_s.partition(' ')
       2157         magic_name = magic_name.lstrip(prefilter.ESC_MAGIC)
    -> 2158         return self.run_line_magic(magic_name, magic_arg_s)
       2159 
       2160     #-------------------------------------------------------------------------


    /opt/conda/lib/python3.6/site-packages/IPython/core/interactiveshell.py in run_line_magic(self, magic_name, line)
       2077                 kwargs['local_ns'] = sys._getframe(stack_depth).f_locals
       2078             with self.builtin_trap:
    -> 2079                 result = fn(*args,**kwargs)
       2080             return result
       2081 


    <decorator-gen-130> in drill(self, line, cell)


    /opt/conda/lib/python3.6/site-packages/IPython/core/magic.py in <lambda>(f, *a, **k)
        186     # but it's overkill for just that one bit of state.
        187     def magic_deco(arg):
    --> 188         call = lambda f, *a, **k: f(*a, **k)
        189 
        190         if callable(arg):


    /opt/conda/lib/python3.6/site-packages/drill_core/drill_base.py in drill(self, line, cell)
        298                 self.connectDrill(True)
        299             elif line.lower() == "connect":
    --> 300                 self.connectDrill(False)
        301             elif line.lower() .find('set ') == 0:
        302                 self.setvar(line)


    /opt/conda/lib/python3.6/site-packages/drill_core/drill_base.py in connectDrill(self, prompt)
        216                 requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        217             result = -1
    --> 218             self.session, result = self.authDrill()
        219             if result == 0:
        220                 self.drill_connected = True


    /opt/conda/lib/python3.6/site-packages/drill_core/drill_base.py in authDrill(self)
        252             print("Headers in authDrill: %s" % self.drill_opts['drill_headers'][0])
        253             print("")
    --> 254         r = self.session.post(url, data=login, headers=self.drill_opts['drill_headers'][0], verify=self.drill_opts['drill_verify'][0])
        255 
        256         if r.status_code == 200:


    /opt/conda/lib/python3.6/site-packages/requests/sessions.py in post(self, url, data, json, **kwargs)
        557         """
        558 
    --> 559         return self.request('POST', url, data=data, json=json, **kwargs)
        560 
        561     def put(self, url, data=None, **kwargs):


    /opt/conda/lib/python3.6/site-packages/requests/sessions.py in request(self, method, url, params, data, headers, cookies, files, auth, timeout, allow_redirects, proxies, hooks, stream, verify, cert, json)
        510         }
        511         send_kwargs.update(settings)
    --> 512         resp = self.send(prep, **send_kwargs)
        513 
        514         return resp


    /opt/conda/lib/python3.6/site-packages/requests/sessions.py in send(self, request, **kwargs)
        620 
        621         # Send the request
    --> 622         r = adapter.send(request, **kwargs)
        623 
        624         # Total elapsed time of the request (approximately)


    /opt/conda/lib/python3.6/site-packages/requests/adapters.py in send(self, request, stream, timeout, verify, cert, proxies)
        509             if isinstance(e.reason, _SSLError):
        510                 # This branch is for urllib3 v1.22 and later.
    --> 511                 raise SSLError(e, request=request)
        512 
        513             raise ConnectionError(e, request=request)


    SSLError: HTTPSConnectionPool(host='192.168.0.108', port=20004): Max retries exceeded with url: /j_security_check (Caused by SSLError(CertificateError("hostname '192.168.0.108' doesn't match 'drillprod-prod.marathon.slave.mesos'",),))



```python
%drill disconnect
```

    Drill Not Currently Connected - Resetting All Variables


### Using requests.toolkit to rewrite the host header. 

So now, using the requests toolkit HostHeaderSSLAdapter this should be an easy fix. 

In this setup, we use the host "drillprod-prod.marathon.slave.mesos"  which comes from the orginal URL, if I understand things correctly, this means:

1. The connection requests will make will go to https:/192.168.0.103:20004 (or what ever host the name drillprod-prod.marathon.slave.mesos resolves to at the moment). 
2. The Host Header will be rewritten to have Host: drillprod-prod.marathon.slave.mesos  
3. This hostheader will be used to match to the certificate to determine if SSL is valid. 


Oddly, the error returned is confusing

```ConnectionError: HTTPSConnectionPool(host='drillprod-prod.marathon.slave.mesos', port=443): Max retries exceeded with url: /;jsessionid=18x8rovql3iv31m0ddow8f55zt (Caused by NewConnectionError('<urllib3.connection.VerifiedHTTPSConnection object at 0x7fb97c7f9278>: Failed to establish a new connection: [Errno 111] Connection refused',))```

IT looks like the host got rewritten, but the port is now set to 443? That has to be something to do with the Host Header we set ... right? 




```python
%drill set drill_rewrite_host True
```


```python
%drill status
```

    Current State of Drill Interface:
    
    Connected:                     False                                             
    Debug Mode:                    True                                              
    
    Display Properties:
    -----------------------------------
    pd_display_idx                 0                                                  Display the Pandas Index with output
    pd_replace_crlf                1                                                  Replace extra crlfs in outputs with String representations of CRs and LFs
    pd_max_colwidth                50                                                 Max column width to display
    pd_display.max_rows            1000                                               Number of Max Rows  
    pd_display.max_columns         None                                               Max Columns         
    
    Drill Properties:
    -----------------------------------
    drill_user                     jomernik                                           User to connect with drill - Can be set via ENV Var: JPY_USER otherwise will prompt
    drill_base_url                 https://drillprod-prod.marathon.slave.mesos:20004  URL to connect to Drill server. Can be set via ENV Var: DRILL_BASE_URL
    drill_base_url_host                                                               Hostname of drill connection derived from drill_base_url
    drill_base_url_port                                                               Port of drill connection derived from drill_base_url
    drill_base_url_scheme                                                             Scheme of drill connection derived from drill_base_url
    drill_pin_to_ip                False                                              Obtain an IP from the name and connect directly to that IP
    drill_pinned_ip                                                                   IP of pinned connection
    drill_rewrite_host             True                                               When using Pin to IP, rewrite the host header to match the name of base_url
    drill_inc_port_in_rewrite      True                                               When rewriting the host header, include :%port% in the host header
    drill_headers                  {}                                                 Customer Headers to use for Drill connections
    drill_url                                                                         Actual URL used for connection (base URL is the URL that is passed in as default
    drill_verify                   /etc/ssl/certs/ca-certificates.crt                 Either the path to the CA Cert validation bundle or False for don't verify
    drill_ignore_ssl_warn          False                                              Supress SSL warning upon connection - Not recommended



```python
%drill connect
```

    Connecting as user jomernik
    
    Connecting to Drill URL: https://drillprod-prod.marathon.slave.mesos:20004
    
    Please enter the password you wish to connect with:
    
    Pinning to IP for this session: 192.168.0.103
    
    Headers in connectDrill: {'Host': 'drillprod-prod.marathon.slave.mesos'}
    
    Connecting URL: https://192.168.0.103:20004/j_security_check
    
    
    Headers in authDrill: {'Host': 'drillprod-prod.marathon.slave.mesos'}
    



    ---------------------------------------------------------------------------

    ConnectionRefusedError                    Traceback (most recent call last)

    /opt/conda/lib/python3.6/site-packages/urllib3/connection.py in _new_conn(self)
        170             conn = connection.create_connection(
    --> 171                 (self._dns_host, self.port), self.timeout, **extra_kw)
        172 


    /opt/conda/lib/python3.6/site-packages/urllib3/util/connection.py in create_connection(address, timeout, source_address, socket_options)
         78     if err is not None:
    ---> 79         raise err
         80 


    /opt/conda/lib/python3.6/site-packages/urllib3/util/connection.py in create_connection(address, timeout, source_address, socket_options)
         68                 sock.bind(source_address)
    ---> 69             sock.connect(sa)
         70             return sock


    ConnectionRefusedError: [Errno 111] Connection refused

    
    During handling of the above exception, another exception occurred:


    NewConnectionError                        Traceback (most recent call last)

    /opt/conda/lib/python3.6/site-packages/urllib3/connectionpool.py in urlopen(self, method, url, body, headers, retries, redirect, assert_same_host, timeout, pool_timeout, release_conn, chunked, body_pos, **response_kw)
        599                                                   body=body, headers=headers,
    --> 600                                                   chunked=chunked)
        601 


    /opt/conda/lib/python3.6/site-packages/urllib3/connectionpool.py in _make_request(self, conn, method, url, timeout, chunked, **httplib_request_kw)
        342         try:
    --> 343             self._validate_conn(conn)
        344         except (SocketTimeout, BaseSSLError) as e:


    /opt/conda/lib/python3.6/site-packages/urllib3/connectionpool.py in _validate_conn(self, conn)
        848         if not getattr(conn, 'sock', None):  # AppEngine might not have  `.sock`
    --> 849             conn.connect()
        850 


    /opt/conda/lib/python3.6/site-packages/urllib3/connection.py in connect(self)
        313         # Add certificate verification
    --> 314         conn = self._new_conn()
        315 


    /opt/conda/lib/python3.6/site-packages/urllib3/connection.py in _new_conn(self)
        179             raise NewConnectionError(
    --> 180                 self, "Failed to establish a new connection: %s" % e)
        181 


    NewConnectionError: <urllib3.connection.VerifiedHTTPSConnection object at 0x7fd31754e358>: Failed to establish a new connection: [Errno 111] Connection refused

    
    During handling of the above exception, another exception occurred:


    MaxRetryError                             Traceback (most recent call last)

    /opt/conda/lib/python3.6/site-packages/requests/adapters.py in send(self, request, stream, timeout, verify, cert, proxies)
        444                     retries=self.max_retries,
    --> 445                     timeout=timeout
        446                 )


    /opt/conda/lib/python3.6/site-packages/urllib3/connectionpool.py in urlopen(self, method, url, body, headers, retries, redirect, assert_same_host, timeout, pool_timeout, release_conn, chunked, body_pos, **response_kw)
        637             retries = retries.increment(method, url, error=e, _pool=self,
    --> 638                                         _stacktrace=sys.exc_info()[2])
        639             retries.sleep()


    /opt/conda/lib/python3.6/site-packages/urllib3/util/retry.py in increment(self, method, url, response, error, _pool, _stacktrace)
        397         if new_retry.is_exhausted():
    --> 398             raise MaxRetryError(_pool, url, error or ResponseError(cause))
        399 


    MaxRetryError: HTTPSConnectionPool(host='drillprod-prod.marathon.slave.mesos', port=443): Max retries exceeded with url: /;jsessionid=18oy55svq4ehr9onakrcnmvbz (Caused by NewConnectionError('<urllib3.connection.VerifiedHTTPSConnection object at 0x7fd31754e358>: Failed to establish a new connection: [Errno 111] Connection refused',))

    
    During handling of the above exception, another exception occurred:


    ConnectionError                           Traceback (most recent call last)

    <ipython-input-7-0102b7eb8d56> in <module>()
    ----> 1 get_ipython().magic('drill connect')
    

    /opt/conda/lib/python3.6/site-packages/IPython/core/interactiveshell.py in magic(self, arg_s)
       2156         magic_name, _, magic_arg_s = arg_s.partition(' ')
       2157         magic_name = magic_name.lstrip(prefilter.ESC_MAGIC)
    -> 2158         return self.run_line_magic(magic_name, magic_arg_s)
       2159 
       2160     #-------------------------------------------------------------------------


    /opt/conda/lib/python3.6/site-packages/IPython/core/interactiveshell.py in run_line_magic(self, magic_name, line)
       2077                 kwargs['local_ns'] = sys._getframe(stack_depth).f_locals
       2078             with self.builtin_trap:
    -> 2079                 result = fn(*args,**kwargs)
       2080             return result
       2081 


    <decorator-gen-130> in drill(self, line, cell)


    /opt/conda/lib/python3.6/site-packages/IPython/core/magic.py in <lambda>(f, *a, **k)
        186     # but it's overkill for just that one bit of state.
        187     def magic_deco(arg):
    --> 188         call = lambda f, *a, **k: f(*a, **k)
        189 
        190         if callable(arg):


    /opt/conda/lib/python3.6/site-packages/drill_core/drill_base.py in drill(self, line, cell)
        302                 self.connectDrill(True)
        303             elif line.lower() == "connect":
    --> 304                 self.connectDrill(False)
        305             elif line.lower() .find('set ') == 0:
        306                 self.setvar(line)


    /opt/conda/lib/python3.6/site-packages/drill_core/drill_base.py in connectDrill(self, prompt)
        216                 requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        217             result = -1
    --> 218             self.session, result = self.authDrill()
        219             if result == 0:
        220                 self.drill_connected = True


    /opt/conda/lib/python3.6/site-packages/drill_core/drill_base.py in authDrill(self)
        256             print("Headers in authDrill: %s" % self.drill_opts['drill_headers'][0])
        257             print("")
    --> 258         r = self.session.post(url, data=login, headers=self.drill_opts['drill_headers'][0], verify=self.drill_opts['drill_verify'][0])
        259 
        260         if r.status_code == 200:


    /opt/conda/lib/python3.6/site-packages/requests/sessions.py in post(self, url, data, json, **kwargs)
        557         """
        558 
    --> 559         return self.request('POST', url, data=data, json=json, **kwargs)
        560 
        561     def put(self, url, data=None, **kwargs):


    /opt/conda/lib/python3.6/site-packages/requests/sessions.py in request(self, method, url, params, data, headers, cookies, files, auth, timeout, allow_redirects, proxies, hooks, stream, verify, cert, json)
        510         }
        511         send_kwargs.update(settings)
    --> 512         resp = self.send(prep, **send_kwargs)
        513 
        514         return resp


    /opt/conda/lib/python3.6/site-packages/requests/sessions.py in send(self, request, **kwargs)
        642 
        643         # Resolve redirects if allowed.
    --> 644         history = [resp for resp in gen] if allow_redirects else []
        645 
        646         # Shuffle things around if there's history.


    /opt/conda/lib/python3.6/site-packages/requests/sessions.py in <listcomp>(.0)
        642 
        643         # Resolve redirects if allowed.
    --> 644         history = [resp for resp in gen] if allow_redirects else []
        645 
        646         # Shuffle things around if there's history.


    /opt/conda/lib/python3.6/site-packages/requests/sessions.py in resolve_redirects(self, resp, req, stream, timeout, verify, cert, proxies, yield_requests, **adapter_kwargs)
        220                     proxies=proxies,
        221                     allow_redirects=False,
    --> 222                     **adapter_kwargs
        223                 )
        224 


    /opt/conda/lib/python3.6/site-packages/requests/sessions.py in send(self, request, **kwargs)
        620 
        621         # Send the request
    --> 622         r = adapter.send(request, **kwargs)
        623 
        624         # Total elapsed time of the request (approximately)


    /opt/conda/lib/python3.6/site-packages/requests_toolbelt/adapters/host_header_ssl.py in send(self, request, **kwargs)
         41             connection_pool_kwargs.pop("assert_hostname", None)
         42 
    ---> 43         return super(HostHeaderSSLAdapter, self).send(request, **kwargs)
    

    /opt/conda/lib/python3.6/site-packages/requests/adapters.py in send(self, request, stream, timeout, verify, cert, proxies)
        511                 raise SSLError(e, request=request)
        512 
    --> 513             raise ConnectionError(e, request=request)
        514 
        515         except ClosedPoolError as e:


    ConnectionError: HTTPSConnectionPool(host='drillprod-prod.marathon.slave.mesos', port=443): Max retries exceeded with url: /;jsessionid=18oy55svq4ehr9onakrcnmvbz (Caused by NewConnectionError('<urllib3.connection.VerifiedHTTPSConnection object at 0x7fd31754e358>: Failed to establish a new connection: [Errno 111] Connection refused',))


### Adding a port to the hostheader

So I am not sure if a port in the host header is good or not (per RFC). However, I added an ability to do just this. Since Port was apparently being inferred by the host header (443 is not set anywhere, something is defaulting to it)

However, once we do this, the certificate no longer matches because we are changing the host to drillprod-prod.marathon.slave.mesos:20004 and the cert has drillprod-prod.marathon.slave.mesos

Thus I am stumped. 


```python
%drill set drill_inc_port_in_rewrite True
```


```python
%drill status
```

    Current State of Drill Interface:
    
    Connected:                     False                                             
    Debug Mode:                    True                                              
    
    Display Properties:
    -----------------------------------
    pd_display_idx                 0                                                  Display the Pandas Index with output
    pd_replace_crlf                1                                                  Replace extra crlfs in outputs with String representations of CRs and LFs
    pd_max_colwidth                50                                                 Max column width to display
    pd_display.max_rows            1000                                               Number of Max Rows  
    pd_display.max_columns         None                                               Max Columns         
    
    Drill Properties:
    -----------------------------------
    drill_user                     jomernik                                           User to connect with drill - Can be set via ENV Var: JPY_USER otherwise will prompt
    drill_base_url                 https://drillprod-prod.marathon.slave.mesos:20004  URL to connect to Drill server. Can be set via ENV Var: DRILL_BASE_URL
    drill_base_url_host                                                               Hostname of drill connection derived from drill_base_url
    drill_base_url_port                                                               Port of drill connection derived from drill_base_url
    drill_base_url_scheme                                                             Scheme of drill connection derived from drill_base_url
    drill_pin_to_ip                True                                               Obtain an IP from the name and connect directly to that IP
    drill_pinned_ip                                                                   IP of pinned connection
    drill_rewrite_host             True                                               When using Pin to IP, rewrite the host header to match the name of base_url
    drill_inc_port_in_rewrite      True                                               When rewriting the host header, include :%port% in the host header
    drill_headers                  {}                                                 Customer Headers to use for Drill connections
    drill_url                                                                         Actual URL used for connection (base URL is the URL that is passed in as default
    drill_verify                   /etc/ssl/certs/ca-certificates.crt                 Either the path to the CA Cert validation bundle or False for don't verify
    drill_ignore_ssl_warn          False                                              Supress SSL warning upon connection - Not recommended



```python
%drill connect
```

    Connecting as user jomernik
    
    Connecting to Drill URL: https://drillprod-prod.marathon.slave.mesos:20004
    
    Please enter the password you wish to connect with:


    ERROR:urllib3.connection:Certificate did not match expected hostname: drillprod-prod.marathon.slave.mesos:20004. Certificate: {'subject': ((('commonName', 'drillprod-prod.marathon.slave.mesos'),),), 'subjectAltName': []}


    
    Pinning to IP for this session: 192.168.0.103
    
    Headers in connectDrill: {'Host': 'drillprod-prod.marathon.slave.mesos:20004'}
    
    Connecting URL: https://192.168.0.103:20004/j_security_check
    
    
    Headers in authDrill: {'Host': 'drillprod-prod.marathon.slave.mesos:20004'}
    



    ---------------------------------------------------------------------------

    CertificateError                          Traceback (most recent call last)

    /opt/conda/lib/python3.6/site-packages/urllib3/connectionpool.py in urlopen(self, method, url, body, headers, retries, redirect, assert_same_host, timeout, pool_timeout, release_conn, chunked, body_pos, **response_kw)
        599                                                   body=body, headers=headers,
    --> 600                                                   chunked=chunked)
        601 


    /opt/conda/lib/python3.6/site-packages/urllib3/connectionpool.py in _make_request(self, conn, method, url, timeout, chunked, **httplib_request_kw)
        342         try:
    --> 343             self._validate_conn(conn)
        344         except (SocketTimeout, BaseSSLError) as e:


    /opt/conda/lib/python3.6/site-packages/urllib3/connectionpool.py in _validate_conn(self, conn)
        848         if not getattr(conn, 'sock', None):  # AppEngine might not have  `.sock`
    --> 849             conn.connect()
        850 


    /opt/conda/lib/python3.6/site-packages/urllib3/connection.py in connect(self)
        375                 )
    --> 376             _match_hostname(cert, self.assert_hostname or hostname)
        377 


    /opt/conda/lib/python3.6/site-packages/urllib3/connection.py in _match_hostname(cert, asserted_hostname)
        385     try:
    --> 386         match_hostname(cert, asserted_hostname)
        387     except CertificateError as e:


    /opt/conda/lib/python3.6/ssl.py in match_hostname(cert, hostname)
        324             "doesn't match %r"
    --> 325             % (hostname, dnsnames[0]))
        326     else:


    CertificateError: hostname 'drillprod-prod.marathon.slave.mesos:20004' doesn't match 'drillprod-prod.marathon.slave.mesos'

    
    During handling of the above exception, another exception occurred:


    MaxRetryError                             Traceback (most recent call last)

    /opt/conda/lib/python3.6/site-packages/requests/adapters.py in send(self, request, stream, timeout, verify, cert, proxies)
        444                     retries=self.max_retries,
    --> 445                     timeout=timeout
        446                 )


    /opt/conda/lib/python3.6/site-packages/urllib3/connectionpool.py in urlopen(self, method, url, body, headers, retries, redirect, assert_same_host, timeout, pool_timeout, release_conn, chunked, body_pos, **response_kw)
        637             retries = retries.increment(method, url, error=e, _pool=self,
    --> 638                                         _stacktrace=sys.exc_info()[2])
        639             retries.sleep()


    /opt/conda/lib/python3.6/site-packages/urllib3/util/retry.py in increment(self, method, url, response, error, _pool, _stacktrace)
        397         if new_retry.is_exhausted():
    --> 398             raise MaxRetryError(_pool, url, error or ResponseError(cause))
        399 


    MaxRetryError: HTTPSConnectionPool(host='192.168.0.103', port=20004): Max retries exceeded with url: /j_security_check (Caused by SSLError(CertificateError("hostname 'drillprod-prod.marathon.slave.mesos:20004' doesn't match 'drillprod-prod.marathon.slave.mesos'",),))

    
    During handling of the above exception, another exception occurred:


    SSLError                                  Traceback (most recent call last)

    <ipython-input-10-0102b7eb8d56> in <module>()
    ----> 1 get_ipython().magic('drill connect')
    

    /opt/conda/lib/python3.6/site-packages/IPython/core/interactiveshell.py in magic(self, arg_s)
       2156         magic_name, _, magic_arg_s = arg_s.partition(' ')
       2157         magic_name = magic_name.lstrip(prefilter.ESC_MAGIC)
    -> 2158         return self.run_line_magic(magic_name, magic_arg_s)
       2159 
       2160     #-------------------------------------------------------------------------


    /opt/conda/lib/python3.6/site-packages/IPython/core/interactiveshell.py in run_line_magic(self, magic_name, line)
       2077                 kwargs['local_ns'] = sys._getframe(stack_depth).f_locals
       2078             with self.builtin_trap:
    -> 2079                 result = fn(*args,**kwargs)
       2080             return result
       2081 


    <decorator-gen-130> in drill(self, line, cell)


    /opt/conda/lib/python3.6/site-packages/IPython/core/magic.py in <lambda>(f, *a, **k)
        186     # but it's overkill for just that one bit of state.
        187     def magic_deco(arg):
    --> 188         call = lambda f, *a, **k: f(*a, **k)
        189 
        190         if callable(arg):


    /opt/conda/lib/python3.6/site-packages/drill_core/drill_base.py in drill(self, line, cell)
        302                 self.connectDrill(True)
        303             elif line.lower() == "connect":
    --> 304                 self.connectDrill(False)
        305             elif line.lower() .find('set ') == 0:
        306                 self.setvar(line)


    /opt/conda/lib/python3.6/site-packages/drill_core/drill_base.py in connectDrill(self, prompt)
        216                 requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        217             result = -1
    --> 218             self.session, result = self.authDrill()
        219             if result == 0:
        220                 self.drill_connected = True


    /opt/conda/lib/python3.6/site-packages/drill_core/drill_base.py in authDrill(self)
        256             print("Headers in authDrill: %s" % self.drill_opts['drill_headers'][0])
        257             print("")
    --> 258         r = self.session.post(url, data=login, headers=self.drill_opts['drill_headers'][0], verify=self.drill_opts['drill_verify'][0])
        259 
        260         if r.status_code == 200:


    /opt/conda/lib/python3.6/site-packages/requests/sessions.py in post(self, url, data, json, **kwargs)
        557         """
        558 
    --> 559         return self.request('POST', url, data=data, json=json, **kwargs)
        560 
        561     def put(self, url, data=None, **kwargs):


    /opt/conda/lib/python3.6/site-packages/requests/sessions.py in request(self, method, url, params, data, headers, cookies, files, auth, timeout, allow_redirects, proxies, hooks, stream, verify, cert, json)
        510         }
        511         send_kwargs.update(settings)
    --> 512         resp = self.send(prep, **send_kwargs)
        513 
        514         return resp


    /opt/conda/lib/python3.6/site-packages/requests/sessions.py in send(self, request, **kwargs)
        620 
        621         # Send the request
    --> 622         r = adapter.send(request, **kwargs)
        623 
        624         # Total elapsed time of the request (approximately)


    /opt/conda/lib/python3.6/site-packages/requests_toolbelt/adapters/host_header_ssl.py in send(self, request, **kwargs)
         41             connection_pool_kwargs.pop("assert_hostname", None)
         42 
    ---> 43         return super(HostHeaderSSLAdapter, self).send(request, **kwargs)
    

    /opt/conda/lib/python3.6/site-packages/requests/adapters.py in send(self, request, stream, timeout, verify, cert, proxies)
        509             if isinstance(e.reason, _SSLError):
        510                 # This branch is for urllib3 v1.22 and later.
    --> 511                 raise SSLError(e, request=request)
        512 
        513             raise ConnectionError(e, request=request)


    SSLError: HTTPSConnectionPool(host='192.168.0.103', port=20004): Max retries exceeded with url: /j_security_check (Caused by SSLError(CertificateError("hostname 'drillprod-prod.marathon.slave.mesos:20004' doesn't match 'drillprod-prod.marathon.slave.mesos'",),))
