import io
import re
import sys
import json
import Cookie
import requests

from os.path import basename

from burp import IBurpExtender
from burp import IContextMenuFactory

from javax.swing import JPanel;
from javax.swing import JMenuItem;

from http_parser.pyparser import HttpParser
from urlparse import urlparse

class BurpExtender(IBurpExtender, IContextMenuFactory):
    
    aslanpp_constants = set()
    aslanpp_nonpublic_constants = set()
    aslanpp_variables = set()
    taglist = set()
    
    # requests
    page = "none"
    params ="none"
    cookie = "none"
    cookie2 = "none"

    # response
    return_page = "none"
    return_cookie = "none"

    # concretization
    url = "none"
    method = "none"
    params_concrete = []
    cookie_concrete = []
    headers = []
    mapping = []
    concretization_file = {}

    taglist = []
    tag = "tag"
    i_tag = 0
    
    branches = ""
    params_keys = []
    cookie_request = ""

    request_skeleton = """
    \t\t\t\t\t\ton(?Entity*->*Actor:http_request({},{},{}).{}.?WebNonce):{{
    \t\t\t\t\t\t% todo: request's behavior here
    \t\t\t\t\t\tActor*->*Entity:http_response({},{}).{}.WebNonce;
    \t\t\t\t\t}}
    """

    client_skeleton = """
    \t\t\t\t\t\ton(Actor*->*Webapplication:http_request({},{},{}).{}.?WebNonce):{{
    \t\t\t\t\t\t% todo: request's behavior here
    \t\t\t\t\t\tWebapplication*->*Actor:http_response({},{}).{}.WebNonce;
    \t\t\t\t\t}}
    """

    _webapp_branch = ""
    _client_branch = ""

    def registerExtenderCallbacks(self, callbacks):
        
        # your extension code here
        self._panel = JPanel()
        self._callbacks = callbacks
        callbacks.setExtensionName("WAFEx")
        #callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        
        return

    # def getTabCaption(self):
    #     return "Hello tab"

    # def getUiComponent(self):
    #     return self._panel
    
    def createMenuItems(self, invocation):
        ret = []
        #if(invocation.getInvocationContext() == invocation.CONTEXT_TARGET_SITE_MAP_TREE or invocation.getInvocationContext() == invocation.CONTEXT_TARGET_SITE_MAP_TABLE):
        if(invocation.getInvocationContext() == invocation.CONTEXT_TARGET_SITE_MAP_TABLE):
            menu = JMenuItem("Generate WAFEx model")
            messages = invocation.getSelectedMessages()
            def listener(e):
                """ Generates a new WAFEx model. """
                self.generateWAFExModel(messages)

            menu.addActionListener(listener)
            ret.append(menu)
        return ret


    def generateWAFExModel(self,messages):
        # reset some variables
        self._webapp_branch = ""
        self.i_tag = 0
        # start the generation
        for msg in messages:
            self.parseHttpRequestResponse(msg)



    def parseHttpRequestResponse(self, msg):
        """ Parses a HTTP Request/Response and generate it's translation in ASLan++. """
        # To keep the concretization file simple, it will contain
        # - URL
        # - METHOD
        # - PARAMS
        # - HEADERS
        # - MAPPING from abstract to concrete (which will be 1:1 when this plugin is used)

        # from byte to char Request and Response
        http_request = "".join(chr(b) for b in msg.getRequest())
        http_response = "".join(chr(b) for b in msg.getResponse())

        request_parser = HttpParser()
        request_parser.execute(http_request,len(http_request))

        # URL for concretization
        self.url = msg.getHttpService().getProtocol() +"://"+ request_parser.get_headers()['Host'] +"/" + request_parser.get_url()

        # path (this string should not begin with something different from a character)
        self.page = re.sub("^[^a-z]*","",urlparse(self.url).path.replace(".","_").replace("/","_"))

        # method for concretization
        self.method = request_parser.get_method()
        
        query_string = ""
        # GET requests
        if self.method == "GET":
            # GET parameters
            query_string = request_parser.get_query_string()
        # POST requests
        elif self.method == "POST":
            # POST parameters
            query_string = request_parser.recv_body()

        # parse parameters
        if query_string:
            # saving the concrete parameters
            self.params_concrete = [couple.split("=") for couple in query_string.split("&")]
            aslanpp_params = ""
            for c in self.params_concrete:
                key = re.sub("[^a-zA-Z0-9]","", c[0].lower())
                value = ("none" if not c[1] else re.sub("[^a-zA-Z0-9]","",c[1].capitalize()))
                # key is a public constant
                # value is a public variable
                self.aslanpp_nonpublic_constants.add(key)
                self.aslanpp_variables.add(value)

                # ASLan++ parameters
                aslanpp_params += key + ".s." + value + ".s."
            # save ASLan++ parameters
            self.params = "none" if not aslanpp_params else aslanpp_params[:-3]

        # cookie in the request
        try:
            cookie_request = request_parser.get_headers()['Cookie']

            simple_cookie = Cookie.SimpleCookie(cookie_request) 
            self.cookie_concrete = [[item,simple_cookie[item].value] for item in simple_cookie]
            aslanpp_cookie = ""
            for c in self.cookie_concrete:
                key = re.sub("[^a-zA-Z0-9]","", c[0].lower())
                value = ("none" if not c[1] else re.sub("[^a-zA-Z0-9]","",c[1].capitalize()))

                # ASLan++ constants and variables
                self.aslanpp_nonpublic_constants.add(key)
                self.aslanpp_variables.add(value)

                # ASLan++ code cookie
                aslanpp_cookie += key + ".s." + value + ".s."

                # concretization mapping
                self.mapping.append([key,key])

            self.cookie = "none" if not aslanpp_cookie else aslanpp_cookie[:-3]
        except KeyError:
            pass

        # check if the page should be nonpublic
        page_nonpublic = self.is_nonpublic(request_parser,query_string)

        if page_nonpublic:
            self.aslanpp_nonpublic_constants.add(self.page)
        else:
             self.aslanpp_constants.add(self.page)

        # check the response
        response_parser = HttpParser()
        response_parser.execute(http_response,len(http_response))

        # Location
        # get the returned page by checking the Location field in
        # the header. If Location is set, it means is a 302 Redirect
        # and the client is receiving a different page back in the response
        try:
            self.return_page = urlparse(response_parser.get_headers()['Location']).path.partition("?")[0].replace("/","_")
            is_nonpublic = self.is_nonpublic(self.return_page)
            if is_nonpublic:
                self.aslanpp_nonpublic_constants.add(self.return_page)
            else:
                self.aslanpp_constants.add(self.return_page)
        except KeyError:
            self.return_page = self.page

        # and let's see if we have a new cookie
        try:
            set_cookie_header = response_parser.get_headers()['Set-Cookie']
            # parse new cookie
            simple_cookie = Cookie.SimpleCookie(set_cookie_header) 
            cookies = [[item,simple_cookie[item].value] for item in simple_cookie]
            aslanpp_cookie = ""
            for c in cookies:
                key = re.sub("[^a-zA-Z0-9]","", c[0].lower())
                value = ("none" if not c[1] else re.sub("[^a-zA-Z0-9]","",c[1].capitalize()))

                # ASLan++ constants and variables
                self.aslanpp_nonpublic_constants.add(key)
                self.aslanpp_variables.add(value)

                # ASLan++ cookie
                aslanpp_cookie += key + ".s." + value + ".s."

                # concretization mapping
                self.mapping.append([key,key])

            self.return_cookie = "none" if not aslanpp_cookie else aslanpp_cookie[:-3]
        except KeyError:
            pass

        tag = self.tag + str(self.i_tag)
        self._webapp_branch += self.request_skeleton.format(self.page, self.params,self.cookie,tag,self.return_page,self.return_cookie,tag)
        self._client_branch += self.client_skeleton.format(self.page, self.params,self.cookie,tag,self.return_page,self.return_cookie,tag)

        # create the concretization JSON
        self.concretization_file[tag] = {"method" : self.method, "url" : self.url, "params" : self.params_concrete,"cookie":self.return_cookie}
        
        # save tag in taglist and increment the tag number
        self.taglist.append("{}{}".format(self.tag,self.i_tag))
        self.i_tag +=1

        # create a new model
        skeleton = open("skeleton.aslan++","r").read()
        if self.aslanpp_nonpublic_constants:
            nonpublic_constants = "nonpublic " + ",".join(item for item in self.aslanpp_nonpublic_constants) + " : text;"
            skeleton = skeleton.replace("@constants2",nonpublic_constants)
        else:
            skeleton = skeleton.replace("@constants2","")
        if self.aslanpp_constants:
            public_constants = ",".join(item for item in self.aslanpp_constants) + " : text;"
            skeleton = skeleton.replace("@constants",public_constants)
        else:
            skeleton = skeleton.replace("@constants","")
        if self.aslanpp_variables:
            variables = ", ".join(item for item in self.aslanpp_variables) + " : message;"
            skeleton = skeleton.replace("@webappsymbols",variables)
        else:
            skeleton = skeleton.replace("@webappsymbols","")
        if self.taglist:
            tags = ", ".join(item for item in self.taglist) + " : text;"
            skeleton = skeleton.replace("@tags",tags)
        else:
            skeleton = skeleton.replace("@tags","")
        skeleton = skeleton.replace("@webappbody",self._webapp_branch)
        skeleton = skeleton.replace("@honestbody",self._client_branch)

        with open("m.aslan++","w") as f:
            f.write(skeleton)
        print("model created")

        with open("concrete.txt","w") as f:
            f.write(json.dumps(self.concretization_file))

    def is_nonpublic(self,header,body):
        """Checks if a page is accessible even if the requests is made without cookies.
           This is used to understand if a page should be *public* or *nonpublic* in the ASLan++ model. 
        """
        # Python versins older than 2.7.9 have an SNIMissingWarning issue
        # so right now only HTTP requests are supported and not HTTPS
        # https://urllib3.readthedocs.io/en/latest/advanced-usage.html#ssl-warnings

        url = "http://" + header.get_headers()['Host'] + header.get_url()
        # I don't want the cookie to be part of the header
        h = {k:v for (k,v) in header.get_headers().iteritems() if k != "Cookie"}
        payload = body
        r = 0
        if header.get_method() == "GET":
            r = requests.get(url, verify=False, headers=h, allow_redirects=False)
        elif header.get_method() == "POST":
            r = requests.post(url,data=payload, verify=False, headers=h, allow_redirects=False)
        if r.status_code == 200:
            return False
        else:
            return True

