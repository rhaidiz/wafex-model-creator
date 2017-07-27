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
    aslanpp_tables_nonpublic_constants = set()
    
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

    var_tag = "Var_"
    var_tag_i = 0
    
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
    populate_database_skeleton = "db->add({});\n"

    _webapp_branch = ""
    _client_branch = ""
    _init_database = ""

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
        self._client_branch = ""
        self.i_tag = 0
        self.aslanpp_constants = set()
        self.aslanpp_nonpublic_constants = set()
        self.aslanpp_variables = set()
        self.taglist = set()
        self.aslanpp_tables_nonpublic_constants = set()

        print("create model")
        # start the generation
        try:
            for msg in messages:
                # from byte to char Request and Response
                # for some reason b can be a negative value causing a crash
                # so I put a check to ensure b is in the right range 
                http_request = "".join(chr(b) for b in msg.getRequest() if b >= 0 and b <= 256)
                http_response = "".join(chr(b) for b in msg.getResponse() if b >=0 and b <= 256)
                protocol = msg.getHttpService().getProtocol()
                self.parseHttpRequestResponse(http_request, http_response, protocol)

            # create the database
            self.parse_database("/Users/federicodemeo/Downloads/chained.sql")


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

            if self.aslanpp_tables_nonpublic_constants:
                nonpublic_constants = "nonpublic " + ",".join(item for item in self.aslanpp_tables_nonpublic_constants) + " : text;"
                skeleton = skeleton.replace("@databasestructure",nonpublic_constants)
                skeleton = skeleton.replace("@databaseinit",self._init_database)
            else:
                skeleton = skeleton.replace("@databasestructure","")
                skeleton = skeleton.replace("@databaseinit","")


            with open("m.aslan++","w") as f:
                f.write(skeleton)
            print("model created")

            with open("concrete.txt","w") as f:
                f.write(json.dumps(self.concretization_file))
           
        except Exception as e:
            print(e)



    def parseHttpRequestResponse(self, http_request, http_response, protocol):
        """ Parses a HTTP Request/Response and generate it's translation in ASLan++. """
        # To keep the concretization file simple, it will contain
        # - URL
        # - METHOD
        # - PARAMS
        # - HEADERS
        # - MAPPING from abstract to concrete (which will be 1:1 when this plugin is used)

        request_parser = HttpParser()
        request_parser.execute(http_request,len(http_request))

        # URL for concretization
        self.url = protocol +"://"+ request_parser.get_headers()['Host'] +"/" + request_parser.get_url()

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

            # parse the parameters and retrieve ASLan++ code, constants, variables and mapping
            aslanpp_params, constants, variables, mapping = self.parse_parameters(self.params_concrete)

            self.aslanpp_nonpublic_constants |= constants 
            self.aslanpp_variables |= variables
            self.mapping += mapping

            # save ASLan++ parameters
            self.params = "none" if not aslanpp_params else aslanpp_params[:-3]

        # cookie in the request
        try:
            cookie_request = request_parser.get_headers()['Cookie']

            simple_cookie = Cookie.SimpleCookie(cookie_request) 
            self.cookie_concrete = [[item,simple_cookie[item].value] for item in simple_cookie]
            
            # parse the parameters and retrieve ASLan++ code, constants, variables and mapping
            aslanpp_cookie, constants, variables, mapping = self.parse_parameters(self.cookie_concrete)

            self.aslanpp_nonpublic_constants |= constants 
            self.aslanpp_variables |= variables
            self.mapping += mapping

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
            is_nonpublic = self.is_nonpublic(response_parser,"")
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
            
            # parse the parameters and retrieve ASLan++ code, constants, variables and mapping
            aslanpp_cookie, constants, variables, mapping = self.parse_parameters(cookies)

            self.aslanpp_nonpublic_constants |= constants 
            self.aslanpp_variables |= variables
            self.mapping += mapping

            self.return_cookie = "none" if not aslanpp_cookie else aslanpp_cookie[:-3]
        except KeyError:
            pass

        tag = self.tag + str(self.i_tag)
        self._webapp_branch += self.request_skeleton.format(self.page, self.params,self.cookie,tag,self.return_page,self.return_cookie,tag)
        self._client_branch += self.client_skeleton.format(self.page, self.params,self.cookie,tag,self.return_page,self.return_cookie,tag)

        # create the concretization JSON
        self.concretization_file[tag] = {"method" : self.method, "url" : self.url, "params" : self.params_concrete,"cookie":self.return_cookie}
        
        # save tag in taglist and increment the tag number
        self.taglist.add("{}{}".format(self.tag,self.i_tag))
        self.i_tag +=1





    def parse_parameters(self,line_parsed):
        """ Translates line_parsed in ASLan++ and returns the ASLan++ code, constants, variables and mapping. """
        aslanpp_code = ""
        constants = set()
        variables = set()
        mapping = []
        for c in line_parsed:
            key = re.sub("[^a-zA-Z0-9]","", c[0].lower())
            value = "{}{}".format(self.var_tag,self.var_tag_i)
            self.var_tag_i += 1

            # ASLan++ constants and variables
            constants.add(key)
            variables.add(value)

            # ASLan++ code cookie
            aslanpp_code += key + ".s." + value + ".s."

            # concretization mapping
            mapping.append([key,key])

        return aslanpp_code, constants, variables, mapping

    def parse_database(self, sql_file):

        with open(sql_file) as f:
            line = f.read()
            tables_name = re.findall("CREATE TABLE[a-zA-Z ]*`(.*)`", line)
            for t in tables_name:
                self.aslanpp_tables_nonpublic_constants.add(t)
                self._init_database += self.populate_database_skeleton.format(t)




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

