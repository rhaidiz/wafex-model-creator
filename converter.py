import re
import os
import sys
import json
import Cookie
import requests

from urlparse import urlparse

from aslanppmodel import AslanppModel
from http_parser.pyparser import HttpParser

i_tag = 0
var_tag = "Var_"
var_i = 0

_search_pattern = "Entity\*->\*Actor:http_request\([0-9\?\.\-_A-Za-z]*,[0-9_\?\.\-A-Za-z]*,[_0-9\?\.\-A-Za-z]*\)\.{}"

request_skeleton = """
\t\t\t\ton(?Entity*->*Actor:http_request({},{},{}).{}.?WebNonce):{{
\t\t\t\t% todo: request's behavior here
\t\t\t\tActor*->*Entity:http_response({},{},{}).{}.WebNonce;
\t\t\t}}
"""

client_skeleton = """
\t\t\t\ton(true):{{
\t\t\t\t% send request
\t\t\t\tWebNonce := fresh();
\t\t\t\tActor*->*Webapplication:http_request({},{},{}).{}.WebNonce;
\t\t\t\t% expected response
\t\t\t\tWebapplication*->*Actor:http_response({},?Body,?Cookie).{}.WebNonce;
\t\t\t\thknows->add(Cookie);
\t\t\t\tif(client_xss(Body)){{
\t\t\t\t\tActor -> i : hknows;
\t\t\t\t}}
\t\t\t}}
"""
populate_database_skeleton = "db->add({});\n"
# Code for generating the model


""" Generates the ASLan++ code starting from an AslanppModel. """
def _generateWAFExModel(model):
    # start the generation
    try:
        i_tag = 0
        # create the database
        if model._sql_file != None:
            _parse_database(model)


        skeleton = open("skeleton.aslan++","r").read()
        if model._page_constants:
            pages = ",".join(item for item in model._page_constants) + " : page;"
            skeleton = skeleton.replace("@pages", pages)
        else:
            skeleton = skeleton.replace("@pages", "")

        if model._params_constants:
            params = ",".join(item for item in model._params_constants) + " : param;"
            skeleton = skeleton.replace("@params",params)
        else:
            skeleton = skeleton.replace("@params","")

        if model._taglist:
            taglist = ",".join(item for item in model._taglist) + " : text;"
            skeleton = skeleton.replace("@tags", taglist)
        else:
            skeleton = skeleton.replace("@tags", "")
        if model._params_webapp_variables:
            variables = ", ".join(item for item in model._params_webapp_variables) + " : messages;"
            skeleton = skeleton.replace("@webappsymbols",variables)
        else:
            skeleton = skeleton.replace("@webappsymbols","")
        if model._aslanpp_tables:
            nonpublic_constants = "nonpublic " + ",".join(item for item in model._aslanpp_tables) + " : message set;"
            skeleton = skeleton.replace("@databasestructure",nonpublic_constants)
            skeleton = skeleton.replace("@databaseinit",model._init_database)
        else:
            skeleton = skeleton.replace("@databasestructure","")
            skeleton = skeleton.replace("@databaseinit","")

        skeleton = skeleton.replace("@webappbody",model._webapp_branch)
        skeleton = skeleton.replace("@honestbody",model._client_branch)

        concrete = json.dumps(model._concretization, indent=1)
        return skeleton, concrete
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)

def _byte_array_to_string(byte):
    return "".join(chr(b) for b in byte if b >= 0 and b <= 256)


def _parseHttpRequestResponse(model, http_request, http_response, protocol):
    try:
        global i_tag
        global var_i
        """ Parses a HTTP Request/Response and generate it's translation in ASLan++. """
        request_parser = HttpParser()
        request_parser.execute(http_request,len(http_request))

        var_i = 0

        # concretization details
        concrete = dict()
        
        # concretization TAG
        returntag = "tag{}".format(i_tag)

        # URL for concretization
        url = protocol +"://"+ request_parser.get_headers()['Host'] +"/" + request_parser.get_url()
        concrete['url'] = url

        # path (this string should not begin with something different from a character)
        # and replace every non alphanumeric character with _
        # the first re.sub is used to replace every non alphanumeric char
        # the second re.sub is used to remove non character from the begining of the string
        page = re.sub("^[^a-z]*","",re.sub("[^a-zA-Z0-9]","_",urlparse(url).path))
        # add page in the array _aslanpp_constants
        model._page_constants.add(page)

        # method for concretization
        method = request_parser.get_method()
        concrete['method'] = method
        
        # query string
        post_query_string = ""
        get_query_string = request_parser.get_query_string()
        if method == "POST" and "Content-type" in request_parser.get_headers() and "multipart/form-data" not in request_parser.get_headers()['Content-Type']:
            # POST parameters, multipart/form-data not yet supported
            post_query_string = request_parser.recv_body() #"&".join(a for a in [query_string, request_parser.recv_body()] if len(a)>0)
        if  "Content-type" in request_parser.get_headers() and "multipart/form-data" in request_parser.get_headers()['Content-Type']:
            print("multipart/form-data not yet supported")

        # for each request\response I need
        aslanpp_params_no_questionmark = ""
        aslanpp_params_questionmark = ""
        aslanpp_cookie_no_questionmark = ""
        aslanpp_cookie_questionmark = ""
        aslanpp_cookie2_no_questionmark = ""
        aslanpp_cookie2_questionmark = ""

        # convert GET parameters
        if get_query_string:
            # saving the concrete parameters
            concrete_get_params = [couple.split("=") for couple in get_query_string.split("&")]

            # parse the parameters and retrieve ASLan++ code and mapping
            aslanpp_no_questionmark, aslanpp_questionmark, mapping_get = _parse_parameters(model, concrete_get_params)
            aslanpp_params_no_questionmark += aslanpp_no_questionmark
            aslanpp_params_questionmark += aslanpp_questionmark

            # save get param in concretization
            concrete['get_params'] = mapping_get

        # convert POST parameters
        if post_query_string:
            # saving the concrete parameters
            concrete_post_params = [couple.split("=") for couple in post_query_string.split("&")]

            # parse the parameters and retrieve ASLan++ code and mapping
            aslanpp_no_questionmark, aslanpp_questionmark, mapping_post = _parse_parameters(model, concrete_post_params)
            aslanpp_params_no_questionmark += aslanpp_no_questionmark
            aslanpp_params_questionmark += aslanpp_questionmark

            # save get param in concretization
            concrete['post_params'] = mapping_post

        if aslanpp_params_no_questionmark == "":
            aslanpp_params_no_questionmark = "none"
        else:
            aslanpp_params_no_questionmark = aslanpp_params_no_questionmark[:-5]
        if aslanpp_params_questionmark == "":
            aslanpp_params_questionmark = "none"
        else:
            aslanpp_params_questionmark = aslanpp_params_questionmark[:-5]

        # convert cookie in the request
        try:
            cookie_request = request_parser.get_headers()['Cookie']

            simple_cookie = Cookie.SimpleCookie(cookie_request) 
            concrete_cookie = [[item,simple_cookie[item].value] for item in simple_cookie]
            
            # parse the parameters and retrieve ASLan++ code, constants, variables and mapping
            cookie_no_questionmark, cookie_questionmark, cookie_mapping = _parse_parameters(model, concrete_cookie)
            aslanpp_cookie_no_questionmark += cookie_no_questionmark[:-5]
            aslanpp_cookie_questionmark += cookie_questionmark[:-5]

            # save the mapping cookies
            concrete['cookies'] = cookie_mapping
        except KeyError:
            aslanpp_cookie_no_questionmark = "none"
            aslanpp_cookie_questionmark = "none"
            pass


        # check the response
        response_parser = HttpParser()
        response_parser.execute(http_response,len(http_response))

        # Location
        # get the returned page by checking the Location field in
        # the header. If Location is set, it means is a 302 Redirect
        # and the client is receiving a different page back in the response
        try:
            location = response_parser.get_headers()['Location']
            # prepend the letter p since in ASLan++ constants should start with a char
            return_page = "p{}".format(urlparse(location).path.partition("?")[0].replace(".","_").replace("/","_"))
            model._page_constants.add(return_page)
        except KeyError:
            return_page = page

        # parse cookie in the response
        try:
            set_cookie_header = response_parser.get_headers()['Set-Cookie']
            # parse new cookie
            simple_cookie = Cookie.SimpleCookie(set_cookie_header) 
            cookies = [[item,simple_cookie[item].value] for item in simple_cookie]
            
            # parse the parameters and retrieve ASLan++ code, constants, variables and mapping
            aslanpp_cookie2_no_questionmark, aslanpp_cookie2_questionmark, cookie2_mapping = _parse_parameters(model, cookies)
            aslanpp_cookie2_no_questionmark += cookie_no_questionmark[:-5]
            aslanpp_cookie2_questionmark += cookie_questionmark[:-5]

            # save the mapping cookies
            concrete['cookies'] = cookie2_mapping

        except KeyError:
            aslanpp_cookie2_no_questionmark = "none"
            aslanpp_cookie2_questionmark = "non" 
            pass



        model._webapp_branch += request_skeleton.format(page,
                aslanpp_params_questionmark, aslanpp_cookie_questionmark,
                returntag, return_page, "none", aslanpp_cookie2_no_questionmark,
                returntag)


        model._client_branch += client_skeleton.format(page,
                aslanpp_params_no_questionmark,
                aslanpp_cookie_no_questionmark, returntag, return_page, returntag)

        model._concretization[returntag] = concrete
        
        # save tag in taglist and increment the tag number
        model._taglist.add(returntag)

        # increate tag
        i_tag +=1

        return returntag
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)

def _parse_parameters( model, line_parsed):
    """ Translates line_parsed in ASLan++ and returns the ASLan++ code, constants, variables and mapping. """
    global var_tag
    global var_i 
    aslanpp_questionmark = ""
    aslanpp_no_questionmark = ""
    constants = set()
    variables = set()
    mapping = dict()
    for c in line_parsed:
        # replace non alphanumeric char with nothing
        key = re.sub("[^a-zA-Z0-9]","", c[0].lower())
        # replace begining of key if it doesn't start with a lower case letter
        key = re.sub("^[^a-z]","", key)
        value = "{}{}".format(var_tag, var_i)
        var_i += 1

        # ASLan++ constants and variables
        model._params_constants.add(key)
        model._params_webapp_variables.add(value)

        # ASLan++ code where the variable "value" doesn't have a question mark
        aslanpp_no_questionmark += "{}.eq.{}.emp.".format(key, value)

        # ASLan++ code where the variable "value" has a question mark
        aslanpp_questionmark += "{}.eq.?{}.emp.".format(key, value)

        # concretization mapping
        mapping[c[0]] = [key, value]
    return aslanpp_no_questionmark, aslanpp_questionmark, mapping

def _parse_database(model):
    """ Parses a SQL file, extracts the tables and populate the model class. """
    with open(model.sql_file) as f:
        line = f.read()
        tables_name = re.findall("CREATE TABLE[a-zA-Z ]*`(.*)`", line)
        for t in tables_name:
            model._aslanpp_tables.add(t)
            model._init_database += populate_database_skeleton.format(t)


def _is_nonpublic(header,body):
    """Checks if a page is accessible even if the requests is made without cookies.
       This is used to understand if a page should be *public* or *nonpublic* in the ASLan++ model. 
    """
    # Python versins older than 2.7.9 have an SNIMissingWarning issue
    # so right now only HTTP requests are supported and not HTTPS
    # https://urllib3.readthedocs.io/en/latest/advanced-usage.html#ssl-warnings

    url = "http://" + header.get_headers()['Host'] + header.get_url()
    print("Trying {}".format(url))
    # I don't want the cookie to be part of the header
    h = {k:v for (k,v) in header.get_headers().iteritems() if k != "Cookie"}
    payload = body
    r = 0
    if header.get_method() == "GET":
        r = requests.get(url, verify=False, headers=h, allow_redirects=False)
    elif header.get_method() == "POST":
        r = requests.post(url,data=payload, verify=False, headers=h, allow_redirects=False)
    print("status {}".format(r.status_code))
    if r.status_code == 200:
        return False
    else:
        return True
