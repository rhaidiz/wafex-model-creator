import io
import re
import sys
import json
import Cookie
import requests

from os.path import basename

from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import ITab
from burp import ITextEditor
from burp import IMessageEditor

from javax.swing import JPanel
from javax.swing import JTabbedPane
from javax.swing import JScrollPane
from javax.swing import GroupLayout
from javax.swing import JTextArea
from javax.swing import JScrollPane
from javax.swing import JButton
from javax.swing import JTextArea
from javax.swing import JTextField
from javax.swing import JMenuItem
from javax.swing import JFileChooser
from javax.swing import JSplitPane
from javax.swing import JTable
from javax.swing.table import DefaultTableModel
from javax.swing.filechooser import FileNameExtensionFilter
from javax.swing import BorderFactory
from java.awt import BorderLayout
from java.awt import GridBagLayout
from java.awt.event import ComponentListener
from java.awt import Dimension


from http_parser.pyparser import HttpParser
from urlparse import urlparse

class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, ComponentListener):

    taglist = []
    tag = "tag"
    i_tag = 0

    var_tag = "Var_"
    var_tag_i = 0
    
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

    def registerExtenderCallbacks(self, callbacks):

        self._panel = JPanel()
        #self._panel.setLayout(BorderLayout())
        self._panel.setLayout(BorderLayout())
        #self._panel.setLayout(GridBagLayout())
        self._panel.setSize(400,400)

        try:
            # creating all the UI elements
            self._split_pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
            self._split_pane_ = JSplitPane(JSplitPane.VERTICAL_SPLIT)
            self._split_pane_.setDividerLocation(0.5)
            self._split_pane.setDividerLocation(0.5)

            self._panel_top = JPanel()
            self._panel_top.setLayout(BorderLayout())
            self._panel_bottom = JPanel()
            self._panel_bottom.setLayout(BorderLayout())
            self._panel_right = JPanel()
            self._panel_right.setLayout(BorderLayout())
            self._panel_request = JPanel()
            self._panel_request.setLayout(BorderLayout())
            self._panel_response = JPanel()
            self._panel_response.setLayout(BorderLayout())


            self._tab_pane = JTabbedPane(JTabbedPane.TOP)

            self._button_generate = JButton('Generate!', actionPerformed=self._generate_model)
            self._button_select_sql = JButton('Select SQL', actionPerformed=self._select_sql_file)
            self._text_sql_file = JTextField(20)

            self._bottom_commands = JPanel()
            layout = GroupLayout(self._bottom_commands)
            layout.setAutoCreateGaps(True)
            layout.setAutoCreateContainerGaps(True)
            seq_layout = layout.createSequentialGroup()
            seq_layout.addComponent(self._text_sql_file)
            seq_layout.addComponent(self._button_select_sql)
            seq_layout.addComponent(self._button_generate)
            layout.setHorizontalGroup(seq_layout)

            self._model_editor = JTextArea()
            self._message_editor_request = callbacks.createMessageEditor(None,False)
            self._message_editor_response = callbacks.createMessageEditor(None,False)

            self._table_data = [
                    ['http://127.0.0.1/', 'GET' ,'/wiki.php']
               ]
            self._columns_names = ('Host','Method','URL')
            dataModel = self.NonEditableModel(self._table_data, self._columns_names)
            self._table = JTable(dataModel)
            self._scrollPane = JScrollPane()
            #scrollPane.setPreferredSize(Dimension(600,300))
            self._scrollPane.getViewport().setView((self._table))

            # add all the elements
            self._panel_request.add(self._message_editor_request.getComponent())
            self._panel_response.add(self._message_editor_response.getComponent())

            self._tab_pane.addTab("Request", self._panel_request)
            self._tab_pane.addTab("Response", self._panel_response)

            self._panel_top.add(self._scrollPane, BorderLayout.CENTER)

            self._panel_bottom.add(self._tab_pane, BorderLayout.CENTER)
            self._panel_bottom.add(self._bottom_commands, BorderLayout.PAGE_END)
            #self._panel_bottom.add(self._button_select_sql, BorderLayout.PAGE_END)
            #self._panel_bottom.add(self._button_generate, BorderLayout.PAGE_END)
            scroll = JScrollPane(self._panel_bottom)

            self._panel_right.add(self._model_editor, BorderLayout.CENTER)

            self._split_pane_.setTopComponent(self._panel_top)
            self._split_pane_.setBottomComponent(scroll)
            #self._split_pane_.setBottomComponent(self._panel_bottom)
            self._split_pane.setLeftComponent(self._split_pane_)
            self._split_pane.setRightComponent(self._panel_right)

            self._panel.addComponentListener(self)
            self._panel.add(self._split_pane)

            self._callbacks = callbacks
            callbacks.setExtensionName("WAFEx")
            callbacks.addSuiteTab(self)
            callbacks.registerContextMenuFactory(self)
        except Exception as e:
            print(e)

        return


    def _select_sql_file(self, e):
        """ Shows a JFileChooser dialog to select the SQL file to use for creating
        the model. """
        try:
            chooseFile = JFileChooser()
            filter_ = FileNameExtensionFilter("txt files", ["txt"])
            chooseFile.addChoosableFileFilter(filter_)

            ret = chooseFile.showDialog(self._panel, "Choose file")

            if ret == JFileChooser.APPROVE_OPTION:
                self._sql_file = chooseFile.getSelectedFile()
            else:
                self._sql_file = None
            self._text_sql_file.setText(""+self._sql_file.getPath())
        except Exception as e:
            print(e)

    def _generate_model(self, e):
        print("TBA")

    def getTabCaption(self):
        return "WAFEx"

    def getUiComponent(self):
        print("getUiComponent")
        return self._panel

    def componentShown(self, e):
        self._split_pane.setDividerLocation(0.5);
        self._new_split.setDividerLocation(0.5)
        print("focus")

    def componentHidden(self, e):
        print("hidden")

    def componentMoved(self, e):
        print("moved")
    
    def componentResized(self, e):
        #self._split_pane.setDividerLocation(0.5);
        #self._new_split.setDividerLocation(0.5)
        print("resized")
    
    def createMenuItems(self, invocation):
        ret = []
        try:
            #if(invocation.getInvocationContext() == invocation.CONTEXT_TARGET_SITE_MAP_TREE or invocation.getInvocationContext() == invocation.CONTEXT_TARGET_SITE_MAP_TABLE):
            if(invocation.getInvocationContext() == invocation.CONTEXT_TARGET_SITE_MAP_TABLE):
                menu = JMenuItem("Generate WAFEx model")
                messages = invocation.getSelectedMessages()
                def listener(e):
                    """ Generates a new WAFEx model. """
                    #self.generateWAFExModel(messages)
                    self.area.setText("PIPPO")
                menu.addActionListener(listener)
                ret.append(menu)
        except Exception as e:
            print(e)
        return ret


    def generateWAFExModel(self,messages):
        # reset some variables
        # self._webapp_branch = ""
        # self._client_branch = ""
        # self.i_tag = 0
        # self.aslanpp_constants = set()
        # self.aslanpp_nonpublic_constants = set()
        # self.aslanpp_variables = set()
        # self.taglist = set()
        # self.aslanpp_tables_nonpublic_constants = set()

        model = self.AslanppModel()

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
                self.parseHttpRequestResponse(model, http_request, http_response, protocol)

            # create the database
            self.parse_database(model, "/Users/federicodemeo/Downloads/chained.sql")


            # create a new model
            skeleton = open("skeleton.aslan++","r").read()
            if model._aslanpp_nonpublic_constants:
                nonpublic_constants = "nonpublic " + ",".join(item for item in model._aslanpp_nonpublic_constants) + " : text;"
                skeleton = skeleton.replace("@constants2",nonpublic_constants)
            else:
                skeleton = skeleton.replace("@constants2","")
            if model._aslanpp_constants:
                public_constants = ",".join(item for item in model._aslanpp_constants) + " : text;"
                skeleton = skeleton.replace("@constants",public_constants)
            else:
                skeleton = skeleton.replace("@constants","")
            if model._aslanpp_variables:
                variables = ", ".join(item for item in model._aslanpp_variables) + " : message;"
                skeleton = skeleton.replace("@webappsymbols",variables)
            else:
                skeleton = skeleton.replace("@webappsymbols","")
            if model._taglist:
                tags = ", ".join(item for item in model._taglist) + " : text;"
                skeleton = skeleton.replace("@tags",tags)
            else:
                skeleton = skeleton.replace("@tags","")
            skeleton = skeleton.replace("@webappbody",model._webapp_branch)
            skeleton = skeleton.replace("@honestbody",model._client_branch)

            if model._aslanpp_tables:
                nonpublic_constants = "nonpublic " + ",".join(item for item in model._aslanpp_tables) + " : text;"
                skeleton = skeleton.replace("@databasestructure",nonpublic_constants)
                skeleton = skeleton.replace("@databaseinit",model._init_database)
            else:
                skeleton = skeleton.replace("@databasestructure","")
                skeleton = skeleton.replace("@databaseinit","")


            with open("m.aslan++","w") as f:
                f.write(skeleton)
            print("model created")

            with open("concrete.txt","w") as f:
                f.write(json.dumps(model._concretization_file))
           
        except Exception as e:
            print(e)



    def parseHttpRequestResponse(self, model, http_request, http_response, protocol):
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
        url = protocol +"://"+ request_parser.get_headers()['Host'] +"/" + request_parser.get_url()

        # path (this string should not begin with something different from a character)
        page = re.sub("^[^a-z]*","",urlparse(url).path.replace(".","_").replace("/","_"))

        # method for concretization
        method = request_parser.get_method()
        
        query_string = ""
        # GET requests
        if method == "GET":
            # GET parameters
            query_string = request_parser.get_query_string()
        # POST requests
        elif method == "POST":
            # POST parameters
            query_string = request_parser.recv_body()

        # parse parameters
        params = "none"
        params_concrete = []
        if query_string:
            # saving the concrete parameters
            params_concrete = [couple.split("=") for couple in query_string.split("&")]

            # parse the parameters and retrieve ASLan++ code, constants, variables and mapping
            aslanpp_params, constants, variables, mapping = self.parse_parameters(params_concrete)

            model._aslanpp_nonpublic_constants |= constants 
            model._aslanpp_variables |= variables
            model._mapping += mapping

            # save ASLan++ parameters
            params = "none" if not aslanpp_params else aslanpp_params[:-3]

        # cookie in the request
        try:
            cookie_request = request_parser.get_headers()['Cookie']

            simple_cookie = Cookie.SimpleCookie(cookie_request) 
            cookie_concrete = [[item,simple_cookie[item].value] for item in simple_cookie]
            
            # parse the parameters and retrieve ASLan++ code, constants, variables and mapping
            aslanpp_cookie, constants, variables, mapping = self.parse_parameters(cookie_concrete)

            model._aslanpp_nonpublic_constants |= constants 
            model._aslanpp_variables |= variables
            model._mapping += mapping

            cookie = "none" if not aslanpp_cookie else aslanpp_cookie[:-3]
        except KeyError:
            cookie = "none"
            pass

        # check if the page should be nonpublic
        page_nonpublic = self.is_nonpublic(request_parser,query_string)

        if page_nonpublic:
            model._aslanpp_nonpublic_constants.add(page)
        else:
             model._aslanpp_constants.add(page)

        # check the response
        response_parser = HttpParser()
        response_parser.execute(http_response,len(http_response))

        # Location
        # get the returned page by checking the Location field in
        # the header. If Location is set, it means is a 302 Redirect
        # and the client is receiving a different page back in the response
        try:
            return_page = urlparse(response_parser.get_headers()['Location']).path.partition("?")[0].replace("/","_")
            is_nonpublic = self.is_nonpublic(response_parser,"")
            if is_nonpublic:
                model._aslanpp_nonpublic_constants.add(return_page)
            else:
                model._aslanpp_constants.add(return_page)
        except KeyError:
            return_page = page

        # and let's see if we have a new cookie
        try:
            set_cookie_header = response_parser.get_headers()['Set-Cookie']
            # parse new cookie
            simple_cookie = Cookie.SimpleCookie(set_cookie_header) 
            cookies = [[item,simple_cookie[item].value] for item in simple_cookie]
            
            # parse the parameters and retrieve ASLan++ code, constants, variables and mapping
            aslanpp_cookie, constants, variables, mapping = self.parse_parameters(cookies)

            model._aslanpp_nonpublic_constants |= constants 
            model._aslanpp_variables |= variables
            model._mapping += mapping

            return_cookie = "none" if not aslanpp_cookie else aslanpp_cookie[:-3]
        except KeyError:
            return_cookie = "none"
            pass

        tag = self.tag + str(self.i_tag)
        model._webapp_branch += self.request_skeleton.format(page, params,cookie,tag,return_page,return_cookie,tag)
        model._client_branch += self.client_skeleton.format(page, params,cookie,tag,return_page,return_cookie,tag)

        # create the concretization JSON
        model._concretization_file[tag] = {"method" : method, "url" : url, "params" : params_concrete,"cookie":return_cookie}
        
        # save tag in taglist and increment the tag number
        model._taglist.add("{}{}".format(self.tag,self.i_tag))
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

    def parse_database(self, model, sql_file):
        """ Parses a SQL file, extracts the tables and populate the model class. """
        with open(sql_file) as f:
            line = f.read()
            tables_name = re.findall("CREATE TABLE[a-zA-Z ]*`(.*)`", line)
            for t in tables_name:
                model._aslanpp_tables.add(t)
                model._init_database += self.populate_database_skeleton.format(t)


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

    class AslanppModel:
        """ Represents a new ASLan++ model. Create an object for each model
        and pass it the parsing method. """
        _aslanpp_constants = set()
        _aslanpp_nonpublic_constants = set()
        _aslanpp_variables = set()
        _mapping = []
        _taglist = set()
        _aslanpp_tables = set()
        _concretization_file = {}
        _webapp_branch = ""
        _client_branch = ""
        _init_database = ""

    class NonEditableModel(DefaultTableModel):
        def isCellEditable(self,row, column):
            return False
