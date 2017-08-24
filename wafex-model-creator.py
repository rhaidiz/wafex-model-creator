import io
import re
import sys
import json
import Cookie
import requests

from os.path import basename

from burp import ITab
from burp import ITextEditor
from burp import IBurpExtender
from burp import IMessageEditor
from burp import IContextMenuFactory

from javax.swing import JFrame
from javax.swing import JTable
from javax.swing import JPanel
from javax.swing import JButton
from javax.swing import JMenuItem
from javax.swing import JSplitPane
from javax.swing import JPopupMenu
from javax.swing import JTextField
from javax.swing import JTabbedPane
from javax.swing import JOptionPane
from javax.swing import GroupLayout
from javax.swing import JScrollPane
from javax.swing import JFileChooser
from javax.swing import BorderFactory
from javax.swing.table import DefaultTableModel
from javax.swing.filechooser import FileNameExtensionFilter

from java.awt import Dimension
from java.awt import BorderLayout
from java.awt import GridBagLayout
from java.awt.event import MouseAdapter
from java.awt.event import ActionListener
from java.awt.event import ComponentListener

from urlparse import urlparse
from http_parser.pyparser import HttpParser


from javafx.scene import Scene
from javafx.application import Platform
from javafx.embed.swing import JFXPanel
from javafx.scene.layout import BorderPane
from javafx.scene.layout import AnchorPane

from java.lang import Runnable
from javafx.event import EventHandler
from javafx.scene.input import KeyEvent
from javafx.scene.input import KeyCode

from java.util import Collections
from java.util.function import Consumer
from java.util.function import Function
from java.util.function import Predicate

# this should implicitly starts the JavaFX runtime
# so that I can put the imports here
JFXPanel()

# prevent the JavaFX runtime to finish after the extention loaded
# otherwise if I try to reload the extension the JavaFX runtime won't 
# load again.
Platform.setImplicitExit(False)

from javafx.scene.control import TextArea
from javafx.scene.layout import StackPane

from org.fxmisc.richtext import CodeArea
from org.fxmisc.richtext import CodeArea
from org.fxmisc.richtext import LineNumberFactory
from org.fxmisc.flowless import VirtualizedScrollPane
from org.fxmisc.richtext.model import StyleSpans
from org.fxmisc.richtext.model import StyleSpansBuilder

class jc(Consumer):
    def __init__(self, fn):
        self.accept=fn

class jf(Function):
    def __init__(self, fn):
        self.apply = fn

class jp(Predicate):
    def __init__(self, fn):
        self.test = fn


# syntax highlight keywords for aslanpp
KEYWORD_PATTERN="while|specification|channel_model|CCM|ICM|ACM|entity|import|types|symbols|nonpublic|noninvertible|macros|clauses|equations|body|breakpoints|new|any|where|send|receive|over|retract|assert|constraints|goals|forall|exists|Actor|for"
CONDITIONAL_PATTERN = "select|on|if|else|elseif|then"
TYPES_PATTERN = "fact|message|text|agent|set"
PARENT_PATTERN = "\{|\}"
COMMENT_PATTERN = "%(.*)"

PATTERN = "(?P<keyword>"+KEYWORD_PATTERN+")|(?P<brace>"+PARENT_PATTERN+")|(?P<comment>"+COMMENT_PATTERN+")|(?P<types>"+TYPES_PATTERN+")|(?P<cond>"+CONDITIONAL_PATTERN+")"

# syntax highlight colors file for aslanpp
ASLANPP_SYNTAX_HIGHLIGHT = "file:///Users/federicodemeo/Documents/Universita/PhD/WAFEx/wafex-model-creator/java-keywords.css"

def computeHighlighting(text):
    lastKwEnd = 0
    spansBuilder = StyleSpansBuilder()
    for m in re.finditer(PATTERN,text):
        styleClass = "keyword"
        if m.group("keyword"):
            styleClass = "keyword"
        elif m.group("brace"):
            styleClass = "paren"
        elif m.group("comment"):
            styleClass = "comment"
        elif m.group("types"):
            styleClass = "types"
        elif m.group("cond"):
            styleClass = "conditional"
        spansBuilder.add(Collections.emptyList(), m.start() - lastKwEnd)
        spansBuilder.add(Collections.singleton(styleClass), m.end() - m.start())
        lastKwEnd = m.end()
    spansBuilder.add(Collections.emptyList(), len(text)- lastKwEnd)
    return spansBuilder.create()

class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, ComponentListener, ActionListener, MouseAdapter):

    taglist = []
    tag = "tag"
    i_tag = 0

    _sql_file = None

    var_tag = "Var_"
    var_tag_i = 0

    # contains the messages to translate
    _messages = []

    # used to keep track when to refresh the table
    _reload_table = False

    # contains the messages to show in the messages table
    _table_data = []

    _search_pattern = "Entity\*->\*Actor:http_request\([0-9\.\-_A-Za-z]*,[0-9_\.\-A-Za-z]*,[_0-9\.\-A-Za-z]*\)\.{}"
    
    request_skeleton = """
    \t\t\t\ton(?Entity*->*Actor:http_request({},{},{}).{}.?WebNonce):{{
    \t\t\t\t% todo: request's behavior here
    \t\t\t\tActor*->*Entity:http_response({},{}).{}.WebNonce;
    \t\t\t}}
    """

    client_skeleton = """
    \t\t\t\ton(Actor*->*Webapplication:http_request({},{},{}).{}.?WebNonce):{{
    \t\t\t\t% todo: request's behavior here
    \t\t\t\tWebapplication*->*Actor:http_response({},{}).{}.WebNonce;
    \t\t\t}}
    """
    populate_database_skeleton = "db->add({});\n"

    def registerExtenderCallbacks(self, callbacks):

        self._panel = JPanel()
        self._panel.setLayout(BorderLayout())
        #self._panel.setSize(400,400)

        # sourrounding try\except because Burp is not giving enough info
        try:

            # creating all the UI elements
            # create the split pane
            self._split_pane_horizontal = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
            self._split_panel_vertical = JSplitPane(JSplitPane.VERTICAL_SPLIT)

            # create panels
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

            # create the tabbed pane used to show request\response
            self._tabbed_pane = JTabbedPane(JTabbedPane.TOP)
            
            # create the tabbed pane used to show aslan++\concretization file
            self._tabbed_pane_editor = JTabbedPane(JTabbedPane.TOP)

            # create the bottom command for selecting the SQL file and 
            # generating the model
            self._button_generate = JButton('Generate!', actionPerformed=self._generate_model)
            self._button_save = JButton('Save', actionPerformed=self._save_model)
            self._button_select_sql = JButton('Select SQL', actionPerformed=self._select_sql_file)
            self._text_field_sql_file = JTextField(20)

            self._panel_bottom_commands = JPanel()
            layout = GroupLayout(self._panel_bottom_commands)
            layout.setAutoCreateGaps(True)
            layout.setAutoCreateContainerGaps(True)
            seq_layout = layout.createSequentialGroup()
            seq_layout.addComponent(self._text_field_sql_file)
            seq_layout.addComponent(self._button_select_sql)
            seq_layout.addComponent(self._button_generate)
            seq_layout.addComponent(self._button_save)
            layout.setHorizontalGroup(seq_layout)

            # create the message editors that will be used to show request and response
            self._message_editor_request = callbacks.createMessageEditor(None,True)
            self._message_editor_response = callbacks.createMessageEditor(None,True)

            # create the table that will be used to show the messages selected for
            # the translation

            self._columns_names = ('Host','Method','URL')
            dataModel = NonEditableModel(self._table_data, self._columns_names)
            self._table = JTable(dataModel)
            self._scrollPane = JScrollPane()
            self._scrollPane.getViewport().setView((self._table))

            popmenu = JPopupMenu()
            delete_item = JMenuItem("Delete")
            delete_item.addActionListener(self)
            popmenu.add(delete_item)
            self._table.setComponentPopupMenu(popmenu)
            self._table.addMouseListener(self)

            # add all the elements
            self._panel_request.add(self._message_editor_request.getComponent())
            self._panel_response.add(self._message_editor_response.getComponent())

            self._tabbed_pane.addTab("Request", self._panel_request)
            self._tabbed_pane.addTab("Response", self._panel_response)

            self._panel_top.add(self._scrollPane, BorderLayout.CENTER)

            self._panel_bottom.add(self._tabbed_pane, BorderLayout.CENTER)
            scroll = JScrollPane(self._panel_bottom)

            self._panel_right.add(self._tabbed_pane_editor, BorderLayout.CENTER)
            self._panel_right.add(self._panel_bottom_commands, BorderLayout.PAGE_END)

            self._split_panel_vertical.setTopComponent(self._panel_top)
            self._split_panel_vertical.setBottomComponent(scroll)
            self._split_pane_horizontal.setLeftComponent(self._split_panel_vertical)
            self._split_pane_horizontal.setRightComponent(self._panel_right)

            self._panel.addComponentListener(self)
            self._panel.add(self._split_pane_horizontal)

            self._callbacks = callbacks
            callbacks.setExtensionName("WAFEx")
            callbacks.addSuiteTab(self)
            callbacks.registerContextMenuFactory(self)
        except Exception as e:
            print(e)

    def mouseClicked(self, e):
        """ Positions the Aslan++ editor to the selected request position. """
        try:
            index = self._table.getSelectedRow()
            c = self._messages[index]
            print(len(c))
            message = c[0]
            tag = c[1]
            self._message_editor_request.setMessage(message.getRequest(), True)
            self._message_editor_response.setMessage(message.getResponse(), False)
            if tag != None:
                document = self._jfxp_aslanpp._editor.getText()
                start, end = self._search_tag_position(tag, document)
                self._jfxp_aslanpp._editor.moveTo(start)
                self._jfxp_aslanpp._editor.selectRange(start, end)
                self._jfxp_aslanpp._editor.requestFollowCaret()
                self._jfxp_aslanpp._editor.requestFocus()
        except Exception as e:
            print(e)

    
    def _search_tag_position(self, tag, text):
        """ Searches for a particular tag in a given text and return its position. """
        pattern = self._search_pattern.format(tag)
        for m in re.finditer(pattern, text):
            return m.start(), m.end()

    def actionPerformed(self, e):
        """ Performs the delete action. """
        try:
            index = self._table.getSelectedRow()
            del self._table_data[index]
            del self._messages[index]
            self._table.getModel().setDataVector(self._table_data, self._columns_names)
        except Exception as e:
            print(e)
    
    def _save_model(self, e):
        """ Saves the current Aslan++ model and concretization file. """
        try:
            chooseFile = JFileChooser()
            filter_ = FileNameExtensionFilter("txt files", ["txt"])
            chooseFile.addChoosableFileFilter(filter_)

            ret = chooseFile.showDialog(self._panel, "Choose file")

            if ret == JFileChooser.APPROVE_OPTION:
                self._model_name = chooseFile.getSelectedFile().getPath()
                with open("{}.aslan++".format(self._model_name),"w") as f:
                    f.write(self._jfxp_aslanpp._editor.getText())
                print("model created")

                with open("{}.txt".format(self._model_name),"w") as f:
                    f.write(self._jfxp_concretization._editor.getText())

        except Exception as e:
            print(e)

    
    def _generate_model(self, e):
        try:
            self._model, self._concrete = self._generateWAFExModel(self._messages)
            #self._text_area_concretization_editor.setText(concrete)
            Platform.runLater(UpdateEditor(self._jfxp_aslanpp._editor, self._jfxp_concretization._editor, self._model, self._concrete))
        except Exception as e:
            print(e)

    def _select_sql_file(self, e):
        """ Shows a JFileChooser dialog to select the SQL file to use for creating
        the model. """
        try:
            chooseFile = JFileChooser()
            filter_ = FileNameExtensionFilter("txt files", ["txt"])
            chooseFile.addChoosableFileFilter(filter_)

            ret = chooseFile.showDialog(self._panel, "Choose file")

            if ret == JFileChooser.APPROVE_OPTION:
                self._sql_file = chooseFile.getSelectedFile().getPath()
            else:
                self._sql_file = None
            self._text_field_sql_file.setText(""+self._sql_file)
        except Exception as e:
            print(e)


    def getTabCaption(self):
        return "WAFEx"

    def getUiComponent(self):
        try:
            Platform.runLater(EditorTabUI(self))
            return self._panel
        except Exception as e:
            print(e)
    

    def componentShown(self, e):
        self._split_pane_horizontal.setDividerLocation(0.25);
        # populate the table with the selected requests\response
        try:
            if self._reload_table:
                print("reload")
                self._table_data = []       # empty _table_data (not too cool but quick)
                for c in self._messages:
                    msg = c[0]
                    http_request = self._byte_array_to_string(msg.getRequest())
                    request_parser = HttpParser()
                    request_parser.execute(http_request,len(http_request))

                    host = msg.getHttpService().getHost()
                    page = request_parser.get_url()
                    method = request_parser.get_method()

                    tmp = [host, method, page]
                    self._table_data += [tmp]
                self._table.getModel().setDataVector(self._table_data, self._columns_names)
                self._reload_table = False
        except Exception as e:
            print(e)


    def componentHidden(self, e):
        return

    def componentMoved(self, e):
        return
    
    def componentResized(self, e):
        self._split_pane_horizontal.setDividerLocation(0.25)
    
    def createMenuItems(self, invocation):
        ret = []
        try:
            #if(invocation.getInvocationContext() == invocation.CONTEXT_TARGET_SITE_MAP_TREE or invocation.getInvocationContext() == invocation.CONTEXT_TARGET_SITE_MAP_TABLE):
            if(invocation.getInvocationContext() == invocation.CONTEXT_TARGET_SITE_MAP_TABLE):
                menu = JMenuItem("Send to WAFEx")
                messages = invocation.getSelectedMessages()
                def listener(e):
                    """ Generates a new WAFEx model. """
                    #self._generateWAFExModel(messages)
                    self._addToGeneration(messages)
                menu.addActionListener(listener)
                ret.append(menu)
        except Exception as e:
            print(e)
        return ret

    def _addToGeneration(self, messages):
        for msg in messages:
            self._messages += [[msg,None]]
        self._reload_table = True


    def _generateWAFExModel(self,messages):
        # start the generation
        try:
            if len(messages) <= 0:
                frame = JFrame("Error");
                JOptionPane.showMessageDialog(frame, "No messages!","Error",JOptionPane.ERROR_MESSAGE)
                return
            if self._sql_file == None:
                frame = JFrame("Error");
                replay = JOptionPane.showConfirmDialog(frame, "No SQL file selected!\nDo you want to continue?", "Info", JOptionPane.YES_NO_OPTION)
                if replay == JOptionPane.NO_OPTION:
                    return
            self.var_tag_i = 0
            self.i_tag = 0
            model = AslanppModel()

            print("create model")
            print("webapp branch {}".format(model._webapp_branch))
            print("size before creation {}".format(len(messages)))
            for c in messages:
                # from byte to char Request and Response
                # for some reason b can be a negative value causing a crash
                # so I put a check to ensure b is in the right range 
                msg = c[0]
                http_request = "".join(chr(b) for b in msg.getRequest() if b >= 0 and b <= 256)
                http_response = "".join(chr(b) for b in msg.getResponse() if b >=0 and b <= 256)
                protocol = msg.getHttpService().getProtocol()
                # save the tag number generate by _parseHttpRequestResponse in the _messages array
                c[1] = self._parseHttpRequestResponse(model, http_request, http_response, protocol)

            # create the database
            if self._sql_file != None:
                self._parse_database(model, self._sql_file)


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


            concrete = json.dumps(model._concretization_file, indent=1)
            return skeleton, concrete

            with open("m.aslan++","w") as f:
                f.write(skeleton)
            print("model created")

            with open("concrete.txt","w") as f:
                f.write(json.dumps(model._concretization_file))
           
        except Exception as e:
            print(e)

    def _byte_array_to_string(self, byte):
        return "".join(chr(b) for b in byte if b >= 0 and b <= 256)


    def _parseHttpRequestResponse(self, model, http_request, http_response, protocol):
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
            aslanpp_params, constants, variables, mapping = self._parse_parameters(params_concrete)

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
            aslanpp_cookie, constants, variables, mapping = self._parse_parameters(cookie_concrete)

            model._aslanpp_nonpublic_constants |= constants 
            model._aslanpp_variables |= variables
            model._mapping += mapping

            cookie = "none" if not aslanpp_cookie else aslanpp_cookie[:-3]
        except KeyError:
            cookie = "none"
            pass

        # check if the page should be nonpublic
        page_nonpublic = self._is_nonpublic(request_parser,query_string)

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
            _is_nonpublic = self._is_nonpublic(response_parser,"")
            if _is_nonpublic:
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
            aslanpp_cookie, constants, variables, mapping = self._parse_parameters(cookies)

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

        # save tag to return
        tag = self.i_tag

        # increate tag
        self.i_tag +=1

        return "tag{}".format(tag)


    def _parse_parameters(self,line_parsed):
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

    def _parse_database(self, model, sql_file):
        """ Parses a SQL file, extracts the tables and populate the model class. """
        with open(sql_file) as f:
            line = f.read()
            tables_name = re.findall("CREATE TABLE[a-zA-Z ]*`(.*)`", line)
            for t in tables_name:
                model._aslanpp_tables.add(t)
                model._init_database += self.populate_database_skeleton.format(t)


    def _is_nonpublic(self,header,body):
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
    """ Extends DefaultTableModel to overwrite the possibility of editing a cell. """
    def isCellEditable(self,row, column):
        return False

class UpdateEditor(Runnable):
    """ Update editors content. """
    def __init__(self, aslanpp_editor, concretization_editor, aslanpp_model, concretization):
        self._aslanpp_editor = aslanpp_editor
        self._concretization_editor = concretization_editor
        self._aslanpp_model = aslanpp_model
        self._concretization = concretization

    def run(self):
        self._aslanpp_editor.replaceText(0, 0, self._aslanpp_model)
        self._concretization_editor.replaceText(0, 0, self._concretization)
    
class EditorTabUI(Runnable):
    """ Create the UI for the code editor. """
    
    def __init__(self, parent):
        self._parent = parent

    def run(self):
        self._parent._jfxp_aslanpp = AslanppEditor()
        self._parent._tabbed_pane_editor.addTab("ASLan++", self._parent._jfxp_aslanpp)

        self._parent._jfxp_concretization = ConcretizationEditor()
        self._parent._tabbed_pane_editor.addTab("Concretization",self._parent._jfxp_concretization)

class AslanppEditor(JFXPanel):

    def __init__(self):
        self._editor = MyCodeArea()
        borderPane = BorderPane()
        self._editor.setParagraphGraphicFactory(LineNumberFactory.get(self._editor))
        self._editor.richChanges().filter(jp(lambda ch: not ch.getInserted().equals(ch.getRemoved()))).subscribe(jc(lambda change: self._editor.setStyleSpans(0, computeHighlighting(self._editor.getText()))))
        borderPane.setCenter(VirtualizedScrollPane(self._editor))
        scene = Scene(borderPane)
        scene.getStylesheets().add(ASLANPP_SYNTAX_HIGHLIGHT);
        self.setScene(scene)

class ConcretizationEditor(JFXPanel):

    def __init__(self):
        self._editor = MyCodeArea()
        borderPane = BorderPane()
        self._editor.setParagraphGraphicFactory(LineNumberFactory.get(self._editor))
        borderPane.setCenter(VirtualizedScrollPane(self._editor))
        scene = Scene(borderPane)
        scene.getStylesheets().add(ASLANPP_SYNTAX_HIGHLIGHT);
        self.setScene(scene)


class MyCodeArea(CodeArea, EventHandler):
    """ Extends CodeArea to capture some shortcut such as select-all, copy, paste. """

    def __init__(self):
        self.setOnKeyReleased(self)

    def handle(self, event):
        keyCode = event.getCode()
        caret = self.getCaretPosition()
        if (event.isControlDown()):
            if keyCode == KeyCode.A:
                self.selectAll()
            if keyCode == KeyCode.C:
                self.copy()
            if keyCode == KeyCode.V:
                self.paste()
