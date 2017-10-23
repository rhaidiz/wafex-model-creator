import re
import os
import sys

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

from http_parser.pyparser import HttpParser

from javafx.application import Platform
from javafx.embed.swing import JFXPanel

from java.lang import Runnable
from javafx.scene.input import KeyEvent
from javafx.scene.input import KeyCode


# this should implicitly starts the JavaFX runtime
# so that I can put the imports here
JFXPanel()

# prevent the JavaFX runtime to finish after the extention loaded
# otherwise if I try to reload the extension the JavaFX runtime won't 
# load again.
Platform.setImplicitExit(False)


# custom import
from aslanppmodel import AslanppModel
from aslanppeditor import AslanppEditor
from concretizationeditor import ConcretizationEditor
import converter



class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, ComponentListener, ActionListener, MouseAdapter):
    # contains the messages to show in the messages table
    _table_data = []

    # contains the messages to translate
    _messages = []

    # used to keep track when to refresh the table
    _reload_table = False

    _sql_file = None

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
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)

    def getTabCaption(self):
        return "WAFEx"

    def getUiComponent(self):
        try:
            Platform.runLater(EditorTabUI(self))
            return self._panel
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
    

    def componentShown(self, e):
        self._split_pane_horizontal.setDividerLocation(0.25);
        # populate the table with the selected requests\response
        try:
            if self._reload_table:
                print("reload")
                self._table_data = []       # empty _table_data (not too cool but quick)
                for c in self._messages:
                    msg = c[0]
                    http_request = converter._byte_array_to_string(msg.getRequest())
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


    def actionPerformed(self, e):
        """ Performs the delete action. """
        try:
            index = self._table.getSelectedRow()
            del self._table_data[index]
            del self._messages[index]
            self._table.getModel().setDataVector(self._table_data, self._columns_names)
        except Exception as e:
            print(e)
    
    def _search_tag_position(self, tag, text):
        """ Searches for a particular tag in a given text and return its position. """
        pattern = self._search_pattern.format(tag)
        for m in re.finditer(pattern, text):
            return m.start(), m.end()
    
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
                    skeleton = self._jfxp_aslanpp._editor.getText()
                    skeleton = skeleton.replace("@filename",basename(self._model_name))
                    f.write(skeleton)
                print("model created")

                with open("{}.txt".format(self._model_name),"w") as f:
                    f.write(self._jfxp_concretization._editor.getText())

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



    def _addToGeneration(self, messages):
        for msg in messages:
            self._messages += [[msg,None]]
        self._reload_table = True

    def _generate_model(self, e):
        if len(self._messages) <= 0:
            frame = JFrame("Error");
            JOptionPane.showMessageDialog(frame, "No messages!","Error",JOptionPane.ERROR_MESSAGE)
            return
        if self._sql_file == None:
            frame = JFrame("Error");
            replay = JOptionPane.showConfirmDialog(frame, "No SQL file selected!\nDo you want to continue?", "Info", JOptionPane.YES_NO_OPTION)
            if replay == JOptionPane.NO_OPTION:
                return

        # create a new AslanppModel
        model = AslanppModel()
        # save _sql_file
        model._sql_file = self._sql_file

        for c in self._messages:
            # from byte to char Request and Response
            # for some reason b can be a negative value causing a crash
            # so I put a check to ensure b is in the right range 
            msg = c[0]
            if msg.getRequest() == None or msg.getResponse() == None:
                # do not convert empty messages
                continue
            http_request = "".join(chr(b) for b in msg.getRequest() if b >= 0 and b <= 256)
            http_response = "".join(chr(b) for b in msg.getResponse() if b >=0 and b <= 256)
            protocol = msg.getHttpService().getProtocol()
            # save the tag number generate by _parseHttpRequestResponse in the _messages array
            c[1] = converter._parseHttpRequestResponse(model, http_request, http_response, protocol)

        # generate the ASLan++ code
        self._model, self._concrete = converter._generateWAFExModel(model)
        Platform.runLater(UpdateEditor(self._jfxp_aslanpp._editor, self._jfxp_concretization._editor, self._model, self._concrete))


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
        self._aslanpp_editor.replaceText(0, self._aslanpp_editor.getLength(), self._aslanpp_model)
        self._concretization_editor.replaceText(0, self._concretization_editor.getLength(), self._concretization)
    
class EditorTabUI(Runnable):
    """ Create the UI for the code editor. """
    def __init__(self, parent):
        self._parent = parent

    def run(self):
        self._parent._jfxp_aslanpp = AslanppEditor()
        self._parent._tabbed_pane_editor.addTab("ASLan++", self._parent._jfxp_aslanpp)

        self._parent._jfxp_concretization = ConcretizationEditor()
        self._parent._tabbed_pane_editor.addTab("Concretization",self._parent._jfxp_concretization)


