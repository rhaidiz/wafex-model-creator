from burp import IBurpExtender
from burp import IContextMenuFactory

from javax.swing import JPanel;
from javax.swing import JMenuItem;

class BurpExtender(IBurpExtender, IContextMenuFactory):

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
                for msg in messages:
                    request = "".join(chr(b) for b in msg.getRequest())
                    print(request)
                    response = "".join(chr(b) for b in msg.getResponse())
                    print(response)

            menu.addActionListener(listener)
            ret.append(menu)
        return ret

