from javafx.event import EventHandler
from org.fxmisc.richtext import CodeArea

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



