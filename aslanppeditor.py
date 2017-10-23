import re

from mycodearea import MyCodeArea

from java.util import Collections
from javafx.scene import Scene
from javafx.embed.swing import JFXPanel
from javafx.scene.layout import BorderPane
from java.util.function import Consumer
from java.util.function import Function
from java.util.function import Predicate
from org.fxmisc.richtext.model import StyleSpans
from org.fxmisc.richtext.model import StyleSpansBuilder
from org.fxmisc.richtext import LineNumberFactory
from org.fxmisc.flowless import VirtualizedScrollPane

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
ASLANPP_SYNTAX_HIGHLIGHT = "file:///Users/federicodemeo/Documents/Universita/PhD/WAFEx/wafex-model-creator/style-keywords.css"

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

class AslanppEditor(JFXPanel):
    """ ASLAn++ Editor."""

    def __init__(self):
        self._editor = MyCodeArea()
        borderPane = BorderPane()
        self._editor.setParagraphGraphicFactory(LineNumberFactory.get(self._editor))
        self._editor.richChanges().filter(jp(lambda ch: not ch.getInserted().equals(ch.getRemoved()))).subscribe(jc(lambda change: self._editor.setStyleSpans(0, computeHighlighting(self._editor.getText()))))
        borderPane.setCenter(VirtualizedScrollPane(self._editor))
        scene = Scene(borderPane)
        scene.getStylesheets().add(ASLANPP_SYNTAX_HIGHLIGHT);
        self.setScene(scene)
