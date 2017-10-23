from mycodearea import MyCodeArea
from javafx.scene import Scene
from javafx.scene.layout import BorderPane
from javafx.embed.swing import JFXPanel
from org.fxmisc.richtext import LineNumberFactory
from org.fxmisc.flowless import VirtualizedScrollPane

class ConcretizationEditor(JFXPanel):
    """ Concretization Editor. """

    def __init__(self):
        self._editor = MyCodeArea()
        borderPane = BorderPane()
        self._editor.setParagraphGraphicFactory(LineNumberFactory.get(self._editor))
        borderPane.setCenter(VirtualizedScrollPane(self._editor))
        scene = Scene(borderPane)
        #scene.getStylesheets().add(ASLANPP_SYNTAX_HIGHLIGHT);
        self.setScene(scene)
