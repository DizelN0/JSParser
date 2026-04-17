import javax.swing as swing
import java.awt as awt
import java.awt.datatransfer as dt
from burp import ITab


class JSAnalyzerUI(ITab):
    """
    UI for JS Parser.
    """

    def __init__(self, callbacks, export_callback):
        self.callbacks = callbacks
        self._export_callback = export_callback
        self._main_panel = None
        self._table = None
        self._table_model = None
        self._init_ui()

    #  ITab
    def getTabCaption(self):
        return "JS Parse"

    def getUiComponent(self):
        return self._main_panel

    # UI initialization
    def _init_ui(self):
        self._main_panel = swing.JPanel(awt.BorderLayout())

        # Table
        columns = ["URL", "Pattern", "Severity", "Matched", "Description"]
        self._table_model = swing.table.DefaultTableModel(columns, 0)
        self._table = swing.JTable(self._table_model)
        self._table.setAutoCreateRowSorter(True)
        self._table.getColumn("Severity").setPreferredWidth(80)
        self._table.getColumn("Pattern").setPreferredWidth(150)
        self._table.setDefaultRenderer(object, _SeverityRenderer())

        # Context menu for table (copy raw)
        self._table.setComponentPopupMenu(_TablePopupMenu(self._table))

        scroll_pane = swing.JScrollPane(self._table)
        self._main_panel.add(scroll_pane, awt.BorderLayout.CENTER)

        # Panel of buttons
        button_panel = swing.JPanel(awt.FlowLayout(awt.FlowLayout.LEFT))

        btn_copy = swing.JButton("Copy Selected", actionPerformed=self._copy_selected)
        btn_export_csv = swing.JButton("Export CSV", actionPerformed=lambda e: self._export("csv"))
        btn_export_json = swing.JButton("Export JSON", actionPerformed=lambda e: self._export("json"))
        btn_clear = swing.JButton("Clear", actionPerformed=self._clear)

        button_panel.add(btn_copy)
        button_panel.add(btn_export_csv)
        button_panel.add(btn_export_json)
        button_panel.add(btn_clear)

        self._main_panel.add(button_panel, awt.BorderLayout.SOUTH)

    # Public methods
    def update_table(self, results):
        if self._table_model is None:
            return
        swing.SwingUtilities.invokeLater(lambda: self._do_update_table(results))

    def _do_update_table(self, results):
        self._table_model.setRowCount(0)
        for f in results:
            row = [
                f["url"],
                f["pattern"],
                f["severity"],
                f["matched"][:50] + "..." if len(f["matched"]) > 50 else f["matched"],
                f["description"]
            ]
            self._table_model.addRow(row)

    def _copy_selected(self, event=None):
        rows = self._table.getSelectedRows()
        if not rows:
            return
        lines = []
        for row in rows:
            row_data = [str(self._table_model.getValueAt(row, col))
                        for col in range(self._table_model.getColumnCount())]
            lines.append("\t".join(row_data))

        clipboard = awt.Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(dt.StringSelection("\n".join(lines)), None)

    def _export(self, export_type):
        if self._export_callback is None:
            return
        path, format_name = self._export_callback(export_type)
        if path:
            swing.JOptionPane.showMessageDialog(
                self._main_panel,
                "Exported {} to:\n{}".format(format_name, path),
                "Export Complete",
                swing.JOptionPane.INFORMATION_MESSAGE
            )

    def _clear(self, event=None):
        confirm = swing.JOptionPane.showConfirmDialog(
            self._main_panel,
            "Clear all results?",
            "Confirm",
            swing.JOptionPane.YES_NO_OPTION
        )
        if confirm == swing.JOptionPane.YES_OPTION:
            self._table_model.setRowCount(0)


class _SeverityRenderer(swing.table.DefaultTableCellRenderer):
    """Color for severity"""

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        component = super().getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
        if not isSelected:
            severity = table.getModel().getValueAt(row, 2)
            if severity == "High":
                component.setBackground(awt.Color(255, 200, 200))
            elif severity == "Medium":
                component.setBackground(awt.Color(255, 230, 150))
            elif severity == "Low":
                component.setBackground(awt.Color(220, 240, 255))
            else:
                component.setBackground(awt.Color.WHITE)
        return component


class _TablePopupMenu(swing.JPopupMenu):

    def __init__(self, table):
        super().__init__()
        self._table = table
        copy_item = swing.JMenuItem("Copy Row", actionPerformed=self._copy_row)
        self.add(copy_item)

    def _copy_row(self, event=None):
        row = self._table.getSelectedRow()
        if row < 0:
            return
        model = self._table.getModel()
        row_data = [str(model.getValueAt(row, col)) for col in range(model.getColumnCount())]
        text = "\t".join(row_data)
        clipboard = awt.Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(dt.StringSelection(text), None)