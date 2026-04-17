from burp import IBurpExtender, IContextMenuFactory
from ui import JSAnalyzerUI
import re
import javax.swing as swing
from javax.swing import SwingUtilities
import threading
from java.util import ArrayList

class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("JS Parser")

        self._patterns = self._init_patterns()
        self._results = []
        self._lock = threading.Lock()

        self._ui = JSAnalyzerUI(callbacks, self._on_export_request)
        callbacks.addSuiteTab(self._ui)

        callbacks.registerContextMenuFactory(self)

        self.stdout = callbacks.getStdout()
        self._log("JS Parser loaded")

    def createMenuItems(self, invocation):
    	menu = ArrayList()
    	try:
            messages = invocation.getSelectedMessages()

            if messages and len(messages) > 0:
                item = swing.JMenuItem("Parse JS")

                def handler(event):
                   self._handle_menu_click(invocation)

                item.addActionListener(handler)

                menu.add(item)

        except Exception as e:
            self._log("Menu error: {}".format(e))

        return menu

    def _handle_menu_click(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages:
            return

        def run_analysis():
            for message in messages:
                if message is None or message.getResponse() is None:
                    continue
                if not self._is_javascript(message):
                    continue

                content = self.helpers.bytesToString(message.getResponse())
                url = message.getUrl().toString()
                findings = self._analyze_content(content, url)

                with self._lock:
                    self._results.extend(findings)
                    self._ui.update_table(self._results)

                self._log("Analyzed: {} - {} findings".format(url, len(findings)))

        SwingUtilities.invokeLater(run_analysis)

    def _init_patterns(self):
        return [
            {
                "name": "Hardcoded API Key",
                "regex": r'["\']?(?:api[_-]?key|apikey|api_secret)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']?',
                "severity": "High",
                "description": "Hardcoded API Key",
                "remediation": "Hardcoded API Key"
            },
            {
                "name": "JWT Token in Code",
                "regex": r'["\'](?:eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*)["\']',
                "severity": "Medium",
                "description": "JWT Token in Code",
                "remediation": "JWT Token in Code"
            },
            {
                "name": "Internal Endpoint",
                "regex": r'(?:fetch|axios|\.open)\s*\(\s*["\']((?:https?://)?(?:internal|admin|api)[^"\']+)["\']',
                "severity": "Info",
                "description": "Internal Endpoint",
                "remediation": "Internal Endpoint"
            },
            {
                "name": "Eval/Function Constructor",
                "regex": r'\b(eval|Function|setTimeout|setInterval)\s*\(\s*[^"\']',
                "severity": "Medium",
                "description": "Eval/Function Constructor",
                "remediation": "Eval/Function Constructor"
            },
            {
                "name": "Console Debug Leak",
                "regex": r'console\.(log|debug|info)\s*\([^)]*(?:password|token|secret|key)[^)]*\)',
                "severity": "Low",
                "description": "----",
                "remediation": "Console Debug Leak"
            }
        ]

    def _is_javascript(self, message):
        analyzed = self.helpers.analyzeResponse(message.getResponse())
        for header in analyzed.getHeaders():
            if header.lower().startswith("content-type:"):
                if "javascript" in header.lower() or header.endswith(".js"):
                    return True
        url = message.getUrl().toString().lower()
        if url.endswith(".js") or ".js?" in url:
            return True
        return False

    def _analyze_content(self, content, url):
        findings = []
        seen = set()

        for pattern_conf in self._patterns:
            try:
                regex = re.compile(pattern_conf["regex"], re.IGNORECASE | re.MULTILINE)
                for match in regex.finditer(content):
                    finding_key = "{}:{}:{}".format(
                        pattern_conf['name'],
                        match.start(),
                        match.group(0)[:30]
                    )
                    if finding_key in seen:
                        continue
                    seen.add(finding_key)

                    finding = {
                        "url": url,
                        "pattern": pattern_conf["name"],
                        "severity": pattern_conf["severity"],
                        "description": pattern_conf["description"],
                        "remediation": pattern_conf["remediation"],
                        "matched": match.group(0),
                        "offset": match.start(),
                        "context": self._get_context(content, match.start(), match.end())
                    }
                    findings.append(finding)
            except re.error as e:
                self._log("Regex error: {}".format(e))
        return findings

    def _get_context(self, content, start, end, radius=100):
        ctx_start = max(0, start - radius)
        ctx_end = min(len(content), end + radius)
        return content[ctx_start:ctx_end].replace("\n", " ").replace("\r", " ")

    def _on_export_request(self, export_type):
        if not self._results:
            return None, "No results to export"

        if export_type == "csv":
            import csv, tempfile, os
            path = os.path.join(tempfile.gettempdir(), "js_parser_export.csv")
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=self._results[0].keys())
                writer.writeheader()
                writer.writerows(self._results)
            return path, "CSV"

        elif export_type == "json":
            import json, tempfile, os
            path = os.path.join(tempfile.gettempdir(), "js_parser_export.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self._results, f, indent=2, ensure_ascii=False)
            return path, "JSON"
        return None, None

    def _log(self, msg):
        self.stdout.write("[JS Parser] %s\n" % msg)

    def clear_results(self):
        with self._lock:
            self._results = []
