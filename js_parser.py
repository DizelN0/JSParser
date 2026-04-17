from burp import IBurpExtender, IContextMenuFactory
from ui import JSAnalyzerUI
import re
import javax.swing as swing
from javax.swing import SwingUtilities
import threading
from java.util import ArrayList
import json
import os

class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("JS Parser")
        self.stdout = callbacks.getStdout()
        self._lock = threading.Lock()
        self._results = []
        self._ui = JSAnalyzerUI(callbacks, self._on_export_request)
        callbacks.addSuiteTab(self._ui)

        callbacks.registerContextMenuFactory(self)

        self._patterns = self._init_patterns()
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

        threading.Thread(target=run_analysis).start()

    def _init_patterns(self):
        path = os.path.join(os.getcwd(), "rules.json")

        try:
            with open(path, "r") as f:
                rules = json.load(f)

            self._log("Loaded {} rules".format(len(rules)))
            return rules

        except Exception as e:
            self._log("Failed to load rules.json: {}".format(e))
            return []

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
        content_lower = content.lower()

        for pattern_conf in self._patterns:
            keywords = pattern_conf.get("keywords", [])
            if keywords:
                if not any(k.lower() in content_lower for k in keywords):
                    continue
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
                        "severity": pattern_conf.get("severity", "Info"),
                        "confidence": pattern_conf.get("confidence", "unknown"),
                        "category": pattern_conf.get("category", "general"),
                        "description": pattern_conf.get("description", ""),
                        "remediation": pattern_conf.get("remediation", ""),
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
