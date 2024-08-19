import burp.*;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.HashSet;

public class BurpExtender implements IBurpExtender, IHttpListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private static final String[] PAYLOADS = {"'", "\"", "')", "\")"};
    private static final Set<String> TARGET_HEADERS = new HashSet<>();
    private ExecutorService executorService;

    static {
        TARGET_HEADERS.add("Referer");
        TARGET_HEADERS.add("X-Forwarded-For");
        TARGET_HEADERS.add("Cookie");
        TARGET_HEADERS.add("User-Agent");
    }

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.executorService = Executors.newFixedThreadPool(10);

        callbacks.setExtensionName("SQL Injection Payload Injector");
        callbacks.registerHttpListener(this);
        stdout.println("Plugin loaded successfully.");
    }

    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageIsRequest && (toolFlag & IBurpExtenderCallbacks.TOOL_PROXY) != 0) {
            IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
            List<String> headers = new ArrayList<>(requestInfo.getHeaders());
            byte[] body = getBodyBytes(messageInfo.getRequest(), requestInfo.getBodyOffset());
            List<IParameter> parameters = requestInfo.getParameters();

            executorService.submit(() -> processParameters(messageInfo, parameters));
            executorService.submit(() -> processHeaders(messageInfo, headers, body));
        }
    }

    private void processParameters(IHttpRequestResponse messageInfo, List<IParameter> parameters) {
        for (String payload : PAYLOADS) {
            for (IParameter parameter : parameters) {
                byte[] modifiedRequest = modifyParameter(messageInfo.getRequest(), parameter, payload);
                sendAndLogRequest(messageInfo, modifiedRequest, "Param: " + parameter.getName() + " Payload: " + payload);
            }
        }
    }

    private void processHeaders(IHttpRequestResponse messageInfo, List<String> headers, byte[] body) {
        for (String payload : PAYLOADS) {
            for (int i = 0; i < headers.size(); i++) {
                String header = headers.get(i);
                String headerName = header.split(":")[0];
                if (TARGET_HEADERS.contains(headerName)) {
                    String modifiedHeader = header + payload;
                    headers.set(i, modifiedHeader);
                    byte[] newRequest = helpers.buildHttpMessage(headers, body);
                    sendAndLogRequest(messageInfo, newRequest, "Header: " + headerName + " Payload: " + payload);
                }
            }
        }
    }

    private void sendAndLogRequest(IHttpRequestResponse originalRequest, byte[] modifiedRequest, String testedParameter) {
        IHttpRequestResponse response = callbacks.makeHttpRequest(originalRequest.getHttpService(), modifiedRequest);
        logResponse(response, testedParameter);
    }

    private void logResponse(IHttpRequestResponse response, String testedParameter) {
        byte[] responseBytes = response.getResponse();
        if (responseBytes != null) {
            IResponseInfo responseInfo = helpers.analyzeResponse(responseBytes);
            int contentLength = responseBytes.length;
            String responseBody = new String(responseBytes, responseInfo.getBodyOffset(), contentLength - responseInfo.getBodyOffset());
            IRequestInfo requestInfo = helpers.analyzeRequest(response);
            String url = requestInfo.getUrl().toString();

            if (containsSQLError(responseBody)) {
                stdout.println("SQL Error Detected:");
                stdout.println("URL: " + url);
                stdout.println("Error Message: " + extractSQLError(responseBody));
                stdout.println("Tested Parameter: " + testedParameter);
                stdout.println("Response Length: " + contentLength);
                stdout.println();
            }

            if (isWAFDetected(responseInfo, responseBody)) {
                stdout.println("Potential WAF Detected:");
                stdout.println("URL: " + url);
                stdout.println("Response Length: " + contentLength);
                stdout.println("Tested Parameter: " + testedParameter);
                stdout.println();
            }

            if (isBlindSQLInjectionDetected(responseInfo)) {
                stdout.println("Potential Blind SQL Injection Detected:");
                stdout.println("URL: " + url);
                stdout.println("Response Length: " + contentLength);
                stdout.println("Tested Parameter: " + testedParameter);
                stdout.println();
            }
        }
    }

    private boolean containsSQLError(String responseBody) {
        return responseBody.contains("You have an error in your SQL syntax") ||
                responseBody.contains("sql syntax error") ||
                responseBody.contains("unclosed quotation mark");
    }

    private String extractSQLError(String responseBody) {
        int index = responseBody.indexOf("You have an error in your SQL syntax");
        if (index == -1) {
            index = responseBody.indexOf("sql syntax error");
        }
        return index != -1 ? responseBody.substring(Math.max(0, index - 30), Math.min(responseBody.length(), index + 120)) : "No SQL error found";
    }

    private boolean isWAFDetected(IResponseInfo responseInfo, String responseBody) {
        // Common WAF detection based on status codes and response content
        if (responseInfo.getStatusCode() == 403 ||
                responseBody.contains("Access Denied") ||
                responseBody.contains("403 Forbidden") ||
                responseBody.contains("\\u4e0d\\u5408\\u6cd5") ||
                responseBody.contains("\\u5371\\u9669") ||
                responseBody.contains("\\u62e6\\u622a")) {
            stdout.println("WAF Detected:");
            return true;
        }

        // Vendor-specific WAF detection
        String serverHeader = getHeader(responseInfo, "Server");
        if (serverHeader != null) {
            if (serverHeader.contains("AWS")) {
                stdout.println("AWS WAF Detected");
                return true;
            }
            if (serverHeader.contains("ACE XML Gateway")) {
                stdout.println("Cisco ACE XML Gateway WAF Detected");
                return true;
            }
            if (serverHeader.contains("openresty")) {
                stdout.println("OpenResty WAF Detected");
                return true;
            }
            if (serverHeader.contains("HuaweiCloudWAF")) {
                stdout.println("Huawei Cloud WAF Detected");
                return true;
            }
            if (serverHeader.contains("NSFocus")) {
                stdout.println("NSFocus WAF Detected");
                return true;
            }
        }

        if (responseBody.contains("Security check by BitNinja")) {
            stdout.println("BitNinja WAF Detected");
            return true;
        }
        if (responseBody.contains("Attention Required!") ||
                responseBody.contains("Cloudflare Ray ID:") ||
                responseBody.contains(".fgd_icon") ||
                responseBody.contains("Server Unavailable!")) {
            stdout.println("Cloudflare WAF Detected");
            return true;
        }
        if (responseBody.contains("This Request Has Been Blocked By NAXSI")) {
            stdout.println("NAXSI WAF Detected");
            return true;
        }
        if (responseBody.contains("waf.tencent-cloud.com")) {
            stdout.println("Tencent Cloud WAF Detected");
            return true;
        }

        return false;
    }

    private boolean isBlindSQLInjectionDetected(IResponseInfo responseInfo) {
        return responseInfo.getHeaders().contains("X-Blind-SQL");
    }

    private byte[] modifyParameter(byte[] request, IParameter parameter, String payload) {
        String modifiedValue = parameter.getValue() + payload;
        IParameter modifiedParam = helpers.buildParameter(parameter.getName(), modifiedValue, parameter.getType());
        return helpers.updateParameter(request, modifiedParam);
    }

    private byte[] getBodyBytes(byte[] request, int bodyOffset) {
        int bodyLength = request.length - bodyOffset;
        byte[] body = new byte[bodyLength];
        System.arraycopy(request, bodyOffset, body, 0, bodyLength);
        return body;
    }

    private String getHeader(IResponseInfo responseInfo, String headerName) {
        return responseInfo.getHeaders().stream()
                .filter(header -> header.startsWith(headerName + ":"))
                .map(header -> header.substring(headerName.length() + 1).trim())
                .findFirst().orElse(null);
    }

    public void extensionUnloaded() {
        executorService.shutdown();
        stdout.println("Plugin unloaded and thread pool shut down.");
    }
}
