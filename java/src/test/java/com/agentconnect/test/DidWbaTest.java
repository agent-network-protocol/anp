package com.agentconnect.test;

import com.agentconnect.authentication.DIDWbaAuthHeader;
import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.DefaultAsyncHttpClient;
import org.asynchttpclient.Response;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * @Description
 * @Author yanliqing
 * @Date 2025/5/25 16:23
 */
public class DidWbaTest {

    public static void main(String[] args) {
        exampleUsage();
    }
    /**
     * Example usage of the DIDWbaAuthHeader class.
     */
    public static void exampleUsage() {
        try {
            // Get current working directory
            String baseDir = System.getProperty("user.dir");

            // Create client with absolute paths
            DIDWbaAuthHeader client = new DIDWbaAuthHeader(
                    baseDir + "/examples/use_did_test_public/did.json",
                    baseDir + "/examples//use_did_test_public/key-1_private.pem"
            );

            String serverUrl = "http://service.agent-network-protocol.com";

            // Get authentication header (first call, returns DID authentication header)
            Map<String, String> headers = client.getAuthHeader(serverUrl);

            // Send request
            AsyncHttpClient asyncHttpClient = new DefaultAsyncHttpClient();

            // Prepare the request with headers
            CompletableFuture<Response> future = asyncHttpClient
                    .prepareGet(serverUrl + "/wba/test")
                    .setHeader("Authorization", headers.get("Authorization"))
                    .execute()
                    .toCompletableFuture();

            // Process the response
            Response response = future.get();

            // Check response
            System.out.println("Status code: " + response.getStatusCode());

            // If authentication is successful, update token
            if (response.getStatusCode() == 200) {
                // Convert response headers to map
                Map<String, String> responseHeaders = new HashMap<>();
                for (Map.Entry<String, String> header : response.getHeaders()) {
                    responseHeaders.put(header.getKey(), header.getValue());
                }

                String token = client.updateToken(serverUrl, responseHeaders);
                if (token != null) {
                    System.out.println("Received token: " + token.substring(0, Math.min(30, token.length())) + "...");
                } else {
                    System.out.println("No token received in response headers");
                }
            }
            // If authentication fails and a token was used, clear the token and retry
            else if (response.getStatusCode() == 401) {
                System.out.println("Invalid token, clearing and using DID authentication");
                client.clearToken(serverUrl);
                // Retry request here
            }

            // Get authentication header again (if a token was obtained in the previous step, this will return a token authentication header)
            headers = client.getAuthHeader(serverUrl);
            System.out.println("Header for second request: " + headers);

            // Force use of DID authentication header
            headers = client.getAuthHeader(serverUrl, true);
            System.out.println("Forced use of DID authentication header: " + headers);

            // Test different domain
            String anotherServerUrl = "http://api.example.com";
            headers = client.getAuthHeader(anotherServerUrl);
            System.out.println("Header for another domain: " + headers);

            // Close the HTTP client
            asyncHttpClient.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    // Add your test methods here
}
