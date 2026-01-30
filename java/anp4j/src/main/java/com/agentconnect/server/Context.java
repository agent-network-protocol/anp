/**
 * @program: anp4java
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 */
package com.agentconnect.server;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Request context with session and DID access.
 * 
 * Provides access to the caller's DID, session storage, and authentication result.
 * 
 * Example:
 *     {@literal @}Interface
 *     public Map<String, Object> search(String query, Context ctx) {
 *         ctx.getSession().set("last_query", query);
 *         return Map.of("results", List.of(), "caller", ctx.getDid());
 *     }
 */
public class Context {
    
    private final String did;
    private final Session session;
    private final Map<String, Object> authResult;
    private final Map<String, String> headers;
    
    public Context(String did, Session session, Map<String, Object> authResult, Map<String, String> headers) {
        this.did = did;
        this.session = session;
        this.authResult = authResult;
        this.headers = headers;
    }
    
    /**
     * Get the caller's DID (Decentralized Identifier).
     */
    public String getDid() {
        return did;
    }
    
    /**
     * Alias for getDid() - get the caller's DID.
     */
    public String getCallerDid() {
        return did;
    }
    
    /**
     * Get the session storage for this DID.
     */
    public Session getSession() {
        return session;
    }
    
    /**
     * Get the authentication result from middleware.
     */
    public Map<String, Object> getAuthResult() {
        return authResult;
    }
    
    /**
     * Get request headers.
     */
    public Map<String, String> getHeaders() {
        return headers;
    }
    
    @Override
    public String toString() {
        return "Context{did='" + did + "'}";
    }
    
    /**
     * Session storage for a single DID.
     */
    public static class Session {
        private final Map<String, Object> data = new ConcurrentHashMap<>();
        
        /**
         * Get a value from the session.
         */
        @SuppressWarnings("unchecked")
        public <T> T get(String key) {
            return (T) data.get(key);
        }
        
        /**
         * Get a value from the session with default.
         */
        @SuppressWarnings("unchecked")
        public <T> T get(String key, T defaultValue) {
            Object value = data.get(key);
            return value != null ? (T) value : defaultValue;
        }
        
        /**
         * Set a value in the session.
         */
        public void set(String key, Object value) {
            if (value == null) {
                data.remove(key);
            } else {
                data.put(key, value);
            }
        }
        
        /**
         * Remove a value from the session.
         */
        public void remove(String key) {
            data.remove(key);
        }
        
        /**
         * Clear all session data.
         */
        public void clear() {
            data.clear();
        }
        
        /**
         * Check if a key exists.
         */
        public boolean has(String key) {
            return data.containsKey(key);
        }
    }
}
