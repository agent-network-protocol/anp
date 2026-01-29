/**
 * @program: anp4java
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 */
package com.agentconnect.server;

import java.time.Instant;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Manages sessions across DIDs.
 * 
 * Sessions are isolated by DID and automatically expire after a configurable period.
 */
public class SessionManager {
    
    private static final long DEFAULT_TTL_SECONDS = 3600; // 1 hour
    private static final long CLEANUP_INTERVAL_SECONDS = 300; // 5 minutes
    
    private final Map<String, SessionEntry> sessions = new ConcurrentHashMap<>();
    private final long ttlSeconds;
    private final ScheduledExecutorService cleanupExecutor;
    
    /**
     * Create a session manager with default TTL (1 hour).
     */
    public SessionManager() {
        this(DEFAULT_TTL_SECONDS);
    }
    
    /**
     * Create a session manager with custom TTL.
     * 
     * @param ttlSeconds Session time-to-live in seconds
     */
    public SessionManager(long ttlSeconds) {
        this.ttlSeconds = ttlSeconds;
        this.cleanupExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "SessionManager-Cleanup");
            t.setDaemon(true);
            return t;
        });
        this.cleanupExecutor.scheduleAtFixedRate(
            this::cleanupExpired,
            CLEANUP_INTERVAL_SECONDS,
            CLEANUP_INTERVAL_SECONDS,
            TimeUnit.SECONDS
        );
    }
    
    /**
     * Get or create a session for a DID.
     * 
     * @param did The DID to get/create a session for
     * @return The session
     */
    public Context.Session getSession(String did) {
        SessionEntry entry = sessions.compute(did, (key, existing) -> {
            if (existing == null || existing.isExpired()) {
                return new SessionEntry(new Context.Session(), ttlSeconds);
            }
            existing.touch(ttlSeconds);
            return existing;
        });
        return entry.session;
    }
    
    /**
     * Remove a session for a DID.
     * 
     * @param did The DID to remove the session for
     */
    public void removeSession(String did) {
        sessions.remove(did);
    }
    
    /**
     * Clear all sessions.
     */
    public void clearAll() {
        sessions.clear();
    }
    
    /**
     * Get the number of active sessions.
     */
    public int getSessionCount() {
        return sessions.size();
    }
    
    /**
     * Check if a session exists for a DID.
     */
    public boolean hasSession(String did) {
        SessionEntry entry = sessions.get(did);
        return entry != null && !entry.isExpired();
    }
    
    /**
     * Shutdown the cleanup executor.
     */
    public void shutdown() {
        cleanupExecutor.shutdown();
        try {
            if (!cleanupExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                cleanupExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            cleanupExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
    
    /**
     * Clean up expired sessions.
     */
    private void cleanupExpired() {
        Iterator<Map.Entry<String, SessionEntry>> it = sessions.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, SessionEntry> entry = it.next();
            if (entry.getValue().isExpired()) {
                it.remove();
            }
        }
    }
    
    /**
     * Internal session entry with expiration tracking.
     */
    private static class SessionEntry {
        final Context.Session session;
        volatile Instant expiresAt;
        
        SessionEntry(Context.Session session, long ttlSeconds) {
            this.session = session;
            this.expiresAt = Instant.now().plusSeconds(ttlSeconds);
        }
        
        boolean isExpired() {
            return Instant.now().isAfter(expiresAt);
        }
        
        void touch(long ttlSeconds) {
            this.expiresAt = Instant.now().plusSeconds(ttlSeconds);
        }
    }
}
