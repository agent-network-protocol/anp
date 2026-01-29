/**
 * @program: anp4java
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 */
package com.agentconnect.server.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Mark a class as an ANP Agent.
 * 
 * Example:
 *     {@literal @}AnpAgent(name = "Hotel Agent", did = "did:wba:example.com:hotel", prefix = "/hotel")
 *     public class HotelAgent {
 *         {@literal @}Interface
 *         public Map<String, Object> search(String query) {
 *             return Map.of("results", List.of());
 *         }
 *     }
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface AnpAgent {
    
    /**
     * Agent name (required).
     */
    String name();
    
    /**
     * Agent DID (required).
     */
    String did();
    
    /**
     * Agent description, defaults to name.
     */
    String description() default "";
    
    /**
     * URL prefix for endpoints.
     */
    String prefix() default "";
    
    /**
     * Tags for documentation.
     */
    String[] tags() default {"ANP"};
}
