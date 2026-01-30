/**
 * @program: anp4java
 * @author: Ruitao.Zhai
 * @date: 2025-01-29
 */
package com.agentconnect.server.annotation;

import com.agentconnect.protocol.RPCMethodInfo;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Mark a method as an interface endpoint.
 * 
 * Example:
 *     {@literal @}Interface
 *     public Map<String, Object> search(String query) {
 *         return Map.of("results", List.of());
 *     }
 *     
 *     {@literal @}Interface(mode = Mode.LINK)
 *     public Map<String, Object> book(String hotelId) {
 *         return Map.of("status", "booked");
 *     }
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface Interface {
    
    /**
     * Interface name, defaults to the method name.
     */
    String name() default "";
    
    /**
     * Method description, defaults to empty.
     */
    String description() default "";
    
    /**
     * Protocol type, e.g., "AP2/ANP" for AP2 payment protocol methods.
     */
    String protocol() default "";
    
    /**
     * Interface mode.
     * CONTENT: embeds OpenRPC document (default)
     * LINK: provides URL reference only
     */
    RPCMethodInfo.Mode mode() default RPCMethodInfo.Mode.CONTENT;
    
    /**
     * JSON Schema for the input parameters.
     * Should be a valid JSON Schema object as string.
     * If not provided, schema will be auto-generated from method parameters.
     */
    String inputSchema() default "";
    
    /**
     * JSON Schema for the output/return value.
     * Should be a valid JSON Schema object as string.
     */
    String outputSchema() default "";
}
