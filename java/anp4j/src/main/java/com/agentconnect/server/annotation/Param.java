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
 * Annotate a method parameter with a specific name and description.
 * 
 * This allows using direct parameters instead of Map<String, Object>,
 * making the API more type-safe and readable.
 * 
 * Example:
 * <pre>
 *     // Old style (still supported)
 *     {@literal @}Interface(name = "add")
 *     public Map<String, Object> add(Map<String, Object> params, Context ctx) {
 *         int a = ((Number) params.get("a")).intValue();
 *         int b = ((Number) params.get("b")).intValue();
 *         return Map.of("result", a + b);
 *     }
 *     
 *     // New style with @Param (recommended)
 *     {@literal @}Interface(name = "add")
 *     public int add(@Param("a") int a, @Param("b") int b) {
 *         return a + b;
 *     }
 *     
 *     // With description
 *     {@literal @}Interface(name = "search")
 *     public List<Hotel> search(
 *         @Param(value = "city", description = "City name to search") String city,
 *         @Param(value = "minPrice", required = false) Double minPrice,
 *         Context ctx
 *     ) {
 *         return hotelService.search(city, minPrice);
 *     }
 * </pre>
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.PARAMETER)
public @interface Param {
    
    /**
     * The parameter name as it appears in the JSON-RPC params object.
     * If not specified, uses the Java parameter name (requires -parameters compiler flag).
     */
    String value() default "";
    
    /**
     * Description of the parameter for OpenRPC documentation.
     */
    String description() default "";
    
    /**
     * Whether this parameter is required.
     * Default is true.
     */
    boolean required() default true;
    
    /**
     * Default value for optional parameters (as JSON string).
     * Only used when required = false.
     * 
     * Example: defaultValue = "10" for integer, defaultValue = "\"default\"" for string
     */
    String defaultValue() default "";
}
