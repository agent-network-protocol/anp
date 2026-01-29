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
 * 定义 Agent 提供的 Information 资源
 * 
 * 用于在 ad.json 中声明静态信息资源
 * 
 * 用法：
 * 
 * @AnpAgent(name = "Hotel", did = "did:wba:...")
 * public class HotelAgent {
 *     
 *     // URL 模式 - 外部链接
 *     @Information(type = "VideoObject", description = "Hotel tour", url = "https://cdn.example.com/tour.mp4")
 *     
 *     // URL 模式 - 托管路径
 *     @Information(type = "Product", description = "Room catalog", path = "/products/rooms.json")
 *     
 *     // Content 模式 - 嵌入内容（通过方法返回）
 *     @Information(type = "Contact", description = "Contact info", mode = Mode.CONTENT)
 *     public Map<String, Object> getContactInfo() {
 *         return Map.of("phone", "+1-234-567");
 *     }
 * }
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface Information {
    
    /**
     * Information 类型，如 "Product", "VideoObject", "Organization", "Service"
     */
    String type();
    
    /**
     * 描述
     */
    String description() default "";
    
    /**
     * 输出模式
     */
    Mode mode() default Mode.URL;
    
    /**
     * 相对路径（URL 模式）
     */
    String path() default "";
    
    /**
     * 外部 URL（URL 模式）
     */
    String url() default "";
    
    /**
     * 静态文件路径（用于托管）
     */
    String file() default "";
    
    /**
     * 输出模式枚举
     */
    enum Mode {
        URL,     // 生成 URL 引用
        CONTENT  // 嵌入内容到 ad.json
    }
}
