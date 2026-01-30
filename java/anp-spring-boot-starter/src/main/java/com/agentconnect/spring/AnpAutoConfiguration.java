/**
 * @program: anp4java
 * @description: ANP SDK Spring Boot 自动配置
 * @author: Ruitao.Zhai
 * @date: 2025-01-21
 **/
package com.agentconnect.spring;

import com.agentconnect.server.SessionManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

import java.util.Collections;

/**
 * ANP SDK Spring Boot 自动配置
 * 
 * 启用条件：
 * 1. 类路径存在 Spring Web
 * 2. 配置 anp.enabled=true (默认)
 * 
 * 自动配置内容：
 * 1. AnpProperties - 配置属性
 * 2. SessionManager - 会话管理
 * 3. AnpAgentBeanProcessor - Agent Bean 扫描
 * 4. AnpEndpointController - 端点注册
 * 5. DidWbaAuthFilter - 认证过滤器 (可选)
 */
@Configuration
@ConditionalOnClass(name = "org.springframework.web.servlet.DispatcherServlet")
@ConditionalOnProperty(prefix = "anp", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(AnpProperties.class)
public class AnpAutoConfiguration {
    
    private static final Logger log = LoggerFactory.getLogger(AnpAutoConfiguration.class);
    
    @Bean
    @ConditionalOnMissingBean
    public SessionManager anpSessionManager() {
        log.info("Creating ANP SessionManager");
        return new SessionManager();
    }
    
    @Bean
    @ConditionalOnMissingBean
    public AnpAgentBeanProcessor anpAgentBeanProcessor(AnpProperties properties, SessionManager sessionManager) {
        log.info("Creating ANP Agent Bean Processor");
        return new AnpAgentBeanProcessor(properties, sessionManager);
    }
    
    @Bean
    @ConditionalOnMissingBean
    public AnpEndpointController anpEndpointController(AnpAgentBeanProcessor beanProcessor, AnpProperties properties) {
        log.info("Creating ANP Endpoint Controller with prefix: {}", properties.getPrefix());
        return new AnpEndpointController(beanProcessor, properties);
    }
    
    @Bean
    @ConditionalOnProperty(prefix = "anp.auth", name = "enabled", havingValue = "true")
    public FilterRegistrationBean<DidWbaAuthFilter> didWbaAuthFilter(AnpProperties properties) {
        log.info("Creating DID-WBA Auth Filter");
        
        DidWbaAuthFilter filter = new DidWbaAuthFilter(
            properties.getAuth().getExemptPaths(),
            properties.getAuth().getAllowedDomains()
        );
        
        FilterRegistrationBean<DidWbaAuthFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setUrlPatterns(Collections.singletonList("/*"));
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE + 10);
        registration.setName("didWbaAuthFilter");
        
        return registration;
    }
}
