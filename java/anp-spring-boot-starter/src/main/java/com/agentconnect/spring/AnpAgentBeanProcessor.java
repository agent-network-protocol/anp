/**
 * @program: anp4java
 * @description: ANP Agent Bean 处理器
 * @author: Ruitao.Zhai
 * @date: 2025-01-21
 **/
package com.agentconnect.spring;

import com.agentconnect.protocol.AgentConfig;
import com.agentconnect.server.AgentHandler;
import com.agentconnect.server.Context;
import com.agentconnect.server.SessionManager;
import com.agentconnect.server.annotation.AnpAgent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 扫描并注册所有 @AnpAgent 注解的 Bean
 */
public class AnpAgentBeanProcessor implements BeanPostProcessor, ApplicationContextAware {
    
    private static final Logger log = LoggerFactory.getLogger(AnpAgentBeanProcessor.class);
    
    private final AnpProperties properties;
    private final SessionManager sessionManager;
    private final Map<String, AgentHandler> handlers = new ConcurrentHashMap<>();
    private ApplicationContext applicationContext;
    
    public AnpAgentBeanProcessor(AnpProperties properties, SessionManager sessionManager) {
        this.properties = properties;
        this.sessionManager = sessionManager;
    }
    
    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }
    
    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        Class<?> clazz = bean.getClass();
        AnpAgent annotation = clazz.getAnnotation(AnpAgent.class);
        
        if (annotation != null) {
            log.info("Found @AnpAgent bean: {} ({})", beanName, clazz.getName());
            
            AgentConfig config = buildConfig(annotation);
            AgentHandler handler = new AgentHandler(bean, config, sessionManager);
            
            handlers.put(beanName, handler);
            log.info("Registered ANP Agent: {} with {} methods", 
                config.getName(), handler.getMethods().size());
        }
        
        return bean;
    }
    
    private AgentConfig buildConfig(AnpAgent annotation) {
        String name = annotation.name();
        String did = annotation.did();
        String description = annotation.description().isEmpty() ? name : annotation.description();
        String prefix = annotation.prefix();
        
        if (properties.getName() != null && !properties.getName().isEmpty()) {
            name = properties.getName();
        }
        if (properties.getDid() != null && !properties.getDid().isEmpty()) {
            did = properties.getDid();
        }
        if (properties.getDescription() != null && !properties.getDescription().isEmpty()) {
            description = properties.getDescription();
        }
        if (properties.getPrefix() != null && !properties.getPrefix().isEmpty()) {
            prefix = properties.getPrefix();
        }
        
        return AgentConfig.builder()
            .name(name)
            .did(did)
            .description(description)
            .prefix(prefix)
            .baseUrl(properties.getBaseUrl() != null ? properties.getBaseUrl() : "")
            .version(properties.getVersion())
            .build();
    }
    
    public Map<String, AgentHandler> getHandlers() {
        return handlers;
    }
    
    public AgentHandler getHandler(String beanName) {
        return handlers.get(beanName);
    }
    
    public AgentHandler getFirstHandler() {
        return handlers.isEmpty() ? null : handlers.values().iterator().next();
    }
}
