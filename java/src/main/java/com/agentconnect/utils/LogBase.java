package com.agentconnect.utils;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.ConsoleAppender;
import org.slf4j.LoggerFactory;

/**
 * Utility class for configuring colored logging
 */
public class LogBase {
    
    /**
     * ANSI color codes for console output
     */
    public static class AnsiColors {
        public static final String RESET = "\u001B[0m";
        public static final String DEBUG = "\u001B[94m"; // Blue
        public static final String INFO = "\u001B[92m";  // Green
        public static final String WARN = "\u001B[93m";  // Yellow
        public static final String ERROR = "\u001B[91m"; // Red
        public static final String CRITICAL = "\u001B[95m"; // Magenta
    }
    
    /**
     * Set log color and level for console output
     *
     * @param level Log level to set (use ch.qos.logback.classic.Level)
     */
    public static void setLogColorLevel(Level level) {
        LoggerContext loggerContext = (LoggerContext) LoggerFactory.getILoggerFactory();
        Logger rootLogger = loggerContext.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        
        // Set the log level
        rootLogger.setLevel(level);
        
        // Check if there's already a console appender
        boolean hasConsoleAppender = rootLogger.iteratorForAppenders().hasNext();
        
        if (!hasConsoleAppender) {
            // Create pattern layout with colors
            PatternLayoutEncoder encoder = new PatternLayoutEncoder();
            encoder.setContext(loggerContext);
            encoder.setPattern("%d{yyyy-MM-dd HH:mm:ss} " +
                               "%highlight(%level) " +
                               "%cyan(%logger{36}) - " +
                               "%msg%n");
            encoder.start();
            
            // Create and configure console appender
            ConsoleAppender<ILoggingEvent> consoleAppender = new ConsoleAppender<>();
            consoleAppender.setContext(loggerContext);
            consoleAppender.setEncoder(encoder);
            consoleAppender.start();
            
            // Add appender to root logger
            rootLogger.addAppender(consoleAppender);
        }
        
        // Prevent log messages from propagating to the root logger
        rootLogger.setAdditive(false);
        
        // Test messages
        org.slf4j.Logger logger = LoggerFactory.getLogger(LogBase.class);
        logger.debug("This is a debug message");
        logger.info("This is an info message");
        logger.warn("This is a warning message");
        logger.error("This is an error message");
    }
} 