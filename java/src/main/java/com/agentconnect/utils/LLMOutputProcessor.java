package com.agentconnect.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility class for processing output from Large Language Models (LLMs)
 */
public class LLMOutputProcessor {
    private static final Logger logger = LoggerFactory.getLogger(LLMOutputProcessor.class);

    /**
     * Extract code from LLM output content.
     *
     * Extraction rules:
     * 1. Look for code blocks surrounded by ```java and ```
     * 2. If not found, try to find code blocks surrounded by ``` and ```
     *
     * @param content The complete content string output by the LLM
     * @return The extracted code, or null if extraction fails
     */
    public static String extractCodeFromLLMOutput(String content) {
        try {
            // First, try to match the code block surrounded by ```java and ```
            Pattern javaPattern = Pattern.compile("```java\\s*(.*?)\\s*```", Pattern.DOTALL);
            Matcher javaMatcher = javaPattern.matcher(content);
            
            if (javaMatcher.find()) {
                return javaMatcher.group(1).trim();
            }
            
            // If not found, try to match the code block surrounded by ``` and ```
            Pattern genericPattern = Pattern.compile("```\\s*(.*?)\\s*```", Pattern.DOTALL);
            Matcher genericMatcher = genericPattern.matcher(content);
            
            if (genericMatcher.find()) {
                return genericMatcher.group(1).trim();
            }
            
            logger.error("No code block found in LLM output");
            return null;
        } catch (Exception e) {
            logger.error("Failed to extract code: {}", e.getMessage(), e);
            return null;
        }
    }
} 