# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.

import re
import logging
import traceback
from typing import Optional

def extract_code_from_llm_output(content: str) -> Optional[str]:
    """Extract Python code from LLM output content.
    
    Args:
        content: The complete content string output by the LLM.
        
    Returns:
        str: The extracted Python code. Returns None if extraction fails.
        
    Extraction rules:
    1. Look for code blocks surrounded by ```python and ```.
    2. If not found, try to find code blocks surrounded by ``` and ```.
    """
    try:
        # First, try to match the code block surrounded by ```python and ```
        pattern = r"```python\s*(.*?)\s*```"
        matches = re.findall(pattern, content, re.DOTALL)
        
        if matches:
            return matches[0].strip()
            
        # If not found, try to match the code block surrounded by ``` and ```
        pattern = r"```\s*(.*?)\s*```"
        matches = re.findall(pattern, content, re.DOTALL)
        
        if matches:
            return matches[0].strip()
            
        logging.error("No code block found in LLM output")
        return None
        
    except Exception as e:
        logging.error(f"Failed to extract code: {str(e)}\nStack trace:\n{traceback.format_exc()}")
        return None





