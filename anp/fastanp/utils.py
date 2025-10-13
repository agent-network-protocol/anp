"""
Utility functions for FastANP module.

Provides helper functions for URL handling, type conversion, docstring parsing,
and DID document operations.
"""

import inspect
import json
import re
from pathlib import Path
from typing import Any, Callable, Dict, Tuple, Type, get_args, get_origin
from urllib.parse import urlparse

from pydantic import BaseModel


def normalize_agent_domain(agent_domain: str) -> Tuple[str, str]:
    """
    规范化 agent_domain，处理各种输入格式。

    支持的输入格式：
    - www.a.com -> https://www.a.com (自动添加https)
    - a.com -> https://a.com (自动添加https)
    - http://0.0.0.0:80 -> http://0.0.0.0:80 (保持http)
    - https://a.com -> https://a.com (保持不变)
    - localhost:8000 -> http://localhost:8000 (本地默认http)
    - 127.0.0.1:8000 -> http://127.0.0.1:8000 (本地默认http)

    Args:
        agent_domain: 用户输入的域名或URL

    Returns:
        Tuple[完整URL, 纯域名]: 例如 ("https://example.com", "example.com")
    """
    if not agent_domain:
        raise ValueError("agent_domain cannot be empty")

    agent_domain = agent_domain.strip().rstrip('/')

    # 如果没有协议，尝试解析并添加协议
    if not agent_domain.startswith(('http://', 'https://')):
        # 检查是否是本地地址
        is_local = any([
            agent_domain.startswith('localhost'),
            agent_domain.startswith('127.0.0.1'),
            agent_domain.startswith('0.0.0.0'),
            agent_domain.startswith('[::1]'),  # IPv6 localhost
        ])

        # 本地地址默认使用 http，其他使用 https
        protocol = 'http' if is_local else 'https'
        agent_domain = f"{protocol}://{agent_domain}"

    # 解析 URL
    parsed = urlparse(agent_domain)

    # 提取纯域名（包括端口）
    if parsed.port:
        domain = f"{parsed.hostname}:{parsed.port}"
    else:
        domain = parsed.hostname or parsed.netloc

    # 构建完整的基础URL
    full_url = f"{parsed.scheme}://{parsed.netloc}"

    return full_url, domain


def normalize_url(base_url: str, path: str) -> str:
    """
    Normalize and join base URL with path.
    
    Args:
        base_url: Base URL (e.g., "https://example.com")
        path: Path component (e.g., "/api/info.json")
        
    Returns:
        Complete normalized URL
    """
    # Remove trailing slash from base_url
    base_url = base_url.rstrip('/')
    
    # Ensure path starts with /
    if not path.startswith('/'):
        path = '/' + path
    
    return base_url + path


def python_type_to_json_schema(type_hint: Any, type_name: str = None) -> Dict[str, Any]:
    """
    Convert Python type annotation to JSON Schema.
    
    Args:
        type_hint: Python type annotation
        type_name: Optional name for schema reference
        
    Returns:
        JSON Schema dictionary
    """
    # Check if it's a Pydantic model
    if inspect.isclass(type_hint) and issubclass(type_hint, BaseModel):
        if type_name:
            return {"$ref": f"#/components/schemas/{type_name}"}
        else:
            # Convert Pydantic model to JSON Schema
            return pydantic_to_json_schema(type_hint)
    
    # Get the origin type for generics (List, Dict, Optional, etc.)
    origin = get_origin(type_hint)
    args = get_args(type_hint)
    
    # Handle Optional[T] (which is Union[T, None])
    if origin is type(Union) or (hasattr(type_hint, '__origin__') and 
                                  str(type_hint).startswith('typing.Union')):
        # Filter out NoneType
        non_none_args = [arg for arg in args if arg is not type(None)]
        if len(non_none_args) == 1:
            return python_type_to_json_schema(non_none_args[0], type_name)
        # For other unions, just use the first type
        if non_none_args:
            return python_type_to_json_schema(non_none_args[0], type_name)
    
    # Handle List[T]
    if origin is list:
        if args:
            items_schema = python_type_to_json_schema(args[0])
            return {
                "type": "array",
                "items": items_schema
            }
        return {"type": "array"}
    
    # Handle Dict[K, V]
    if origin is dict:
        schema = {"type": "object"}
        if args and len(args) >= 2:
            # For Dict[str, T], add additionalProperties
            value_schema = python_type_to_json_schema(args[1])
            schema["additionalProperties"] = value_schema
        return schema
    
    # Basic type mappings
    type_map = {
        str: {"type": "string"},
        int: {"type": "integer"},
        float: {"type": "number"},
        bool: {"type": "boolean"},
        list: {"type": "array"},
        dict: {"type": "object"},
        type(None): {"type": "null"},
    }
    
    return type_map.get(type_hint, {"type": "object"})


def pydantic_to_json_schema(model: Type[BaseModel]) -> Dict[str, Any]:
    """
    Convert Pydantic model to JSON Schema.
    
    Args:
        model: Pydantic model class
        
    Returns:
        JSON Schema dictionary
    """
    try:
        # Pydantic v2 method
        return model.model_json_schema()
    except AttributeError:
        # Fallback for older Pydantic versions
        return model.schema()


def extract_pydantic_models_from_signature(func: Callable) -> Dict[str, Type[BaseModel]]:
    """
    Extract all Pydantic models used in function signature.
    
    Args:
        func: Function to analyze
        
    Returns:
        Dictionary mapping model names to model classes
    """
    models = {}
    sig = inspect.signature(func)
    
    # Check parameters
    for param_name, param in sig.parameters.items():
        if param.annotation != inspect.Parameter.empty:
            _collect_pydantic_models(param.annotation, models)
    
    # Check return type
    if sig.return_annotation != inspect.Signature.empty:
        _collect_pydantic_models(sig.return_annotation, models)
    
    return models


def _collect_pydantic_models(type_hint: Any, models: Dict[str, Type[BaseModel]]) -> None:
    """
    Recursively collect Pydantic models from type hint.
    
    Args:
        type_hint: Type hint to analyze
        models: Dictionary to store found models
    """
    # Direct Pydantic model
    if inspect.isclass(type_hint) and issubclass(type_hint, BaseModel):
        models[type_hint.__name__] = type_hint
        return
    
    # Handle generics (List, Dict, Optional, etc.)
    args = get_args(type_hint)
    if args:
        for arg in args:
            _collect_pydantic_models(arg, models)


def parse_docstring(func: Callable) -> Tuple[str, Dict[str, str]]:
    """
    Parse function docstring to extract description and parameter docs.
    
    Supports Google-style and NumPy-style docstrings.
    
    Args:
        func: Function to parse
        
    Returns:
        Tuple of (function_description, param_descriptions_dict)
    """
    docstring = inspect.getdoc(func)
    if not docstring:
        return "", {}
    
    lines = docstring.split('\n')
    description_lines = []
    param_docs = {}
    
    in_args_section = False
    current_param = None
    
    for line in lines:
        stripped = line.strip()
        
        # Check for Args/Parameters section
        if stripped.lower() in ['args:', 'arguments:', 'parameters:', 'params:']:
            in_args_section = True
            continue
        
        # Check for end of Args section
        if in_args_section and stripped and stripped.endswith(':') and not line.startswith(' '):
            in_args_section = False
            continue
        
        if in_args_section:
            # Parse parameter line: "param_name: description" or "param_name (type): description"
            param_match = re.match(r'^\s*(\w+)(?:\s*\([^)]+\))?\s*:\s*(.+)$', line)
            if param_match:
                current_param = param_match.group(1)
                param_docs[current_param] = param_match.group(2).strip()
            elif current_param and line.startswith(' '):
                # Continuation of previous parameter description
                param_docs[current_param] += ' ' + stripped
        else:
            # Collect description lines (before Args section)
            if stripped and not stripped.lower().startswith(('returns:', 'return:', 'raises:', 'examples:')):
                description_lines.append(stripped)
    
    description = ' '.join(description_lines)
    return description, param_docs


def load_did_document(path: str) -> Dict[str, Any]:
    """
    Load DID document from file.
    
    Args:
        path: Path to DID document JSON file
        
    Returns:
        DID document dictionary
        
    Raises:
        FileNotFoundError: If file doesn't exist
        json.JSONDecodeError: If file is not valid JSON
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"DID document not found: {path}")
    
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def load_private_key(path: str) -> bytes:
    """
    Load private key from PEM file.
    
    Args:
        path: Path to private key PEM file
        
    Returns:
        Private key bytes
        
    Raises:
        FileNotFoundError: If file doesn't exist
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Private key not found: {path}")
    
    with open(file_path, 'rb') as f:
        return f.read()


def get_function_name_from_callable(func: Callable) -> str:
    """
    Get the name of a callable (function, method, etc.).
    
    Args:
        func: Callable to get name from
        
    Returns:
        Function name
    """
    if hasattr(func, '__name__'):
        return func.__name__
    return str(func)


# Import Union for type checking
from typing import Union

