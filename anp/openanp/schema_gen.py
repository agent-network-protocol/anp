# pyright: reportMissingImports=false

"""OpenANP SDK - Schema Generation Module

Auto-generate JSON Schema from Python type hints.

Design principles:
- Type-safe: Preserve all type information
- Extensible: Support Pydantic, TypedDict, and custom types
- Fallback-friendly: Unknown types become {"type": "object"}

Supported types:
- Primitive: str, int, float, bool, None
- Container: list[T], dict[str, T], tuple[T, ...]
- Union: Optional[T], Union[T1, T2], T1 | T2
- Annotated: Annotated[T, "description"]
- TypedDict: Full object schema with properties
- Pydantic: BaseModel with model_json_schema()
- Literal: Literal["a", "b"] -> enum schema
- Enum: enum.Enum -> enum schema with values
- NewType: NewType("Name", T) -> underlying type schema
"""

from __future__ import annotations

import enum
import inspect
import types
from typing import (
    Annotated,
    Any,
    Callable,
    Literal,
    Union,
    cast,
    get_args,
    get_origin,
    get_type_hints,
)

# NOTE: This import is required at runtime, but some editors may not resolve the
# mono-repo layout correctly. Pyright is configured per-file above.
from .types import RPCMethodInfo  # pyright: ignore[reportMissingImports]

# Python 3.10+ supports is_typeddict
try:
    from typing import NotRequired, is_typeddict
except ImportError:
    # Fallback for Python 3.9
    def is_typeddict(tp: Any) -> bool:
        return hasattr(tp, "__annotations__") and hasattr(tp, "__total__")

    class NotRequired:
        pass


_PY_UNION_TYPE = getattr(types, "UnionType", None)

__all__ = [
    "type_to_json_schema",
    "extract_method_schemas",
    "create_rpc_methods_from_callables",
]


# =============================================================================
# Core Type Conversion
# =============================================================================


def type_to_json_schema(py_type: Any) -> dict[str, Any]:
    """Convert Python type hint to JSON Schema.

    Supports:
    - Primitive types: str, int, float, bool, None
    - Container types: list[T], dict[str, T], tuple[T, ...]
    - Union types: Optional[T], Union[T1, T2], T1 | T2
    - Annotated types: Annotated[T, "description"]
    - TypedDict: Full object schema with properties
    - Pydantic BaseModel: Delegates to model_json_schema()
    - Literal: Literal["a", "b"] -> enum schema
    - Enum: enum.Enum -> enum schema with values

    Args:
        py_type: Python type hint

    Returns:
        JSON Schema dictionary

    Example:
        >>> type_to_json_schema(str)
        {"type": "string"}

        >>> type_to_json_schema(list[int])
        {"type": "array", "items": {"type": "integer"}}

        >>> type_to_json_schema(Annotated[str, "User query"])
        {"type": "string", "description": "User query"}

        >>> type_to_json_schema(Literal["asc", "desc"])
        {"type": "string", "enum": ["asc", "desc"]}
    """
    origin = get_origin(py_type)

    # Annotated[T, "description"] - extract description from metadata
    if origin is Annotated:
        args = get_args(py_type)
        base_schema = type_to_json_schema(args[0])
        # Last argument is typically the description
        if len(args) > 1 and isinstance(args[-1], str):
            base_schema["description"] = args[-1]
        return base_schema

    # NotRequired[T] - used in TypedDict for optional fields
    if origin is NotRequired:
        return type_to_json_schema(get_args(py_type)[0])

    # Literal["a", "b", ...] -> enum schema
    if origin is Literal:
        args = get_args(py_type)
        if not args:
            raise TypeError("Literal must have at least one value")
        # Infer type from first value
        first_val = args[0]
        if isinstance(first_val, str):
            return {"type": "string", "enum": list(args)}
        if isinstance(first_val, int) and not isinstance(first_val, bool):
            return {"type": "integer", "enum": list(args)}
        if isinstance(first_val, float):
            return {"type": "number", "enum": list(args)}
        if isinstance(first_val, bool):
            return {"type": "boolean", "enum": list(args)}
        return {"enum": list(args)}

    # Union[Ts...], Optional[T], T1 | T2
    if origin is Union or (
        _PY_UNION_TYPE is not None and isinstance(py_type, _PY_UNION_TYPE)
    ):
        args = get_args(py_type)
        return {"anyOf": [type_to_json_schema(t) for t in args]}

    # list[T]
    if origin is list:
        args = get_args(py_type)
        if not args:
            raise TypeError("list must be parameterized, e.g. list[int]")
        # Handle list[Any] - Any means any item type
        if args[0] is Any:
            return {"type": "array"}
        return {"type": "array", "items": type_to_json_schema(args[0])}

    # tuple[T, ...] - treat as array
    if origin is tuple:
        args = get_args(py_type)
        if not args:
            raise TypeError("tuple must be parameterized, e.g. tuple[int, ...]")
        # If all same type or ends with ..., treat as homogeneous array
        if len(args) == 2 and args[1] is ...:
            return {"type": "array", "items": type_to_json_schema(args[0])}
        # Otherwise, tuple with fixed items
        return {
            "type": "array",
            "prefixItems": [type_to_json_schema(t) for t in args],
            "minItems": len(args),
            "maxItems": len(args),
        }

    # dict[str, T]
    if origin is dict:
        args = get_args(py_type)
        if len(args) < 2:
            raise TypeError("dict must be parameterized, e.g. dict[str, int]")
        # Handle dict[str, Any] - Any means any value type
        if args[1] is Any:
            return {"type": "object"}
        return {
            "type": "object",
            "additionalProperties": type_to_json_schema(args[1]),
        }

    # TypedDict - full object schema
    if is_typeddict(py_type):
        return _typed_dict_to_schema(py_type)

    # Pydantic BaseModel - delegate to model_json_schema()
    if hasattr(py_type, "model_json_schema"):
        return py_type.model_json_schema()

    # enum.Enum subclass - convert to enum schema
    if isinstance(py_type, type) and issubclass(py_type, enum.Enum):
        return _enum_to_schema(py_type)

    # NewType - unwrap to underlying type
    if hasattr(py_type, "__supertype__"):
        return type_to_json_schema(py_type.__supertype__)

    # typing.Any - represents any type (no constraints)
    if py_type is Any:
        return {}  # Empty schema means any type

    # Primitive type mapping
    primitive_map: dict[type, str] = {
        str: "string",
        int: "integer",
        float: "number",
        bool: "boolean",
        list: "array",
        dict: "object",
        type(None): "null",
    }

    if py_type in primitive_map:
        return {"type": primitive_map[py_type]}

    raise TypeError(f"Unsupported type hint: {py_type!r}")


def _typed_dict_to_schema(typed_dict_class: type) -> dict[str, Any]:
    """Convert TypedDict to JSON Schema.

    Args:
        typed_dict_class: A TypedDict class

    Returns:
        JSON Schema with properties and required fields

    Example:
        class SearchParams(TypedDict):
            query: str
            limit: NotRequired[int]

        >>> _typed_dict_to_schema(SearchParams)
        {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer"}
            },
            "required": ["query"]
        }
    """
    hints = get_type_hints(typed_dict_class, include_extras=True)
    required_keys = getattr(typed_dict_class, "__required_keys__", set(hints.keys()))

    return {
        "type": "object",
        "properties": {
            field_name: type_to_json_schema(field_type)
            for field_name, field_type in hints.items()
        },
        "required": [key for key in hints.keys() if key in required_keys],
    }


def _enum_to_schema(enum_class: type[enum.Enum]) -> dict[str, Any]:
    """Convert enum.Enum subclass to JSON Schema.

    Args:
        enum_class: An enum.Enum subclass

    Returns:
        JSON Schema with enum values

    Example:
        class SortOrder(enum.Enum):
            ASC = "asc"
            DESC = "desc"

        >>> _enum_to_schema(SortOrder)
        {"type": "string", "enum": ["asc", "desc"]}

        class Priority(enum.IntEnum):
            LOW = 1
            MEDIUM = 2
            HIGH = 3

        >>> _enum_to_schema(Priority)
        {"type": "integer", "enum": [1, 2, 3]}
    """
    # Extract enum values
    values = [member.value for member in enum_class]

    if not values:
        return {"type": "string"}

    # Infer type from first value
    first_val = values[0]

    # Check if it's an IntEnum or similar
    if isinstance(first_val, int) and not isinstance(first_val, bool):
        return {"type": "integer", "enum": values}
    elif isinstance(first_val, float):
        return {"type": "number", "enum": values}
    elif isinstance(first_val, bool):
        return {"type": "boolean", "enum": values}
    elif isinstance(first_val, str):
        return {"type": "string", "enum": values}
    else:
        # Mixed or unknown types
        return {"enum": values}


# =============================================================================
# Function Schema Extraction
# =============================================================================

# Parameters to skip when extracting schemas
SKIP_PARAMS = frozenset({"self", "cls", "request", "ctx", "context"})


def extract_method_schemas(func: Callable) -> tuple[dict[str, Any], dict[str, Any]]:
    """Extract params_schema and result_schema from a function.

    Analyzes function signature and type hints to generate JSON Schemas.
    Skips special parameters (self, request, ctx).
    Detects required parameters based on default values.

    Args:
        func: Function to analyze

    Returns:
        Tuple of (params_schema, result_schema)

    Example:
        async def search(request, query: str, limit: int = 10) -> dict:
            ...

        >>> params, result = extract_method_schemas(search)
        >>> params
        {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer"}
            },
            "required": ["query"]
        }
        >>> result
        {"type": "object"}
    """
    # Get type hints with Annotated preserved
    try:
        hints = get_type_hints(func, include_extras=True)
    except Exception:
        # Fallback if type hints cannot be resolved
        hints = {}

    return_type = hints.pop("return", None)
    sig = inspect.signature(func)

    # Build params_schema
    properties: dict[str, Any] = {}
    required: list[str] = []

    for param_name, param_type in hints.items():
        # Skip special parameters
        if param_name in SKIP_PARAMS:
            continue

        properties[param_name] = type_to_json_schema(param_type)

        # Check if parameter has default value
        param = sig.parameters.get(param_name)
        if param is None or param.default is inspect.Parameter.empty:
            required.append(param_name)

    params_schema: dict[str, Any] = {
        "type": "object",
        "properties": properties,
        "required": required,
    }

    # Build result_schema
    if return_type is not None:
        result_schema = type_to_json_schema(return_type)
    else:
        result_schema = {"type": "object"}

    return params_schema, result_schema


# =============================================================================
# Batch Generation
# =============================================================================


def create_rpc_methods_from_callables(
    callables: list[Callable],
) -> list[RPCMethodInfo]:
    """Generate RPCMethodInfo list from callable list.

    This is the primary API for batch schema generation.
    Each function becomes an RPCMethodInfo with auto-generated schemas.

    Args:
        callables: List of functions to convert

    Returns:
        List of RPCMethodInfo objects

    Example:
        async def search(request, query: str) -> dict:
            '''Search for hotels.'''
            return {"results": []}

        async def book(request, hotel_id: str, guest: str) -> dict:
            '''Book a hotel room.'''
            return {"status": "booked"}

        >>> methods = create_rpc_methods_from_callables([search, book])
        >>> len(methods)
        2
        >>> methods[0].name
        "search"
        >>> methods[0].params_schema["properties"]["query"]
        {"type": "string"}
    """
    methods: list[RPCMethodInfo] = []

    for func in callables:
        params_schema, result_schema = extract_method_schemas(func)

        # Extract description from docstring
        func_name = cast(Any, func).__name__
        description = (func.__doc__ or f"RPC method: {func_name}").strip()
        # Use only first line of docstring
        if "\n" in description:
            description = description.split("\n")[0].strip()

        method = RPCMethodInfo(
            name=func_name,
            description=description,
            params_schema=params_schema,
            result_schema=result_schema,
            handler=func,
        )
        methods.append(method)

    return methods
