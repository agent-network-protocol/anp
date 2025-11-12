#!/usr/bin/env python3
"""
AST Parser to extract all SDKs/APIs from the anp library.

This script scans all Python files in the anp package and extracts
all importable items (classes, functions, constants) that can be
imported using "from anp.xxx import xxx".
"""

import ast
import argparse
import os
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional


def format_arg(arg: ast.arg, default: Optional[ast.AST] = None) -> str:
    """Format a function argument with its type annotation and default value."""
    arg_str = arg.arg
    
    # Add type annotation if present
    if arg.annotation:
        type_str = ast.unparse(arg.annotation) if hasattr(ast, 'unparse') else format_ast_node(arg.annotation)
        arg_str += f": {type_str}"
    
    # Add default value if present
    if default is not None:
        default_str = ast.unparse(default) if hasattr(ast, 'unparse') else format_ast_node(default)
        arg_str += f" = {default_str}"
    
    return arg_str


def format_ast_node(node: ast.AST) -> str:
    """Format an AST node to a string representation."""
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Constant):
        if isinstance(node.value, str):
            return f'"{node.value}"'
        return str(node.value)
    elif isinstance(node, ast.Str):  # Python < 3.8
        return f'"{node.s}"'
    elif isinstance(node, ast.Attribute):
        return f"{format_ast_node(node.value)}.{node.attr}"
    elif isinstance(node, ast.Subscript):
        return f"{format_ast_node(node.value)}[{format_ast_node(node.slice)}]"
    elif isinstance(node, ast.List):
        items = [format_ast_node(elt) for elt in node.elts]
        return f"[{', '.join(items)}]"
    elif isinstance(node, ast.Tuple):
        items = [format_ast_node(elt) for elt in node.elts]
        return f"({', '.join(items)})"
    elif isinstance(node, ast.Dict):
        items = []
        for k, v in zip(node.keys, node.values):
            key_str = format_ast_node(k) if k else "None"
            val_str = format_ast_node(v)
            items.append(f"{key_str}: {val_str}")
        return f"{{{', '.join(items)}}}"
    elif isinstance(node, ast.BinOp):
        left = format_ast_node(node.left)
        right = format_ast_node(node.right)
        op = format_ast_node(node.op)
        return f"{left} {op} {right}"
    elif isinstance(node, ast.Add):
        return "+"
    elif isinstance(node, ast.Sub):
        return "-"
    elif isinstance(node, ast.Mult):
        return "*"
    elif isinstance(node, ast.Div):
        return "/"
    elif isinstance(node, ast.Mod):
        return "%"
    elif isinstance(node, ast.Pow):
        return "**"
    elif isinstance(node, ast.LShift):
        return "<<"
    elif isinstance(node, ast.RShift):
        return ">>"
    elif isinstance(node, ast.BitOr):
        return "|"
    elif isinstance(node, ast.BitXor):
        return "^"
    elif isinstance(node, ast.BitAnd):
        return "&"
    elif isinstance(node, ast.FloorDiv):
        return "//"
    elif isinstance(node, ast.Index):  # Python < 3.9
        return format_ast_node(node.value)
    else:
        return str(type(node).__name__)


def format_function_signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    """Format a complete function signature."""
    is_async = isinstance(node, ast.AsyncFunctionDef)
    prefix = "async " if is_async else ""
    name = node.name
    
    # Build arguments
    args_list = []
    
    # Regular arguments
    defaults_start = len(node.args.args) - len(node.args.defaults)
    for i, arg in enumerate(node.args.args):
        default = node.args.defaults[i - defaults_start] if i >= defaults_start else None
        args_list.append(format_arg(arg, default))
    
    # *args
    if node.args.vararg:
        vararg_str = f"*{node.args.vararg.arg}"
        if node.args.vararg.annotation:
            type_str = ast.unparse(node.args.vararg.annotation) if hasattr(ast, 'unparse') else format_ast_node(node.args.vararg.annotation)
            vararg_str += f": {type_str}"
        args_list.append(vararg_str)
    
    # Keyword-only arguments
    if node.args.kwonlyargs:
        kw_defaults_start = len(node.args.kwonlyargs) - len(node.args.kw_defaults)
        for i, arg in enumerate(node.args.kwonlyargs):
            default = node.args.kw_defaults[i - kw_defaults_start] if i >= kw_defaults_start else None
            args_list.append(format_arg(arg, default))
    
    # **kwargs
    if node.args.kwarg:
        kwarg_str = f"**{node.args.kwarg.arg}"
        if node.args.kwarg.annotation:
            type_str = ast.unparse(node.args.kwarg.annotation) if hasattr(ast, 'unparse') else format_ast_node(node.args.kwarg.annotation)
            kwarg_str += f": {type_str}"
        args_list.append(kwarg_str)
    
    args_str = ", ".join(args_list)
    
    # Return type annotation
    return_type = ""
    if node.returns:
        return_type_str = ast.unparse(node.returns) if hasattr(ast, 'unparse') else format_ast_node(node.returns)
        return_type = f" -> {return_type_str}"
    
    return f"{prefix}def {name}({args_str}){return_type}"


class APIExtractor(ast.NodeVisitor):
    """AST visitor to extract public APIs from Python modules."""

    def __init__(self, module_path: str, ignore_constants: bool = False):
        self.module_path = module_path
        self.ignore_constants = ignore_constants
        self.classes: List[str] = []
        self.functions: List[Tuple[str, str]] = []  # (name, signature)
        self.constants: List[str] = []
        self.all_list: List[str] = []
        self.imports: List[Tuple[str, str]] = []  # (from_module, import_name)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Extract class definitions."""
        # Only include public classes (not starting with _)
        if not node.name.startswith('_'):
            self.classes.append(node.name)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Extract function definitions with full signatures."""
        # Only include public functions (not starting with _)
        if not node.name.startswith('_'):
            signature = format_function_signature(node)
            self.functions.append((node.name, signature))
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Extract async function definitions with full signatures."""
        if not node.name.startswith('_'):
            signature = format_function_signature(node)
            self.functions.append((node.name, signature))
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Extract constant/variable assignments."""
        if self.ignore_constants:
            self.generic_visit(node)
            return
            
        for target in node.targets:
            if isinstance(target, ast.Name):
                name = target.id
                # Include public constants and variables
                if not name.startswith('_') and name not in ['__all__']:
                    # Check if it's a constant (uppercase) or regular variable
                    if name.isupper() or not name.startswith('_'):
                        if name not in self.constants:
                            self.constants.append(name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Extract imports (especially from __init__.py files)."""
        if node.module:
            for alias in node.names:
                import_name = alias.asname if alias.asname else alias.name
                self.imports.append((node.module or '', import_name))
        self.generic_visit(node)

    def visit_List(self, node: ast.List) -> None:
        """Extract __all__ list contents."""
        # Check if this is part of an __all__ assignment
        # This is a simplified check - in practice, we check the parent
        self.generic_visit(node)


def extract_all_from_assign(tree: ast.AST) -> List[str]:
    """Extract items from __all__ assignment."""
    all_items = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == '__all__':
                    if isinstance(node.value, (ast.List, ast.Tuple)):
                        for elt in node.value.elts:
                            # Handle both ast.Str (Python < 3.8) and ast.Constant (Python 3.8+)
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                all_items.append(elt.value)
                            elif hasattr(ast, 'Str') and isinstance(elt, ast.Str):  # Python < 3.8
                                all_items.append(elt.s)
    return all_items


def analyze_file(file_path: Path, package_root: Path, ignore_constants: bool = False) -> Dict:
    """Analyze a single Python file and extract its APIs."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        return {'error': str(e)}

    try:
        tree = ast.parse(content, filename=str(file_path))
    except SyntaxError as e:
        return {'error': f'Syntax error: {e}'}

    # Calculate module path
    rel_path = file_path.relative_to(package_root)
    parts = list(rel_path.parts)
    # Remove .py extension from filename
    if parts:
        parts[-1] = parts[-1].replace('.py', '')
    
    # For __init__.py, remove the __init__ part
    if parts and parts[-1] == '__init__':
        parts = parts[:-1]
    
    if parts:
        module_name = 'anp.' + '.'.join(parts)
    else:
        module_name = "anp"

    # Extract __all__ first
    all_items = extract_all_from_assign(tree)

    # Use visitor to extract APIs
    extractor = APIExtractor(module_name, ignore_constants=ignore_constants)
    extractor.visit(tree)

    # Combine results - functions are now tuples of (name, signature)
    result = {
        'module_path': module_name,
        'file': str(rel_path),
        'classes': sorted(set(extractor.classes)),
        'functions': extractor.functions,  # List of (name, signature) tuples
        'constants': sorted(set(extractor.constants)),
        'all_list': all_items,
        'imports': extractor.imports,
    }

    return result


def find_python_files(package_root: Path) -> List[Path]:
    """Find all Python files in the package, excluding __pycache__ and test files."""
    python_files = []
    for root, dirs, files in os.walk(package_root):
        # Skip __pycache__ directories
        dirs[:] = [d for d in dirs if d != '__pycache__']
        # Skip test directories
        dirs[:] = [d for d in dirs if not d.startswith('test')]
        
        for file in files:
            if file.endswith('.py') and not file.startswith('test_'):
                python_files.append(Path(root) / file)
    
    return sorted(python_files)


def format_output(results: List[Dict], ignore_constants: bool = False) -> str:
    """Format the extracted APIs into a readable text output."""
    output_lines = []
    output_lines.append("=" * 80)
    output_lines.append("ANP Library - All Importable SDKs/APIs")
    output_lines.append("=" * 80)
    output_lines.append("")
    output_lines.append("This file contains all classes, functions, and constants")
    output_lines.append("that can be imported from the anp library.")
    output_lines.append("")
    output_lines.append("=" * 80)
    output_lines.append("")

    # Group by module
    modules: Dict[str, Dict] = {}
    for result in results:
        if 'error' in result:
            continue
        module = result['module_path']
        if module not in modules:
            modules[module] = {
                'classes': set(),
                'functions': {},  # Dict: name -> signature
                'constants': set(),
                'all_list': set(),
                'imports': [],
            }
        modules[module]['classes'].update(result['classes'])
        # Functions are now (name, signature) tuples
        for func_name, func_sig in result['functions']:
            modules[module]['functions'][func_name] = func_sig
        if not ignore_constants:
            modules[module]['constants'].update(result['constants'])
        modules[module]['all_list'].update(result['all_list'])
        modules[module]['imports'].extend(result['imports'])

    # Output by module
    for module in sorted(modules.keys()):
        data = modules[module]
        output_lines.append(f"Module: {module}")
        output_lines.append("-" * 80)

        # Show __all__ exports if available
        if data['all_list']:
            output_lines.append("  __all__ exports:")
            for item in sorted(data['all_list']):
                output_lines.append(f"    - {item}")
            output_lines.append("")

        # Show classes
        if data['classes']:
            output_lines.append("  Classes:")
            for cls in sorted(data['classes']):
                output_lines.append(f"    - {cls}")
            output_lines.append("")

        # Show functions with full signatures
        if data['functions']:
            output_lines.append("  Functions:")
            for func_name in sorted(data['functions'].keys()):
                func_sig = data['functions'][func_name]
                output_lines.append(f"    - {func_sig}")
            output_lines.append("")

        # Show constants (only if not ignored)
        if not ignore_constants and data['constants']:
            output_lines.append("  Constants/Variables:")
            for const in sorted(data['constants']):
                output_lines.append(f"    - {const}")
            output_lines.append("")

        # Show re-exports from __init__.py
        if data['imports'] and module.endswith('__init__'):
            output_lines.append("  Re-exported imports:")
            for from_mod, import_name in data['imports']:
                if from_mod:
                    output_lines.append(f"    - from {from_mod} import {import_name}")
                else:
                    output_lines.append(f"    - import {import_name}")
            output_lines.append("")

        output_lines.append("")

    # Summary
    output_lines.append("=" * 80)
    output_lines.append("Summary")
    output_lines.append("=" * 80)
    total_classes = sum(len(m['classes']) for m in modules.values())
    total_functions = sum(len(m['functions']) for m in modules.values())
    total_constants = sum(len(m['constants']) for m in modules.values()) if not ignore_constants else 0
    total_all = sum(len(m['all_list']) for m in modules.values())
    
    output_lines.append(f"Total modules analyzed: {len(modules)}")
    output_lines.append(f"Total classes: {total_classes}")
    output_lines.append(f"Total functions: {total_functions}")
    if not ignore_constants:
        output_lines.append(f"Total constants: {total_constants}")
    output_lines.append(f"Total __all__ exports: {total_all}")
    output_lines.append("")

    # Import examples
    output_lines.append("=" * 80)
    output_lines.append("Example Import Statements")
    output_lines.append("=" * 80)
    output_lines.append("")
    
    for module in sorted(modules.keys()):
        data = modules[module]
        has_content = any([data['classes'], data['functions'], data['all_list']])
        if not ignore_constants:
            has_content = has_content or bool(data['constants'])
        if not has_content:
            continue
        
        # Use __all__ if available, otherwise use classes/functions
        func_names = list(data['functions'].keys())
        const_list = list(data['constants']) if not ignore_constants else []
        exports = sorted(data['all_list']) if data['all_list'] else sorted(
            list(data['classes']) + func_names + const_list
        )
        
        if exports:
            # Show first few exports as examples
            example_exports = exports[:5]
            if len(exports) > 5:
                example_exports.append(f"... and {len(exports) - 5} more")
            
            module_import = module.replace('anp.', 'anp/').replace('.', '/')
            output_lines.append(f"from {module} import {', '.join(example_exports)}")
    
    output_lines.append("")
    output_lines.append("=" * 80)

    return '\n'.join(output_lines)


def main():
    """Main function to run the API extraction."""
    parser = argparse.ArgumentParser(
        description='Extract all SDKs/APIs from the anp library'
    )
    parser.add_argument(
        '--ignore-constants',
        action='store_true',
        help='Ignore constants and variables in the output'
    )
    args = parser.parse_args()
    
    # Get the package root (parent of this script)
    script_dir = Path(__file__).parent
    package_root = script_dir / 'anp'
    
    if not package_root.exists():
        print(f"Error: Package directory not found at {package_root}")
        return

    print(f"Scanning package at: {package_root}")
    if args.ignore_constants:
        print("Constants/Variables will be ignored in output")
    
    # Find all Python files
    python_files = find_python_files(package_root)
    print(f"Found {len(python_files)} Python files to analyze")
    
    # Analyze each file
    results = []
    for file_path in python_files:
        print(f"Analyzing: {file_path.relative_to(script_dir)}")
        result = analyze_file(file_path, package_root, ignore_constants=args.ignore_constants)
        results.append(result)
    
    # Format output
    output = format_output(results, ignore_constants=args.ignore_constants)
    
    # Write to file
    output_file = script_dir / 'anp_all_sdk_list.txt'
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(output)
    
    print(f"\nOutput written to: {output_file}")
    print(f"Total modules analyzed: {len([r for r in results if 'error' not in r])}")


if __name__ == '__main__':
    main()

