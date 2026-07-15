#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""运行所有可执行的 example 脚本，并收集错误信息。

此脚本用于测试 examples 目录下的所有示例。
支持四种模式：
1. 独立示例：直接运行
2. 服务器/客户端配对示例：先启动服务器，再运行客户端
3. 需要配置的示例：检查配置后运行
4. 跳过的示例：非独立脚本（模块、__init__ 等）

使用方法：
    uv run python scripts/run_all_examples.py
"""

import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class ExampleResult:
    """示例执行结果。"""

    name: str
    path: Path
    success: bool
    return_code: int
    stdout: str
    stderr: str
    error_message: Optional[str] = None


@dataclass
class ServerClientPair:
    """服务器/客户端配对信息。"""

    name: str
    server: str
    client: str
    port: int = 8000
    startup_delay: float = 2.0  # 服务器启动后等待时间


@dataclass
class ConfigurableExample:
    """需要配置的示例。"""

    name: str
    script: str
    required_env_vars: List[str]
    description: str
    env_example: Dict[str, str] = field(default_factory=dict)
    timeout: int = 120  # 可能需要更长的超时


# 可以独立运行的示例（离线或自包含）
STANDALONE_EXAMPLES = [
    # DID WBA 示例（离线）
    "examples/python/did_wba_examples/create_did_document.py",
    "examples/python/did_wba_examples/e1_authenticate_and_verify.py",
    "examples/python/did_wba_examples/validate_did_document.py",
    # AP2 支付协议示例（自包含，启动临时服务器）
    "examples/python/ap2_examples/ap2_complete_flow.py",
]

# 服务器/客户端配对示例
SERVER_CLIENT_PAIRS = [
    ServerClientPair(
        name="Hotel Booking Agent",
        server="examples/python/fastanp_examples/hotel_booking_agent.py",
        client="examples/python/fastanp_examples/test_hotel_booking_client.py",
        port=8000,
        startup_delay=3.0,
    ),
    ServerClientPair(
        name="Minimal ANP Server",
        server="examples/python/minimal_example/minimal_anp_server.py",
        client="examples/python/minimal_example/minimal_anp_client.py",
        port=8000,
        startup_delay=2.0,
    ),
    ServerClientPair(
        name="OpenANP Minimal Server",
        server="examples/python/openanp_examples/minimal_server.py",
        client="examples/python/openanp_examples/minimal_client.py",
        port=8000,
        startup_delay=2.0,
    ),
    ServerClientPair(
        name="OpenANP Advanced Server",
        server="examples/python/openanp_examples/advanced_server.py",
        client="examples/python/openanp_examples/advanced_client.py",
        port=8000,
        startup_delay=2.0,
    ),
]

# 需要配置的示例
CONFIGURABLE_EXAMPLES = [
    ConfigurableExample(
        name="ANP Crawler - AMAP 简单示例",
        script="examples/python/anp_crawler_examples/simple_amap_example.py",
        required_env_vars=[],  # 访问外部 API，但不需要本地配置
        description="ANP 爬虫示例，访问 agent-connect.ai 的 AMAP 服务",
        env_example={},
        timeout=60,
    ),
    ConfigurableExample(
        name="ANP Crawler - AMAP 完整示例",
        script="examples/python/anp_crawler_examples/amap_crawler_example.py",
        required_env_vars=[],  # 访问外部 API，但不需要本地配置
        description="ANP 爬虫完整示例，访问 agent-connect.ai 的 AMAP 服务",
        env_example={},
        timeout=120,
    ),
]

# 需要跳过的示例（非独立脚本）
SKIPPED_EXAMPLES = [
    # negotiation_mode 需要 Azure OpenAI 配置，且需要两个终端配合运行
    (
        "examples/python/negotiation_mode/negotiation_bob.py",
        "需要 Azure OpenAI 配置，且需要与 negotiation_alice.py 在两个终端配合运行",
    ),
    (
        "examples/python/negotiation_mode/negotiation_alice.py",
        "需要 Azure OpenAI 配置，且需要与 negotiation_bob.py 在两个终端配合运行",
    ),
    ("examples/python/negotiation_mode/config.py", "配置模块，非独立示例"),
    ("examples/python/negotiation_mode/utils.py", "工具模块，非独立示例"),
    # simple_agent 没有对应的客户端
    (
        "examples/python/fastanp_examples/simple_agent.py",
        "服务器示例，无对应测试客户端",
    ),
    (
        "examples/python/fastanp_examples/simple_agent_with_context.py",
        "服务器示例，无对应测试客户端",
    ),
    ("examples/python/fastanp_examples/config_example.py", "配置示例，非独立脚本"),
    # __init__.py 文件
    ("examples/python/minimal_example/__init__.py", "__init__ 模块"),
    (
        "examples/python/minimal_example/minimal_anp_agent.py",
        "Agent 模块，被 server 导入",
    ),
    ("examples/python/ap2_examples/__init__.py", "__init__ 模块"),
    (
        "examples/python/ap2_examples/merchant_agent.py",
        "Agent 模块，被 merchant_server 导入",
    ),
    (
        "examples/python/ap2_examples/merchant_server.py",
        "服务器，需要 shopper_client 配合（ap2_complete_flow.py 已覆盖此场景）",
    ),
    (
        "examples/python/ap2_examples/shopper_agent.py",
        "Agent 模块，被 shopper_client 导入",
    ),
    (
        "examples/python/ap2_examples/shopper_client.py",
        "客户端，需要 merchant_server 配合（ap2_complete_flow.py 已覆盖此场景）",
    ),
]


def get_project_root() -> Path:
    """获取项目根目录。"""
    # scripts 目录的父目录是项目根目录
    return Path(__file__).resolve().parent.parent


def check_env_vars(required_vars: List[str]) -> Tuple[bool, List[str]]:
    """检查环境变量是否已设置。

    Args:
        required_vars: 必需的环境变量列表

    Returns:
        Tuple[bool, List[str]]: (是否全部设置, 缺失的变量列表)
    """
    missing = [var for var in required_vars if not os.getenv(var)]
    return len(missing) == 0, missing


def run_example(example_path: Path, timeout: int = 60) -> ExampleResult:
    """运行单个示例脚本。

    Args:
        example_path: 示例脚本路径
        timeout: 超时时间（秒）

    Returns:
        ExampleResult: 执行结果
    """
    root = get_project_root()
    name = str(example_path.relative_to(root))

    try:
        result = subprocess.run(
            ["uv", "run", "python", str(example_path)],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        return ExampleResult(
            name=name,
            path=example_path,
            success=result.returncode == 0,
            return_code=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            error_message=result.stderr if result.returncode != 0 else None,
        )
    except subprocess.TimeoutExpired:
        return ExampleResult(
            name=name,
            path=example_path,
            success=False,
            return_code=-1,
            stdout="",
            stderr="",
            error_message=f"Timeout after {timeout} seconds",
        )
    except Exception as e:
        return ExampleResult(
            name=name,
            path=example_path,
            success=False,
            return_code=-1,
            stdout="",
            stderr="",
            error_message=str(e),
        )


def run_server_client_pair(
    pair: ServerClientPair, timeout: int = 60
) -> Tuple[ExampleResult, Optional[str]]:
    """运行服务器/客户端配对示例。

    Args:
        pair: 服务器/客户端配对信息
        timeout: 客户端超时时间（秒）

    Returns:
        Tuple[ExampleResult, Optional[str]]: 客户端执行结果和服务器输出
    """
    root = get_project_root()
    server_path = root / pair.server
    client_path = root / pair.client

    server_process = None
    server_output = ""

    try:
        # 启动服务器
        server_process = subprocess.Popen(
            ["uv", "run", "python", str(server_path)],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            preexec_fn=None if sys.platform == "win32" else lambda: None,
        )

        # 等待服务器启动
        time.sleep(pair.startup_delay)

        # 检查服务器是否正常启动
        if server_process.poll() is not None:
            # 服务器已退出，获取输出
            server_output = (
                server_process.stdout.read() if server_process.stdout else ""
            )
            return ExampleResult(
                name=f"{pair.name} (Server)",
                path=server_path,
                success=False,
                return_code=server_process.returncode or -1,
                stdout=server_output,
                stderr="",
                error_message=f"Server exited prematurely with code {server_process.returncode}\n{server_output}",
            ), server_output

        # 运行客户端
        client_result = run_example(client_path, timeout=timeout)
        client_result.name = f"{pair.name} (Client: {client_path.name})"

        return client_result, server_output

    finally:
        # 终止服务器进程
        if server_process and server_process.poll() is None:
            server_process.terminate()
            try:
                server_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_process.kill()


def print_env_requirements():
    """打印所有需要配置的环境变量。"""
    print()
    print("=" * 70)
    print("环境变量配置需求")
    print("=" * 70)
    print()
    print("请在项目根目录创建 .env 文件，内容如下：")
    print()
    print("-" * 70)
    print("# .env 文件内容")
    print("-" * 70)
    print()

    # 收集所有环境变量
    all_env_vars: Dict[str, str] = {}
    for example in CONFIGURABLE_EXAMPLES:
        for var, value in example.env_example.items():
            if var not in all_env_vars:
                all_env_vars[var] = value

    # 按类别打印
    print("# Azure OpenAI 配置 (用于 negotiation_mode 示例)")
    azure_vars = [v for v in all_env_vars if v.startswith("AZURE_")]
    for var in azure_vars:
        print(f"{var}={all_env_vars[var]}")

    print()
    print("-" * 70)
    print()

    # 打印每个示例的详细需求
    for example in CONFIGURABLE_EXAMPLES:
        if example.required_env_vars:
            print(f"📋 {example.name}")
            print(f"   脚本: {example.script}")
            print(f"   描述: {example.description}")
            print(f"   需要的环境变量:")
            for var in example.required_env_vars:
                print(f"      - {var}")
            print()


def main() -> int:
    """运行所有示例并报告结果。"""
    root = get_project_root()
    results: List[ExampleResult] = []
    skipped_configurable: List[Tuple[ConfigurableExample, List[str]]] = []

    print("=" * 70)
    print("运行所有 Example 脚本")
    print("=" * 70)
    print(f"项目根目录: {root}")
    print()

    # 1. 运行独立示例
    print("📦 独立运行的示例:")
    print("-" * 50)

    for example_rel in STANDALONE_EXAMPLES:
        example_path = root / example_rel
        if not example_path.exists():
            print(f"  ⚠️  跳过（文件不存在）: {example_rel}")
            continue

        print(f"  ▶️  运行: {example_rel} ...", end=" ", flush=True)
        result = run_example(example_path)
        results.append(result)

        if result.success:
            print("✅ 成功")
        else:
            print("❌ 失败")

    # 2. 运行服务器/客户端配对示例
    print()
    print("🔗 服务器/客户端配对示例:")
    print("-" * 50)

    for pair in SERVER_CLIENT_PAIRS:
        server_path = root / pair.server
        client_path = root / pair.client

        if not server_path.exists():
            print(f"  ⚠️  跳过（服务器文件不存在）: {pair.server}")
            continue
        if not client_path.exists():
            print(f"  ⚠️  跳过（客户端文件不存在）: {pair.client}")
            continue

        print(f"  ▶️  运行: {pair.name}")
        print(f"      服务器: {pair.server}")
        print(f"      客户端: {pair.client}")
        print(f"      等待启动: {pair.startup_delay}s ...", end=" ", flush=True)

        result, server_output = run_server_client_pair(pair)
        results.append(result)

        if result.success:
            print("✅ 成功")
        else:
            print("❌ 失败")

    # 3. 运行需要配置的示例
    print()
    print("🔧 需要配置的示例:")
    print("-" * 50)

    for example in CONFIGURABLE_EXAMPLES:
        example_path = root / example.script
        if not example_path.exists():
            print(f"  ⚠️  跳过（文件不存在）: {example.script}")
            continue

        # 检查环境变量
        if example.required_env_vars:
            env_ok, missing_vars = check_env_vars(example.required_env_vars)
            if not env_ok:
                print(f"  ⏭️  跳过: {example.name}")
                print(f"      原因: 缺少环境变量 {', '.join(missing_vars)}")
                skipped_configurable.append((example, missing_vars))
                continue

        print(f"  ▶️  运行: {example.name}")
        print(f"      脚本: {example.script}")
        print(f"      描述: {example.description}")
        print(f"      超时: {example.timeout}s ...", end=" ", flush=True)

        result = run_example(example_path, timeout=example.timeout)
        results.append(result)

        if result.success:
            print("✅ 成功")
        else:
            print("❌ 失败")

    # 4. 显示跳过的示例
    print()
    print("⏭️  跳过的示例（非独立脚本）:")
    print("-" * 50)
    for example_rel, reason in SKIPPED_EXAMPLES:
        print(f"  {example_rel}")
        print(f"      原因: {reason}")

    # 汇总结果
    print()
    print("=" * 70)
    print("执行结果汇总")
    print("=" * 70)

    success_count = sum(1 for r in results if r.success)
    fail_count = len(results) - success_count

    print(f"  总计运行: {len(results)}")
    print(f"  成功: {success_count}")
    print(f"  失败: {fail_count}")
    print(f"  跳过（缺少配置）: {len(skipped_configurable)}")
    print()

    # 显示失败详情
    failed_results = [r for r in results if not r.success]
    if failed_results:
        print("=" * 70)
        print("失败详情")
        print("=" * 70)

        for result in failed_results:
            print()
            print(f"❌ {result.name}")
            print(f"   返回码: {result.return_code}")
            if result.error_message:
                print("   错误信息:")
                # 缩进错误信息，只显示最后30行
                lines = result.error_message.strip().split("\n")
                if len(lines) > 30:
                    print("      ... (truncated)")
                    lines = lines[-30:]
                for line in lines:
                    print(f"      {line}")
            if result.stdout:
                print("   标准输出:")
                lines = result.stdout.strip().split("\n")
                if len(lines) > 20:
                    print("      ... (truncated)")
                    lines = lines[-20:]
                for line in lines:
                    print(f"      {line}")
    elif fail_count == 0 and len(skipped_configurable) == 0:
        print("🎉 所有示例运行成功！")
    else:
        print("✅ 已运行的示例全部成功！")

    # 如果有跳过的配置示例，打印配置需求
    if skipped_configurable:
        print_env_requirements()

    return 1 if fail_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
