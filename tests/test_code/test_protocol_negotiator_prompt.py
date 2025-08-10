# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.


import asyncio
import logging
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent.parent))

from openai import AsyncAzureOpenAI

from agent_connect.meta_protocol.protocol_negotiator import (
    NegotiationStatus,
    ProtocolNegotiator,
)
from agent_connect.utils.llm.base_llm import AzureLLM, BaseLLM
from agent_connect.utils.log_base import set_log_color_level
from tests.test_code.config import (
    AZURE_OPENAI_API_KEY,
    AZURE_OPENAI_DEPLOYMENT,
    AZURE_OPENAI_ENDPOINT,
    AZURE_OPENAI_MODEL_NAME,
    validate_config,
)


def get_llm_instance() -> BaseLLM:
    """Return Azure OpenAI LLM instance"""

    client = AsyncAzureOpenAI(
        api_key=AZURE_OPENAI_API_KEY,
        api_version="2024-02-01",
        azure_endpoint=AZURE_OPENAI_ENDPOINT,
        azure_deployment=AZURE_OPENAI_DEPLOYMENT,
    )

    # Return AzureLLM instance with client
    return AzureLLM(client=client, model_name=AZURE_OPENAI_MODEL_NAME)

async def mock_capability_info(requirement: str, input_description: str, output_description: str) -> str:
    """Mock capability info callback"""
    logging.info(f"requirement: {requirement}")
    logging.info(f"input_description: {input_description}")
    logging.info(f"output_description: {output_description}")
    logging.info("--------------------------------")
    await asyncio.sleep(0.01)

    return """
    Capability Assessment:
    - Requirements: Can fully meet the specified requirements
    - Input Format: Can process all specified input fields
    - Output Format: Can generate all required output fields
    - No significant limitations or constraints identified
    """

async def test_protocol_negotiation():
    """Test the protocol negotiation process"""

    # 验证配置
    validate_config()

    # 创建 LLM 实例
    llm = get_llm_instance()

    # 创建provider和requester协议协商器
    provider = ProtocolNegotiator(
        llm,
        get_capability_info_callback=mock_capability_info
    )

    requester = ProtocolNegotiator(
        llm,
        get_capability_info_callback=mock_capability_info
    )

    # 测试场景：API 接口协议设计
    requirement = """
    设计一个用于获取用户教育经历的 API 接口。
    - API 应该支持获取单个用户的教育经历信息
    - 教育经历信息应包含：学校名称、专业、学位、成就、开始时间、结束时间
    - 需要支持错误处理和参数验证
    """

    input_description = """
    输入参数应包含：
    - user_id: 用户ID (字符串)
    - include_details: 是否包含详细信息 (布尔值，可选)
    """

    output_description = """
    输出应包含：
    - 教育经历列表，每个教育经历包含：
      * institution: 学校名称
      * major: 专业
      * degree: 学位 (Bachelor/Master/Doctorate)
      * achievements: 成就
      * start_date: 开始时间 (YYYY-MM-DD)
      * end_date: 结束时间 (YYYY-MM-DD)
    - 支持分页和错误信息返回
    """

    try:
        # 1. Requester生成初始协议
        logging.info("=== Requester生成初始协议 ===")
        protocol, status, round_num = await requester.generate_initial_protocol(
            requirement,
            input_description,
            output_description
        )
        logging.info(f"协议生成状态: {status}")
        logging.info(f"当前轮次: {round_num}")
        logging.info(f"生成的协议内容:\n{protocol}")

        # 2. Provider评估协议
        logging.info("=== Provider评估协议 ===")
        provider_result, provider_round = await provider.evaluate_protocol_proposal(
            NegotiationStatus.NEGOTIATING,
            round_num,
            protocol,
            None  # modification_summary for first round is None
        )

        logging.info(f"Provider评估状态: {provider_result.status}")
        logging.info(f"Provider修改说明: {provider_result.modification_summary}")

        if provider_result.status == NegotiationStatus.NEGOTIATING:
            logging.info(f"Provider修改后的协议:\n{provider_result.candidate_protocol}")

        # 3. Requester评估Provider的修改建议
        logging.info("=== Requester评估修改建议 ===")
        requester_result, requester_round = await requester.evaluate_protocol_proposal(
            NegotiationStatus.NEGOTIATING,
            provider_round,
            provider_result.candidate_protocol,
            provider_result.modification_summary
        )

        logging.info(f"Requester评估状态: {requester_result.status}")
        logging.info(f"Requester修改说明: {requester_result.modification_summary}")

        if requester_result.status == NegotiationStatus.NEGOTIATING:
            logging.info(f"最终协议:\n{requester_result.candidate_protocol}")

    except Exception as e:
        logging.error(f"测试过程中出现错误: {str(e)}", exc_info=True)

if __name__ == "__main__":
    set_log_color_level(logging.INFO)
    asyncio.run(test_protocol_negotiation())