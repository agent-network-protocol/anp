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

from agent_connect.meta_protocol.code_generator.provider_generator import (
    _generate_provider_class,
    _generate_provider_description,
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

# 使用与test_requester_generator_prompt.py相同的protocol_doc
protocol_doc = '''
# Requirements

Design an API protocol to retrieve educational background information for a single user. This protocol should:
- Allow fetching educational background details for a specified user based on `user_id`.
- The educational background must include the institution name, major, degree, achievements, start and end dates.
- Support error handling and parameter validation.
- Implement pagination for retrieved data.

# Protocol Flow

## Interaction Flow

1. **Request**: The client sends a request to the server containing `user_id` and an optional parameter `include_details` to specify whether detailed information is required.
2. **Validation**: The server validates the input parameters.
3. **Fetch Data**: Upon successful validation, the server retrieves the educational experience data.
4. **Response**: The server sends back a response containing the educational details or an error message if applicable.

# Data Format

## Request Message Format

The request message is in JSON format with the following structure:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "messageType": {
      "type": "string",
      "const": "getUserEducation"
    },
    "messageId": {
      "type": "string",
      "format": "uuid"
    },
    "userId": {
      "type": "string"
    },
    "includeDetails": {
      "type": "boolean",
      "default": false
    },
    "page": {
      "type": "integer",
      "minimum": 1,
      "default": 1
    },
    "pageSize": {
      "type": "integer",
      "minimum": 1,
      "default": 10
    }
  },
  "required": ["messageType", "messageId", "userId"],
  "additionalProperties": false
}
```

## Response Message Format

The response message is also in JSON format and uses the following structure:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "messageType": {
      "type": "string",
      "const": "getUserEducation"
    },
    "messageId": {
      "type": "string",
      "format": "uuid"
    },
    "code": {
      "type": "integer"
    },
    "data": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "institution": {
            "type": "string"
          },
          "major": {
            "type": "string"
          },
          "degree": {
            "type": "string",
            "enum": ["Bachelor", "Master", "Doctorate"]
          },
          "achievements": {
            "type": "string"
          },
          "startDate": {
            "type": "string",
            "format": "date"
          },
          "endDate": {
            "type": "string",
            "format": "date"
          }
        },
        "required": ["institution", "major", "degree", "startDate", "endDate"]
      }
    },
    "pagination": {
      "type": "object",
      "properties": {
        "currentPage": {
          "type": "integer"
        },
        "totalPages": {
          "type": "integer"
        },
        "totalItems": {
          "type": "integer"
        }
      }
    },
    "error": {
      "type": "object",
      "properties": {
        "message": {
          "type": "string"
        },
        "details": {
          "type": "string"
        }
      },
      "required": ["message"]
    }
  },
  "required": ["messageType", "messageId", "code"],
  "additionalProperties": false
}
```

# Error Handling

The API will use standard HTTP status codes for error handling:

- **200 OK**: Request was successful and data is returned.
- **400 Bad Request**: The request parameters were invalid. The `error` field will contain details.
- **404 Not Found**: No educational data found for the given `user_id`.
- **500 Internal Server Error**: An unexpected server error occurred.

Example error response:

```json
{
  "messageType": "getUserEducation",
  "messageId": "123e4567-e89b-12d3-a456-426614174000",
  "code": 400,
  "error": {
    "message": "Invalid user_id format",
    "details": "The user_id must be a valid UUID."
  }
}
```
'''

def get_llm_instance() -> BaseLLM:
    """返回Azure OpenAI LLM实例"""
    client = AsyncAzureOpenAI(
        api_key=AZURE_OPENAI_API_KEY,
        api_version="2024-02-01",
        azure_endpoint=AZURE_OPENAI_ENDPOINT,
        azure_deployment=AZURE_OPENAI_DEPLOYMENT,
    )
    return AzureLLM(client=client, model_name=AZURE_OPENAI_MODEL_NAME)

async def test_provider_generator():
    """测试provider代码生成流程"""

    # 验证配置
    validate_config()

    # 创建LLM实例
    llm = get_llm_instance()
    try:
        # 1. 测试生成provider描述
        logging.info("\n=== 测试生成provider描述 ===")
        description_json = await _generate_provider_description(protocol_doc, llm)

        logging.info("生成的Provider描述:")
        logging.info("-" * 50)
        logging.info(description_json)
        logging.info("-" * 50)

        # 将生成的描述写入文件
        logging.info("将生成的描述写入文件...")
        try:
            current_dir = Path(__file__).parent
            output_file = current_dir / "generated_code/generated_provider_description.json"

            with open(output_file, "w", encoding="utf-8") as f:
                f.write(description_json)
            logging.info(f"描述已成功写入: {output_file}")
        except Exception as e:
            logging.error(f"写入描述文件时出错: {str(e)}")

        # 2. 测试生成provider类
        logging.info("\n=== 测试生成provider类 ===")
        module_name, provider_code = await _generate_provider_class(protocol_doc, description_json, llm)

        logging.info(f"生成的模块名: {module_name}")
        logging.info("生成的Provider代码:")
        logging.info("-" * 50)
        logging.info(provider_code)
        logging.info("-" * 50)

        # 将生成的代码写入文件
        logging.info("将生成的代码写入文件...")
        try:
            current_dir = Path(__file__).parent
            output_file = current_dir / "generated_code/generated_provider_code.py"

            with open(output_file, "w", encoding="utf-8") as f:
                f.write(provider_code)
            logging.info(f"代码已成功写入: {output_file}")
        except Exception as e:
            logging.error(f"写入代码文件时出错: {str(e)}")

        # # 3. 测试完整的生成流程
        # logging.info("\n=== 测试完整的生成流程 ===")
        # final_module_name, final_code, final_description = await generate_provider_code(
        #     protocol_doc,
        #     llm
        # )

        # logging.info(f"最终模块名: {final_module_name}")
        # logging.info("最终代码:")
        # logging.info("-" * 50)
        # logging.info(final_code)
        # logging.info("-" * 50)
        # logging.info("最终描述:")
        # logging.info("-" * 50)
        # logging.info(final_description)
        # logging.info("-" * 50)

    except Exception as e:
        logging.error(f"测试过程中出现错误: {str(e)}", exc_info=True)

if __name__ == "__main__":
    set_log_color_level(logging.INFO)
    asyncio.run(test_provider_generator())