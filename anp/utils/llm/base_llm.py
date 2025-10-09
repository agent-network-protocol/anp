# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.


import datetime
import os
import logging
import base64
from openai import AsyncAzureOpenAI, AzureOpenAI
from abc import ABC, abstractmethod
import openai
from pydantic import BaseModel
from typing import List, Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class BaseLLM(ABC):
    """Base class for LLM"""
    
    def __init__(self, client, model_name: str):
        """Initialize base class with client"""
        # TODO: This is not a good approach, needs optimization later
        self.client = client
        self.model_name = model_name

    @abstractmethod
    async def async_generate_response(self, system_prompt: str, user_prompt: str) -> str:
        """Abstract method for async response generation, to be implemented by subclasses"""
        pass

    @abstractmethod
    async def async_generate_vision_response(self, system_prompt: str, user_prompt: str, image_path: str) -> str:
        """Abstract method for async vision response generation, to be implemented by subclasses"""
        pass

    @abstractmethod
    async def async_openai_generate_parse(self, system_prompt: str, user_prompt: str, response_format) -> BaseModel:
        """Abstract method for async parse response generation, to be implemented by subclasses"""
        pass

    @abstractmethod
    async def async_generate_vision_parse_response(self, system_prompt: str, user_prompt: str, image_path: str, response_format) -> BaseModel:
        """Abstract method for async vision parse response generation, to be implemented by subclasses"""
        pass

class AzureLLM(BaseLLM):
    """LLM subclass using Azure OpenAI"""

    def __init__(self, client, model_name: str):
        """Initialize AzureLLM
        
        Args:
            client: The Azure OpenAI client instance
            model_name: Model name to use
        """
        super().__init__(client, model_name)

    async def async_generate_response(self, system_prompt: str, user_prompt: str) -> str:
        """Method for async response generation"""
        try:
            response = await self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ]
            )
            return response.choices[0].message.content
        except Exception as e:
            logging.error(f"Failed to generate response: {str(e)}")
            return ""

    async def async_generate_vision_response(self, system_prompt: str, user_prompt: str, image_path: str) -> str:
        """Method for async vision response generation"""
        try:
            with open(image_path, "rb") as image_file:
                base64_image = base64.b64encode(image_file.read()).decode('utf-8')
            
            response = await self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": user_prompt
                            },
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:image/jpeg;base64,{base64_image}"
                                }
                            }
                        ]
                    }
                ]
            )
            return response.choices[0].message.content
        except Exception as e:
            logging.error(f"Failed to generate vision response: {str(e)}")
            return ""
        
    async def async_openai_generate_parse(self, system_prompt: str, user_prompt: str, response_format):
        """Method for async parse response generation"""
        try:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]
            completion = await self.client.beta.chat.completions.parse(
                model=self.model_name,
                messages=messages,
                response_format=response_format,
            )
            return completion.choices[0].message.parsed
        except Exception as e:
            logging.error(f"Failed to generate parse response: {str(e)}")
            # Handle edge cases
            if type(e) == openai.LengthFinishReasonError:
                logging.error(f"Too many tokens: {str(e)}")
            else:
                # Handle other exceptions
                logging.error(f"Failed to generate parse response: {str(e)}")
            return None

    async def async_generate_vision_parse_response(self, system_prompt: str, user_prompt: str, image_path: str, response_format) -> BaseModel:
        """Method for async vision parse response generation"""
        try:
            messages = [
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": user_prompt
                        }
                    ]
                }
            ]
            
            if image_path and os.path.exists(image_path):
                with open(image_path, "rb") as image_file:
                    base64_image = base64.b64encode(image_file.read()).decode('utf-8')
                messages[1]["content"].append({
                    "type": "image_url",
                    "image_url": {
                        "url": f"data:image/jpeg;base64,{base64_image}"
                    }
                })
            start_time = datetime.datetime.now()
            completion = await self.client.beta.chat.completions.parse(
                model=self.model_name,
                messages=messages,
                response_format=response_format,
            )
            end_time = datetime.datetime.now()
            logging.info(f"openai vision parse response cost time: {end_time - start_time}")
            return completion.choices[0].message.parsed
        except Exception as e:
            logging.error(f"Failed to generate vision parse response: {str(e)}")
            return None

    
