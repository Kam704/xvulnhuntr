import logging
import os
import re
import time
from types import SimpleNamespace
from typing import Any, Dict, List, Union
from unittest.mock import patch

import anthropic
import dotenv
import httpx
import openai
from anthropic import DefaultHttpxClient
from pydantic import BaseModel, ValidationError

from vulnhuntr.mocks import *
from vulnhuntr.utils import write_response

dotenv.load_dotenv()

log = logging.getLogger(__name__)
logger = logging.getLogger("xvulnhuntr")

class LLMError(Exception):
    """Base class for all LLM-related exceptions."""
    pass

class RateLimitError(LLMError):
    pass

class APIConnectionError(LLMError):
    pass

class APIStatusError(LLMError):
    def __init__(self, status_code: int, response: Dict[str, Any]):
        self.status_code = status_code
        self.response = response
        super().__init__(f"Received non-200 status code: {status_code}")

# Base LLM class to handle common functionality
class LLM:
    def __init__(self, system_prompt: str = "", mock: bool = False) -> None:
        self.system_prompt = system_prompt
        self.mock = mock
        self.history: List[Dict[str, str]] = []
        self.prev_prompt: Union[str, None] = None
        self.prev_response: Union[str, None] = None
        self.prefill = None

    def _validate_response(self, response_text: str, response_model: BaseModel) -> BaseModel:
        try:
            if self.prefill:
                response_text = self.prefill + response_text
            # ugly hack but if '\' is returned by the model it cannot be parsed as valid json
            # however, existing \" must be left untouched
            response_text = re.sub(r'(\\")|\\', lambda m: m.group(1) if m.group(1) else '\\\\', response_text)
            return response_model.model_validate_json(response_text)
        except ValidationError as e:
            log.warning("[-] Response validation failed\n", exc_info=e)
            logger.debug(response_text)
            raise LLMError("Validation failed") from e

    def _add_to_history(self, role: str, content: str) -> None:
        self.history.append({"role": role, "content": content})

    def _handle_error(self, e: Exception, attempt: int) -> None:
        log.error(f"An error occurred on attempt {attempt}: {str(e)}", exc_info=e)
        raise e
    
    def _log_response(self, response: Dict[str, Any]) -> None:
        usage_info = response.usage.__dict__
        log.debug("Received chat response", extra={"usage": usage_info})

    def chat(self, user_prompt: str, step: str, config: dict, file_iteration_counter: int = -1, vulnerability_type: VulnType = None, iteration: int = -1, response_model: BaseModel = None, max_tokens: int = 4096) -> Union[BaseModel, str]:
        self._add_to_history("user", user_prompt)
        messages = self.create_messages(user_prompt)
        response = self.send_message(messages=messages,
                                     max_tokens=max_tokens,
                                     response_model=response_model,
                                     step=step,
                                     vulnerability_type=vulnerability_type,
                                     iteration=iteration,
                                     config=config,
                                     file_iteration_counter=file_iteration_counter)
        self._log_response(response)

        response_text = self.get_response(response)
        write_response(config=config, response=response_text, vulnerability_type=vulnerability_type)
        if response_model:
            response_text = self._validate_response(response_text, response_model) if response_model else response_text
        self._add_to_history("assistant", response_text)
        return response_text

class Claude(LLM):
    def __init__(self, model: str, base_url: str, config: dict, system_prompt: str = "") -> None:
        super().__init__(system_prompt=system_prompt, mock=config["test"])
        # API key is retrieved from an environment variable by default
        proxy = config.get("proxy", False)
        cert_ca = config.get("certificate", False)
        if proxy:
            self.client = anthropic.Anthropic(max_retries=3, base_url=base_url, http_client=DefaultHttpxClient(proxy=proxy, verify=cert_ca, transport=httpx.HTTPTransport(local_address="0.0.0.0"),
            ))
        else:
            self.client = anthropic.Anthropic(max_retries=3, base_url=base_url)
        self.model = model

    def create_messages(self, user_prompt: str) -> List[Dict[str, str]]:
        if "Provide a very concise summary of the README.md content" in user_prompt:
            messages = [{"role": "user", "content": user_prompt}]
        else:
            self.prefill = "{    \"scratchpad\": \"1."
            messages = [{"role": "user", "content": user_prompt}, 
                        {"role": "assistant", "content": self.prefill}]
        return messages

    def send_message(self, messages: List[Dict[str, str]], max_tokens: int, response_model: BaseModel, step: str, vulnerability_type: VulnType, iteration: int,config: Dict, file_iteration_counter: int = -1) -> Dict[str, Any]:
        for attempt in range(config["retries"]):
            try:
                if self.mock:
                    if step == PromptStep.SUMMARY:
                        mock_text = config["mock"][step]
                    elif step == PromptStep.INITIAL_ANALYSIS:
                        mock_text = config["mock"][step][file_iteration_counter]
                    elif step == PromptStep.SECONDARY_ANALYSIS:
                        mock_text = config["mock"][step][vulnerability_type][iteration]

                    mock_response  = anthropic.types.Message(
                        id="mocked-response",
                        type="message",
                        role="assistant",
                        content=[anthropic.types.TextBlock(type="text", text=f"{mock_text}")],
                        model="claude-3-sonnet-20240229",
                        stop_reason="end_turn",
                        usage=anthropic.types.Usage(input_tokens=10, output_tokens=10),
                    )
                        
                    with patch.object(self.client.messages, "create", return_value=mock_response):
                        return self.client.messages.create(
                            model=self.model,
                            max_tokens=max_tokens,
                            system=self.system_prompt,
                            messages=messages
                        )
                else:
                    # response_model is not used here, only in ChatGPT
                    return self.client.messages.create(
                        model=self.model,
                        max_tokens=max_tokens,
                        system=self.system_prompt,
                        messages=messages
                    )
            except anthropic.APIConnectionError as e:
                raise APIConnectionError("Server could not be reached") from e
            except anthropic.RateLimitError as e:
                # increase delay at each attempt
                # better to wait than lose the execution (currently no restore point to resume from)
                delay = attempt*config["sleep_between_retries"]
                logger.info(f"Got an exception, wait for {delay} seconds before next API call")
                time.sleep(delay)
                raise RateLimitError("Request was rate-limited") from e
            except anthropic.APIStatusError as e:
                delay = attempt*config["sleep_between_retries"]
                logger.info(f"Got an exception, wait for {delay} seconds before next API call")
                time.sleep(delay)
                raise APIStatusError(e.status_code, e.response) from e

    def get_response(self, response: Dict[str, Any]) -> str:
        return response.content[0].text.replace('\n', '')


class ChatGPT(LLM):
    def __init__(self, model: str, base_url: str, config: dict, system_prompt: str = "") -> None:
        super().__init__(system_prompt=system_prompt, mock=config["test"])
        proxy = config.get("proxy", False)
        cert_ca = config.get("certificate", False)
        if proxy:
            self.client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"), base_url=base_url,http_client=DefaultHttpxClient(proxy=proxy, verify=cert_ca, transport=httpx.HTTPTransport(local_address="0.0.0.0"),))
        else:
            self.client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"), base_url=base_url)
        self.model = model

    def create_messages(self, user_prompt: str) -> List[Dict[str, str]]:
        messages = [{"role": "system", "content": self.system_prompt}, 
                    {"role": "user", "content": user_prompt}]
        return messages

    def send_message(self, messages: List[Dict[str, str]], max_tokens: int, step: str, vulnerability_type: VulnType, iteration: int,config: Dict, response_model=None, file_iteration_counter: int = -1) -> Dict[str, Any]:
        for attempt in range(config["retries"]):
            try:
                params = {
                    "model": self.model,
                    "messages": messages,
                    "max_tokens": max_tokens,
                }

                # Add response format configuration if a model is provided
                if response_model:
                    params["response_format"] = {
                        "type": "json_object"
                    }

                if self.mock:
                    # the mocked responses from Claude are used also when mocking ChatGPT
                    self.prefill = "{    \"scratchpad\": \"1."
                    mock_text = ""
                    if step == PromptStep.SUMMARY:
                        mock_text = config["mock"][step]
                    elif step == PromptStep.INITIAL_ANALYSIS:
                        mock_text = config["mock"][step][file_iteration_counter]
                    elif step == PromptStep.SECONDARY_ANALYSIS:
                        mock_text = config["mock"][step][vulnerability_type][iteration]

                    mock_response = SimpleNamespace(
                        id="chatcmpl-mock123",
                        object="chat.completion",
                        created=1711000000,
                        model="gpt-4",
                        choices=[
                            SimpleNamespace(
                                index=0,
                                message=SimpleNamespace(
                                    role="assistant",
                                    content=mock_text
                                ),
                                finish_reason="stop"
                            )
                        ],
                        usage=SimpleNamespace(
                            prompt_tokens=10,
                            completion_tokens=5,
                            total_tokens=15
                        )
                    )
                    with patch("openai.resources.chat.completions.Completions.create", return_value=mock_response):
                        return self.client.chat.completions.create(**params)
                else:
                    return self.client.chat.completions.create(**params)

            except openai.APIConnectionError as e:
                raise APIConnectionError("The server could not be reached") from e
            except openai.RateLimitError as e:
                raise RateLimitError("Request was rate-limited; consider backing off") from e
            except openai.APIStatusError as e:
                raise APIStatusError(e.status_code, e.response) from e
            except Exception as e:
                raise LLMError(f"An unexpected error occurred: {str(e)}") from e

    def get_response(self, response: Dict[str, Any]) -> str:
        response = response.choices[0].message.content
        return response

def initialize_llm(config:dict, system_prompt: str = "") -> Claude | ChatGPT:
    llm_arg = config["llm"]
    llm_arg = llm_arg.lower()
    if llm_arg == 'claude':
        anth_model = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-latest")
        anth_base_url = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com")
        llm = Claude(model=anth_model, base_url=anth_base_url, system_prompt=system_prompt, config=config)
    elif llm_arg == 'gpt':
        openai_model = os.getenv("OPENAI_MODEL", "gpt-4o")
        openai_base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        llm = ChatGPT(model=openai_model, base_url=openai_base_url, system_prompt=system_prompt, config=config)
    else:
        raise ValueError(f"Invalid LLM argument: {llm_arg}\nValid options are: claude, gpt")
    return llm