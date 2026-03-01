"""消息 content 解析和类型检测。"""

from typing import Any, Dict, Optional

from anp.e2e_encryption_hpke.models import (
    E2eeErrorContent,
    E2eeInitContent,
    E2eeMsgContent,
    GroupE2eeKeyContent,
    GroupE2eeMsgContent,
    GroupEpochAdvanceContent,
    MessageType,
)


def detect_message_type(type_field: str) -> Optional[MessageType]:
    """从 type 字段检测消息类型。

    Args:
        type_field: 消息的 type 字段值。

    Returns:
        对应的 MessageType，未识别则返回 None。
    """
    try:
        return MessageType(type_field)
    except ValueError:
        return None


def parse_e2ee_init(content: Dict[str, Any]) -> E2eeInitContent:
    """解析 e2ee_init / e2ee_rekey 消息 content。"""
    return E2eeInitContent(**content)


def parse_e2ee_msg(content: Dict[str, Any]) -> E2eeMsgContent:
    """解析 e2ee_msg 消息 content。"""
    return E2eeMsgContent(**content)


def parse_e2ee_error(content: Dict[str, Any]) -> E2eeErrorContent:
    """解析 e2ee_error 消息 content。"""
    return E2eeErrorContent(**content)


def parse_group_e2ee_key(content: Dict[str, Any]) -> GroupE2eeKeyContent:
    """解析 group_e2ee_key 消息 content。"""
    return GroupE2eeKeyContent(**content)


def parse_group_e2ee_msg(content: Dict[str, Any]) -> GroupE2eeMsgContent:
    """解析 group_e2ee_msg 消息 content。"""
    return GroupE2eeMsgContent(**content)


def parse_group_epoch_advance(content: Dict[str, Any]) -> GroupEpochAdvanceContent:
    """解析 group_epoch_advance 消息 content。"""
    return GroupEpochAdvanceContent(**content)
