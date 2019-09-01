# SCP-079-WATCH - Observe and track suspicious spam behaviors
# Copyright (C) 2019 SCP-079 <https://scp-079.org>
#
# This file is part of SCP-079-WATCH.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging
from json import dumps
from typing import List, Optional, Union

from pyrogram import Client, Message
from pyrogram.errors import FloodWait

from .. import glovar
from .etc import code, code_block, get_md5sum, get_text, thread, wait_flood
from .file import crypt_file, data_to_file, delete_file, get_new_path
from .group import get_message
from .image import get_file_id
from .telegram import send_document, send_message

# Enable logging
logger = logging.getLogger(__name__)


def format_data(sender: str, receivers: List[str], action: str, action_type: str,
                data: Union[bool, dict, int, str] = None) -> str:
    # See https://scp-079.org/exchange/
    text = ""
    try:
        data = {
            "from": sender,
            "to": receivers,
            "action": action,
            "type": action_type,
            "data": data
        }
        text = code_block(dumps(data, indent=4))
    except Exception as e:
        logger.warning(f"Format data error: {e}", exc_info=True)

    return text


def forward_evidence(client: Client, message: Message, level: str,
                     more: str = None) -> Optional[Union[bool, Message]]:
    # Forward the message to the watch channel as evidence
    result = None
    try:
        uid = message.from_user.id
        text = (f"项目编号：{code(glovar.sender)}\n"
                f"用户 ID：{code(uid)}\n"
                f"操作等级：{code(level)}\n"
                f"规则：{code('全局规则')}\n")

        if message.contact or message.location or message.venue or message.video_note or message.voice:
            text += f"附加信息：{code('可能涉及隐私而未转发')}\n"
        elif message.game:
            text += f"附加信息：{code('此类消息无法转发至频道')}\n"
        elif more:
            text += f"附加信息：{code(more)}\n"

        # DO NOT try to forward these types of message
        if message.contact or message.location or message.venue or message.video_note or message.voice or message.game:
            result = send_message(client, glovar.watch_channel_id, text)
            return result

        flood_wait = True
        while flood_wait:
            flood_wait = False
            try:
                result = message.forward(
                    chat_id=glovar.watch_channel_id,
                    disable_notification=True
                )
            except FloodWait as e:
                flood_wait = True
                wait_flood(e)
            except Exception as e:
                logger.info(f"Forward evidence message error: {e}", exc_info=True)
                return False

        result = result.message_id
        result = send_message(client, glovar.watch_channel_id, text, result)
    except Exception as e:
        logger.warning(f"Forward evidence error: {e}", exc_info=True)

    return result


def get_content(client: Optional[Client], mid: Union[int, Message]) -> str:
    # Get the message that will be added to except_ids, return the file_id or text's hash
    result = ""
    try:
        if client and isinstance(mid, int):
            message = get_message(client, glovar.watch_channel_id, mid)
            if message:
                message = message.reply_to_message
        else:
            message = mid

        if message:
            file_id = get_file_id(message)
            text = get_text(message)
            if file_id:
                result += file_id
            elif text:
                result += get_md5sum("string", text)
    except Exception as e:
        logger.warning(f"Get content error: {e}", exc_info=True)

    return result


def share_data(client: Client, receivers: List[str], action: str, action_type: str, data: Union[bool, dict, int, str],
               file: str = None, encrypt: bool = True) -> bool:
    # Use this function to share data in the exchange channel
    try:
        if glovar.sender in receivers:
            receivers.remove(glovar.sender)

        if receivers:
            channel_id = glovar.hide_channel_id
            if file:
                text = format_data(
                    sender=glovar.sender,
                    receivers=receivers,
                    action=action,
                    action_type=action_type,
                    data=data
                )
                if encrypt:
                    # Encrypt the file, save to the tmp directory
                    file_path = get_new_path()
                    crypt_file("encrypt", file, file_path)
                else:
                    # Send directly
                    file_path = file

                result = send_document(client, channel_id, file_path, text)
                # Delete the tmp file
                if result:
                    for f in {file, file_path}:
                        if "tmp/" in f:
                            thread(delete_file, (f,))
            else:
                text = format_data(
                    sender=glovar.sender,
                    receivers=receivers,
                    action=action,
                    action_type=action_type,
                    data=data
                )
                result = send_message(client, channel_id, text)

            if result is False:
                return True

        return True
    except Exception as e:
        logger.warning(f"Share data error: {e}", exc_info=True)

    return False


def share_regex_count(client: Client, word_type: str) -> bool:
    # Use this function to share regex count to REGEX
    try:
        if glovar.regex[word_type]:
            file = data_to_file(eval(f"glovar.{word_type}_words"))
            share_data(
                client=client,
                receivers=["REGEX"],
                action="update",
                action_type="count",
                data=f"{word_type}_words",
                file=file
            )

        return True
    except Exception as e:
        logger.warning(f"Share regex update error: {e}", exc_info=True)

    return False


def share_watch_user(client: Client, the_type: str, uid: int, until: str) -> bool:
    # Share a watch ban user with other bots
    try:
        share_data(
            client=client,
            receivers=glovar.receivers["watch"],
            action="add",
            action_type="watch",
            data={
                "id": uid,
                "type": the_type,
                "until": until
            }
        )

        return True
    except Exception as e:
        logger.warning(f"Share watch user error: {e}", exc_info=True)
