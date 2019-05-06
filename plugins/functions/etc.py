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
from json import dumps, loads
from random import choice
from string import ascii_letters, digits
from threading import Thread, Timer
from typing import Callable, List, Union

from cryptography.fernet import Fernet
from opencc import convert
from pyrogram import Message, User

# Enable logging
logger = logging.getLogger(__name__)


def bold(text) -> str:
    # Get a bold text
    if text:
        return f"**{text}**"

    return ""


def button_data(action: str, action_type: str = None, data: Union[int, str] = None) -> bytes:
    # Get a button's bytes data
    button = {
        "a": action,
        "t": action_type,
        "d": data
    }
    return dumps(button).replace(" ", "").encode("utf-8")


def code(text) -> str:
    # Get a code text
    if text:
        return f"`{text}`"

    return ""


def code_block(text) -> str:
    # Get a code block text
    if text:
        return f"```{text}```"

    return ""


def crypt_str(operation: str, text: str, key: str) -> str:
    # Encrypt or decrypt a string
    f = Fernet(key)
    text = text.encode("utf-8")
    if operation == "decrypt":
        result = f.decrypt(text)
    else:
        result = f.encrypt(text)

    result = result.decode("utf-8")

    return result


def delay(secs: int, target: Callable, args: list) -> bool:
    # Call a function with delay
    t = Timer(secs, target, args)
    t.daemon = True
    t.start()

    return True


def format_data(sender: str, receivers: List[str], action: str, action_type: str, data=None) -> str:
    # See https://scp-079.org/exchange/
    data = {
        "from": sender,
        "to": receivers,
        "action": action,
        "type": action_type,
        "data": data
    }

    return code_block(dumps(data, indent=4))


def get_command_context(message: Message) -> str:
    # Get the context "b" in "/command a b"
    text = get_text(message)
    command_list = text.split(" ")
    if len(list(filter(None, command_list))) > 2:
        i = 1
        command_type = command_list[i]
        while command_type == "" and i < len(command_list):
            i += 1
            command_type = command_list[i]

        command_context = text[1 + len(command_list[0]) + i + len(command_type):].strip()
    else:
        command_context = ""

    return command_context


def get_document_filename(message: Message) -> str:
    # Get document's filename
    text = ""
    try:
        if message.document:
            if message.document.file_name:
                text = message.document.file_name

        if text:
            text = t2s(text)
    except Exception as e:
        logger.warning(f"Get document filename error: {e}", exc_info=True)

    return text


def get_forward_name(message: Message) -> str:
    # Get forwarded message's origin sender's name
    text = ""
    try:
        if message.forward_from:
            user = message.forward_from
            text = get_full_name(user)
        elif message.forward_from_name:
            text = message.forward_from_name
        elif message.forward_from_chat:
            chat = message.forward_from_chat
            text = chat.title

        if text:
            text = t2s(text)
    except Exception as e:
        logger.warning(f"Get forward name error: {e}", exc_info=True)

    return text


def get_full_name(user: User) -> str:
    # Get user's full name
    text = ""
    try:
        if user and not user.is_deleted:
            text = user.first_name
            if user.last_name:
                text += f" {user.last_name}"

        if text:
            text = t2s(text)
    except Exception as e:
        logger.warning(f"Get full name error: {e}", exc_info=True)

    return text


def get_text(message: Message) -> str:
    # Get message's text, including link and mentioned user's name
    text = ""
    try:
        if message.text or message.caption:
            if message.text:
                text += message.text
            else:
                text += message.caption

            if message.entities or message.caption_entities:
                if message.entities:
                    entities = message.entities
                else:
                    entities = message.caption_entities

                for en in entities:
                    if en.url:
                        text += f"\n{en.url}"

                    if en.user:
                        text += f"\n{get_full_name(en.user)}"

        if text:
            text = t2s(text)
    except Exception as e:
        logger.warning(f"Get text error: {e}", exc_info=True)

    return text


def general_link(text: Union[int, str], link: str) -> str:
    # Get a markdown link
    return f"[{text}]({link})"


def message_link(cid: int, mid: int) -> str:
    # Get a message's link in a channel
    return f"[{mid}](https://t.me/c/{str(cid)[4:]}/{mid})"


def random_str(i: int) -> str:
    # Get a random string
    return ''.join(choice(ascii_letters + digits) for _ in range(i))


def receive_data(message: Message) -> dict:
    # Receive data from exchange channel
    text = get_text(message)
    try:
        assert text is not "", f"Can't get text from message: {message}"
        data = loads(text)
        return data
    except Exception as e:
        logger.warning(f"Receive data error: {e}")

    return {}


def t2s(text: str) -> str:
    # Covert Traditional Chinese to Simplified Chinese
    return convert(text, config="t2s.json")


def thread(target: Callable, args: tuple) -> bool:
    # Call a function using thread
    t = Thread(target=target, args=args)
    t.daemon = True
    t.start()

    return True


def user_mention(uid: int) -> str:
    # Get a mention text
    return f"[{uid}](tg://user?id={uid})"
