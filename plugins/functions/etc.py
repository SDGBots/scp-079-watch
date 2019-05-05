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
from pyrogram import Message

# Enable logging
logger = logging.getLogger(__name__)


def bold(text) -> str:
    if text != "":
        return f"**{text}**"

    return ""


def button_data(action: str, action_type: str = None, data: Union[int, str] = None) -> bytes:
    button = {
        "a": action,
        "t": action_type,
        "d": data
    }
    return dumps(button).replace(" ", "").encode("utf-8")


def code(text) -> str:
    if text != "":
        return f"`{text}`"

    return ""


def code_block(text) -> str:
    if text != "":
        return f"```{text}```"

    return ""


def crypt_str(operation: str, text: str, key: str) -> str:
    f = Fernet(key)
    text = text.encode("utf-8")
    if operation == "decrypt":
        result = f.decrypt(text)
    else:
        result = f.encrypt(text)

    result = result.decode("utf-8")

    return result


def delay(secs: int, target: Callable, args: list) -> bool:
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
    command_list = get_text(message).split(" ")
    if len(list(filter(None, command_list))) > 2:
        i = 1
        command_type = command_list[i]
        while command_type == "" and i < len(command_list):
            i += 1
            command_type = command_list[i]

        command_context = get_text(message)[1 + len(command_list[0]) + i + len(command_type):].strip()
    else:
        command_context = ""

    return command_context


def get_text(message: Message) -> str:
    text = ""
    if message.text:
        text += message.text
    elif message.caption:
        text += message.caption

    if message.entities:
        for en in message.entities:
            if en.url:
                text += f"\n{en.url}"
    elif message.caption_entities:
        for en in message.caption_entities:
            if en.url:
                text += f"\n{en.url}"

    return text


def general_link(text: Union[int, str], link: str) -> str:
    return f"[{text}]({link})"


def message_link(cid: int, mid: int) -> str:
    return f"[{mid}](https://t.me/c/{str(cid)[4:]}/{mid})"


def random_str(i: int) -> str:
    return ''.join(choice(ascii_letters + digits) for _ in range(i))


def receive_data(message: Message) -> dict:
    text = get_text(message)
    try:
        assert text is not None, f"Can't get text from message: {message}"
        data = loads(text)
        return data
    except Exception as e:
        logger.warning(f"Receive data error: {e}")

    return {}


def thread(target: Callable, args: tuple) -> bool:
    t = Thread(target=target, args=args)
    t.daemon = True
    t.start()

    return True


def user_mention(uid: int) -> str:
    return f"[{uid}](tg://user?id={uid})"
