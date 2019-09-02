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
import pickle
from json import loads
from typing import Any

from pyrogram import Client, Message

from .. import glovar
from .channel import get_content
from .etc import crypt_str, get_int, get_text, thread
from .file import crypt_file, delete_file, get_new_path, get_downloaded_path, save
from .ids import init_group_id, init_user_id

# Enable logging
logger = logging.getLogger(__name__)


def receive_add_except(client: Client, data: dict) -> bool:
    # Receive a object and add it to except list
    try:
        the_id = data["id"]
        the_type = data["type"]
        # Receive except channels
        if the_type == "channel":
            glovar.except_ids["channels"].add(the_id)
            save("except_ids")
        # Receive except contents
        elif the_type in {"long", "temp"}:
            content = get_content(client, the_id)
            if content:
                if the_type == "long":
                    glovar.except_ids["long"].add(content)
                elif the_type == "temp":
                    glovar.except_ids["temp"].add(content)

                save("except_ids")

        return True
    except Exception as e:
        logger.warning(f"Receive add except error: {e}", exc_info=True)

    return False


def receive_add_bad(sender: str, data: dict) -> bool:
    # Receive bad users or channels that other bots shared
    try:
        uid = data["id"]
        bad_type = data["type"]
        if bad_type == "user":
            glovar.bad_ids["users"].add(uid)
            save("bad_ids")
        elif sender == "MANAGE" and bad_type == "channel":
            glovar.bad_ids["channels"].add(uid)
            save("bad_ids")

        return True
    except Exception as e:
        logger.warning(f"Receive add bad error: {e}", exc_info=True)

    return False


def receive_file_data(client: Client, message: Message, decrypt: bool = False) -> Any:
    # Receive file's data from exchange channel
    data = None
    try:
        if message.document:
            file_id = message.document.file_id
            path = get_downloaded_path(client, file_id)
            if path:
                if decrypt:
                    # Decrypt the file, save to the tmp directory
                    path_decrypted = get_new_path()
                    crypt_file("decrypt", path, path_decrypted)
                    path_final = path_decrypted
                else:
                    # Read the file directly
                    path_decrypted = ""
                    path_final = path

                with open(path_final, "rb") as f:
                    data = pickle.load(f)

                for f in {path, path_decrypted}:
                    thread(delete_file, (f,))
    except Exception as e:
        logger.warning(f"Receive file error: {e}", exc_info=True)

    return data


def receive_regex(client: Client, message: Message, data: str) -> bool:
    # Receive regex
    try:
        file_name = data
        word_type = file_name.split("_")[0]
        if word_type not in glovar.regex:
            return True

        words_data = receive_file_data(client, message, True)
        if words_data:
            if glovar.locks["regex"].acquire():
                try:
                    pop_set = set(eval(f"glovar.{file_name}")) - set(words_data)
                    new_set = set(words_data) - set(eval(f"glovar.{file_name}"))
                    for word in pop_set:
                        eval(f"glovar.{file_name}").pop(word, 0)

                    for word in new_set:
                        eval(f"glovar.{file_name}")[word] = 0

                    save(file_name)
                except Exception as e:
                    logger.warning(f"Update download regex error: {e}", exc_info=True)
                finally:
                    glovar.locks["regex"].release()

        return True
    except Exception as e:
        logger.warning(f"Receive regex error: {e}", exc_info=True)

    return False


def receive_remove_bad(sender: str, data: dict) -> bool:
    # Receive removed bad objects
    try:
        the_id = data["id"]
        the_type = data["type"]
        if sender == "MANAGE" and the_type == "channel":
            glovar.bad_ids["channels"].discard(the_id)
        elif the_type == "user":
            glovar.bad_ids["users"].discard(the_id)
            glovar.user_ids.pop(the_id, {})
            save("user_ids")

        save("bad_ids")

        return True
    except Exception as e:
        logger.warning(f"Receive remove bad error: {e}", exc_info=True)

    return False


def receive_remove_except(client: Client, data: dict) -> bool:
    # Receive a object and remove it from except list
    try:
        the_id = data["id"]
        the_type = data["type"]
        # Receive except channels
        if the_type == "channel":
            glovar.except_ids["channels"].discard(the_id)
            save("except_ids")
        # Receive except contents
        elif the_type in {"long", "temp"}:
            content = get_content(client, the_id)
            if content:
                if the_type == "long":
                    glovar.except_ids["long"].discard(content)
                elif the_type == "temp":
                    glovar.except_ids["temp"].discard(content)

                save("except_ids")

        return True
    except Exception as e:
        logger.warning(f"Receive remove except error: {e}", exc_info=True)

    return False


def receive_remove_watch(data: dict) -> bool:
    # Receive removed watching users
    try:
        uid = data["id"]
        watch_type = data["type"]
        if watch_type == "all":
            glovar.user_ids.pop(uid, {})
            save("user_ids")

        return True
    except Exception as e:
        logger.warning(f"Receive remove watch error: {e}", exc_info=True)

    return False


def receive_text_data(message: Message) -> dict:
    # Receive text's data from exchange channel
    data = {}
    try:
        text = get_text(message)
        if text:
            data = loads(text)
    except Exception as e:
        logger.warning(f"Receive data error: {e}")

    return data


def receive_declared_message(data: dict) -> bool:
    # Update declared message's id
    try:
        gid = data["group_id"]
        mid = data["message_id"]
        if init_group_id(gid):
            glovar.declared_message_ids[gid].add(mid)
            return True
    except Exception as e:
        logger.warning(f"Receive declared message error: {e}", exc_info=True)

    return False


def receive_watch_user(data: dict) -> bool:
    # Receive watch users that other bots shared
    try:
        watch_type = data["type"]
        uid = data["id"]
        until = data["until"]

        # Decrypt the data
        until = crypt_str("decrypt", until, glovar.key)
        until = get_int(until)

        # Add to list
        if init_user_id(uid):
            glovar.user_ids[uid]["type"] = watch_type
            glovar.user_ids[uid]["until"] = until
            save("user_ids")

        return True
    except Exception as e:
        logger.warning(f"Receive watch user error: {e}", exc_info=True)

    return False
