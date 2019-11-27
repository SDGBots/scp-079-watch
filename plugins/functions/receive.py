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
from copy import deepcopy
from json import loads
from typing import Any

from pyrogram import Client, Message

from .. import glovar
from .channel import get_content, send_help, share_data
from .etc import code, crypt_str, general_link, get_int, get_now, get_report_record, get_text, lang, mention_id, thread
from .file import crypt_file, data_to_file, delete_file, get_new_path, get_downloaded_path, save
from .group import get_message
from .ids import init_group_id, init_user_id

# Enable logging
logger = logging.getLogger(__name__)


def receive_add_bad(sender: str, data: dict) -> bool:
    # Receive bad users or channels that other bots shared
    try:
        # Basic data
        the_id = data["id"]
        the_type = data["type"]

        # Receive bad channel
        if sender == "MANAGE" and the_type == "channel":
            glovar.bad_ids["channels"].add(the_id)

        # Receive bad user
        if the_type == "user":
            glovar.bad_ids["users"].add(the_id)

        save("bad_ids")

        return True
    except Exception as e:
        logger.warning(f"Receive add bad error: {e}", exc_info=True)

    return False


def receive_add_except(client: Client, data: dict) -> bool:
    # Receive a object and add it to except list
    try:
        # Basic data
        the_id = data["id"]
        the_type = data["type"]

        # Receive except channel
        if the_type == "channel":
            glovar.except_ids["channels"].add(the_id)

        # Receive except content
        if the_type in {"long", "temp"}:
            message = get_message(client, glovar.watch_channel_id, the_id)
            if not message:
                return True

            record = get_report_record(message)
            if lang("name") in record["rule"]:
                if record["name"]:
                    glovar.except_ids["long"].add(record["name"])

                if record["from"]:
                    glovar.except_ids["long"].add(record["from"])

            if message.reply_to_message:
                message = message.reply_to_message
            else:
                return True

            if message.sticker and record["more"]:
                glovar.except_ids["long"].add(record["more"])

            content = get_content(message)
            if content:
                glovar.except_ids[the_type].add(content)

        save("except_ids")

        return True
    except Exception as e:
        logger.warning(f"Receive add except error: {e}", exc_info=True)

    return False


def receive_clear_data(client: Client, data_type: str, data: dict) -> bool:
    # Receive clear data command
    glovar.locks["message"].acquire()
    try:
        # Basic data
        aid = data["admin_id"]
        the_type = data["type"]

        # Clear bad data
        if data_type == "bad":
            if the_type == "channels":
                glovar.bad_ids["channels"] = set()
            elif the_type == "users":
                glovar.bad_ids["users"] = set()

            save("bad_ids")

        # Clear except data
        if data_type == "except":
            if the_type == "channels":
                glovar.except_ids["channels"] = set()
            elif the_type == "long":
                glovar.except_ids["long"] = set()
            elif the_type == "temp":
                glovar.except_ids["temp"] = set()

            save("except_ids")

        # Clear user data
        if data_type == "user":
            if the_type == "all":
                glovar.user_ids = {}
            elif the_type == "new":
                for uid in list(glovar.user_ids):
                    glovar.user_ids[uid]["join"] = 0

            save("user_ids")

        # Clear watch data
        if data_type == "watch":
            if the_type == "all":
                for uid in list(glovar.user_ids):
                    glovar.user_ids[uid]["type"] = ""
                    glovar.user_ids[uid]["ban"] = {}
                    glovar.user_ids[uid]["delete"] = {}
            elif the_type == "ban":
                for uid in list(glovar.user_ids):
                    glovar.user_ids[uid]["type"] = ""
                    glovar.user_ids[uid]["ban"] = {}
            elif the_type == "delete":
                for uid in list(glovar.user_ids):
                    glovar.user_ids[uid]["type"] = ""
                    glovar.user_ids[uid]["delete"] = {}

            save("user_ids")

        # Send debug message
        text = (f"{lang('project')}{lang('colon')}{general_link(glovar.project_name, glovar.project_link)}\n"
                f"{lang('admin_project')}{lang('colon')}{mention_id(aid)}\n"
                f"{lang('action')}{lang('colon')}{code(lang('clear'))}\n"
                f"{lang('more')}{lang('colon')}{code(f'{data_type} {the_type}')}\n")
        thread(send_help, (client, glovar.debug_channel_id, text))
    except Exception as e:
        logger.warning(f"Receive clear data: {e}", exc_info=True)
    finally:
        glovar.locks["message"].release()

    return False


def receive_declared_message(data: dict) -> bool:
    # Update declared message's id
    try:
        # Basic data
        gid = data["group_id"]
        mid = data["message_id"]

        if init_group_id(gid):
            glovar.declared_message_ids[gid].add(mid)

        return True
    except Exception as e:
        logger.warning(f"Receive declared message error: {e}", exc_info=True)

    return False


def receive_file_data(client: Client, message: Message, decrypt: bool = True) -> Any:
    # Receive file's data from exchange channel
    data = None
    try:
        if not message.document:
            return None

        file_id = message.document.file_id
        file_ref = message.document.file_ref
        path = get_downloaded_path(client, file_id, file_ref)

        if not path:
            return None

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
    glovar.locks["regex"].acquire()
    try:
        file_name = data
        word_type = file_name.split("_")[0]
        if word_type not in glovar.regex:
            return True

        words_data = receive_file_data(client, message)
        if not words_data:
            return True

        pop_set = set(eval(f"glovar.{file_name}")) - set(words_data)
        new_set = set(words_data) - set(eval(f"glovar.{file_name}"))
        for word in pop_set:
            eval(f"glovar.{file_name}").pop(word, 0)

        for word in new_set:
            eval(f"glovar.{file_name}")[word] = 0

        save(file_name)

        # Regenerate special characters dictionary if possible
        if file_name in {"spc_words", "spe_words"}:
            special = file_name.split("_")[0]
            exec(f"glovar.{special}_dict = {{}}")
            for rule in words_data:
                # Check keys
                if "[" not in rule:
                    continue

                # Check value
                if "?#" not in rule:
                    continue

                keys = rule.split("]")[0][1:]
                value = rule.split("?#")[1][1]
                for k in keys:
                    eval(f"glovar.{special}_dict")[k] = value

        return True
    except Exception as e:
        logger.warning(f"Receive regex error: {e}", exc_info=True)
    finally:
        glovar.locks["regex"].release()

    return False


def receive_remove_bad(data: dict) -> bool:
    # Receive removed bad objects
    try:
        # Basic data
        the_id = data["id"]
        the_type = data["type"]

        # Remove bad channel
        if the_type == "channel":
            glovar.bad_ids["channels"].discard(the_id)

        # Remove bad user
        if the_type == "user":
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
        # Basic data
        the_id = data["id"]
        the_type = data["type"]

        # Receive except channel
        if the_type == "channel":
            glovar.except_ids["channels"].discard(the_id)

        # Receive except content
        if the_type in {"long", "temp"}:
            message = get_message(client, glovar.watch_channel_id, the_id)
            if not message:
                return True

            record = get_report_record(message)
            if lang("name") in record["rule"]:
                if record["name"]:
                    glovar.except_ids["long"].discard(record["name"])

                if record["from"]:
                    glovar.except_ids["long"].discard(record["from"])

            if message.reply_to_message:
                message = message.reply_to_message
            else:
                return True

            if message.sticker and record["more"]:
                glovar.except_ids["long"].discard(record["more"])

            content = get_content(message)
            if content:
                glovar.except_ids[the_type].discard(content)

        save("except_ids")

        return True
    except Exception as e:
        logger.warning(f"Receive remove except error: {e}", exc_info=True)

    return False


def receive_remove_watch(data: dict) -> bool:
    # Receive removed watching users
    try:
        # Basic data
        uid = data["id"]
        the_type = data["type"]

        if the_type == "all":
            glovar.user_ids.pop(uid, {})

        save("user_ids")

        return True
    except Exception as e:
        logger.warning(f"Receive remove watch error: {e}", exc_info=True)

    return False


def receive_rollback(client: Client, message: Message, data: dict) -> bool:
    # Receive rollback data
    try:
        # Basic data
        aid = data["admin_id"]
        the_type = data["type"]
        the_data = receive_file_data(client, message)

        if not the_data:
            return True

        exec(f"glovar.{the_type} = the_data")
        save(the_type)

        # Send debug message
        text = (f"{lang('project')}{lang('colon')}{general_link(glovar.project_name, glovar.project_link)}\n"
                f"{lang('admin_project')}{lang('colon')}{mention_id(aid)}\n"
                f"{lang('action')}{lang('colon')}{code(lang('rollback'))}\n"
                f"{lang('more')}{lang('colon')}{code(the_type)}\n")
        thread(send_help, (client, glovar.debug_channel_id, text))
    except Exception as e:
        logger.warning(f"Receive rollback error: {e}", exc_info=True)

    return False


def receive_status_ask(client: Client, data: dict) -> bool:
    # Receive version info request
    try:
        # Basic data
        aid = data["admin_id"]
        mid = data["message_id"]
        now = get_now()

        new_count = 0
        ban_count = 0
        delete_count = 0
        pending_ban_count = 0
        pending_delete_count = 0
        user_ids = deepcopy(glovar.user_ids)

        for uid in user_ids:
            if now - user_ids[uid]["join"] < glovar.time_new:
                new_count += 1

            if user_ids[uid]["type"] == "ban" and now < user_ids[uid]["until"]:
                ban_count += 1

            if user_ids[uid]["type"] == "delete" and now < user_ids[uid]["until"]:
                delete_count += 1

            if now - user_ids[uid]["join"] < glovar.time_new and user_ids[uid]["ban"]:
                pending_ban_count += 1

            if now - user_ids[uid]["join"] < glovar.time_new and user_ids[uid]["delete"]:
                pending_delete_count += 1

        status = {
            lang("new_user"): f"{new_count} {lang('members')}",
            lang("suggest_ban"): f"{ban_count} {lang('members')}",
            lang("suggest_delete"): f"{delete_count} {lang('members')}",
            lang("track_ban"): f"{pending_ban_count} {lang('members')}",
            lang("track_delete"): f"{pending_delete_count} {lang('members')}"
        }
        file = data_to_file(status)
        share_data(
            client=client,
            receivers=["MANAGE"],
            action="status",
            action_type="reply",
            data={
                "admin_id": aid,
                "message_id": mid
            },
            file=file
        )

        return True
    except Exception as e:
        logger.warning(f"Receive version ask error: {e}", exc_info=True)

    return False


def receive_text_data(message: Message) -> dict:
    # Receive text's data from exchange channel
    data = {}
    try:
        text = get_text(message)

        if not text:
            return {}

        data = loads(text)
    except Exception as e:
        logger.warning(f"Receive text data error: {e}")

    return data


def receive_version_ask(client: Client, data: dict) -> bool:
    # Receive version info request
    try:
        # Basic data
        aid = data["admin_id"]
        mid = data["message_id"]

        share_data(
            client=client,
            receivers=["HIDE"],
            action="version",
            action_type="reply",
            data={
                "admin_id": aid,
                "message_id": mid,
                "version": glovar.version
            }
        )

        return True
    except Exception as e:
        logger.warning(f"Receive version ask error: {e}", exc_info=True)

    return False


def receive_watch_user(data: dict) -> bool:
    # Receive watch users that other bots shared
    try:
        # Basic data
        the_type = data["type"]
        uid = data["id"]
        until = data["until"]

        if not init_user_id(uid):
            return True

        # Decrypt the data
        until = crypt_str("decrypt", until, glovar.key)
        until = get_int(until)

        # Add to list
        glovar.user_ids[uid]["type"] = the_type
        glovar.user_ids[uid]["until"] = until
        save("user_ids")

        return True
    except Exception as e:
        logger.warning(f"Receive watch user error: {e}", exc_info=True)

    return False
