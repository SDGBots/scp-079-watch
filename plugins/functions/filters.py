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
from time import time
from typing import Union

from pyrogram import Client, Filters, Message

from .. import glovar
from .etc import get_document_filename, get_forward_name, get_text
from .file import delete_file, get_downloaded_path
from .ids import init_user_id
from .image import get_color, get_ocr, get_qrcode
from .telegram import get_preview

# Enable logging
logger = logging.getLogger(__name__)


def is_class_a(_, message: Message) -> bool:
    try:
        cid = message.chat.id
        if cid == glovar.o5_1_id:
            return True
    except Exception as e:
        logger.warning(f"Is class a error: {e}", exc_info=True)

    return False


def is_class_c(_, message: Message) -> bool:
    try:
        uid = message.from_user.id
        if uid in glovar.bot_ids or message.from_user.is_self:
            return True
    except Exception as e:
        logger.warning(f"Is class c error: {e}", exc_info=True)

    return False


def is_class_d(_, message: Message) -> bool:
    try:
        uid = message.from_user.id
        if uid in glovar.bad_ids["users"]:
            return True

        if message.forward_from_chat:
            cid = message.forward_from_chat.id
            if cid in glovar.bad_ids["channels"]:
                return True
    except Exception as e:
        logger.warning(f"Is class d error: {e}", exc_info=True)


def is_class_e(_, message: Message) -> bool:
    try:
        uid = message.from_user.id
        if uid in glovar.except_ids["users"]:
            return True

        if message.forward_from_chat:
            cid = message.forward_from_chat.id
            if cid in glovar.except_ids["channels"]:
                return True
    except Exception as e:
        logger.warning(f"Is class e error: {e}", exc_info=True)

    return False


def is_hide_channel(_, message: Message) -> bool:
    # This message is sent from hide channel
    try:
        cid = message.chat.id
        if cid == glovar.hide_channel_id:
            return True
    except Exception as e:
        logger.warning(f"Is hide channel error: {e}", exc_info=True)

    return False


def is_new_user(_, message: Message) -> bool:
    # This message is sent from a new joined member in last glovar.time_new hours
    try:
        uid = message.from_user.id
        for i in range(glovar.time_new):
            if uid in glovar.new_user_ids[i]:
                return True
    except Exception as e:
        logger.warning(f"Is new user error: {e}", exc_info=True)

    return False


def is_watch_ban(_, message: Message) -> bool:
    try:
        uid = message.from_user.id
        status = glovar.watch_ids["ban"].get(uid, 0)
        now = int(time())
        if now - status < glovar.time_ban:
            return True
    except Exception as e:
        logger.warning(f"Is watch ban error: {e}", exc_info=True)

    return False


def is_watch_delete(_, message: Message) -> bool:
    try:
        uid = message.from_user.id
        status = glovar.watch_ids["delete"].get(uid, 0)
        now = int(time())
        if now - status < glovar.time_delete:
            return True
    except Exception as e:
        logger.warning(f"Is watch delete error: {e}", exc_info=True)

    return False


class_a = Filters.create(
    name="Class A",
    func=is_class_a
)

class_c = Filters.create(
    name="Class C",
    func=is_class_c
)

class_d = Filters.create(
    name="Class D",
    func=is_class_d
)

class_e = Filters.create(
    name="Class E",
    func=is_class_e
)

hide_channel = Filters.create(
    name="Hide Channel",
    func=is_hide_channel
)

new_user = Filters.create(
    name="New User",
    func=is_new_user
)

watch_ban = Filters.create(
    name="Watch Ban",
    func=is_watch_ban
)

watch_delete = Filters.create(
    name="Watch Delete",
    func=is_watch_delete
)


def is_ban_text(text: str) -> bool:
    try:
        if (glovar.compiled["ban"].search(text)
                or (glovar.compiled["ad"].search(text) and glovar.compiled["con"].search(text))):
            return True
    except Exception as e:
        logger.warning(f"Is ban text error: {e}", exc_info=True)

    return False


def is_ban_name_text(text: str) -> bool:
    try:
        if (glovar.compiled["ban"].search(text)
                or (glovar.compiled["ad"].search(text) and glovar.compiled["con"].search(text))
                or glovar.compiled["nm"].search(text)
                or glovar.compiled["bio"].search(text)):
            return True
    except Exception as e:
        logger.warning(f"Is ban name text error: {e}", exc_info=True)

    return False


def is_restricted_channel(message: Message) -> bool:
    # Check if the message is forwarded form restricted channel
    try:
        if message.forward_from_chat:
            if message.forward_from_chat.restriction_reason:
                return True
    except Exception as e:
        logger.warning(f"Is restricted channel error: {e}", exc_info=True)

    return False


def is_watch_message(client: Client, message: Message) -> Union[bool, str]:
    need_delete = {}
    try:
        gid = message.chat.id
        uid = message.from_user.id
        init_user_id(uid)

        # Start detect watch ban

        # Check whether the user already recorded in this group
        if gid in glovar.user_ids[uid]["ban"]:
            return False

        # Search the message's text
        # Ensure that the text will not directly trigger the ban rule
        message_text = get_text(message)
        if message_text:
            if is_ban_text(message_text):
                return False

            if glovar.compiled["wb"].search(message_text):
                return "ban"

        # Search name and text

        # Search the forward name:
        forward_name = get_forward_name(message)
        if forward_name:
            if is_ban_name_text(forward_name):
                return False

            if glovar.compiled["wb"].search(forward_name):
                return "ban"

        # Search the document filename:
        file_name = get_document_filename(message)
        if file_name:
            if is_ban_text(file_name):
                return False

            if glovar.compiled["wb"].search(file_name):
                return "ban"

        # Search image

        # Search preview
        preview = get_preview(client, message)
        if preview["text"]:
            if is_ban_text(preview["text"]):
                return False

            if glovar.compiled["wb"].search(preview["text"]):
                return "ban"

        if preview["file_id"]:
            preview["image_path"] = get_downloaded_path(client, preview["file_id"])
            if preview["image_path"]:
                need_delete["preview"] = preview["image_path"]
                preview["ocr"] = get_ocr(preview["image_path"])
                if preview["ocr"]:
                    if is_ban_text(preview["ocr"]):
                        return False

                    if glovar.compiled["wb"].search(preview["ocr"]):
                        return "ban"

                preview["qrcode"] = get_qrcode(preview["image_path"])
                if preview["qrcode"]:
                    if is_ban_text(preview["qrcode"]):
                        return False

                    if glovar.compiled["wb"].search(preview["qrcode"]):
                        return "ban"

        # Start detect watch delete
        # Check if the user is already in watch delete
        if not is_watch_delete(None, message):
            return False

        if gid in glovar.user_ids[uid]["delete"]:
            return False

        # Some media type
        if (message.animation
                or message.audio
                or message.document
                or message.game
                or message.location
                or message.venue
                or message.via_bot
                or message.video
                or message.video_note):
            return "delete"

        # Check the message's text
        if message_text:
            if glovar.compiled["wd"].search(message_text):
                return "delete"

        # Search preview
        if preview["text"]:
            if glovar.compiled["wd"].search(preview["text"]):
                return "delete"

        if preview["file_id"]:
            if preview["image_path"]:
                if preview["ocr"]:
                    if glovar.compiled["wd"].search(preview["ocr"]):
                        return "delete"

                if preview["qrcode"]:
                    if glovar.compiled["wd"].search(preview["qrcode"]):
                        return "delete"

                if get_color(preview["image_path"]):
                    return "delete"

        # Search image
    except Exception as e:
        logger.warning(f"Is watch message error: {e}", exc_info=True)
    finally:
        for file_type in need_delete:
            delete_file(need_delete[file_type])

    return False
