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
import re

from pyrogram import Client, Filters, Message, WebPage

from .. import glovar
from .channel import get_content
from .etc import get_channel_link, get_document_filename, get_entity_text, get_forward_name, get_now
from .etc import get_links, get_stripped_link, get_text
from .file import delete_file, get_downloaded_path, save
from .ids import init_user_id
from .image import get_file_id, get_ocr, get_qrcode
from .telegram import get_chat_member, resolve_username

# Enable logging
logger = logging.getLogger(__name__)


def is_class_c(_, message: Message) -> bool:
    # Check if the message is Class C object
    try:
        if message.from_user:
            uid = message.from_user.id
            if uid in glovar.bot_ids or message.from_user.is_self:
                return True
    except Exception as e:
        logger.warning(f"Is class c error: {e}", exc_info=True)

    return False


def is_class_d(_, message: Message) -> bool:
    # Check if the message is Class D object
    try:
        if message.from_user:
            uid = message.from_user.id
            if uid in glovar.bad_ids["users"]:
                return True

        if message.forward_from:
            fid = message.forward_from.id
            if fid in glovar.bad_ids["users"]:
                return True

        if message.forward_from_chat:
            cid = message.forward_from_chat.id
            if cid in glovar.bad_ids["channels"]:
                return True
    except Exception as e:
        logger.warning(f"Is class d error: {e}", exc_info=True)

    return False


def is_class_e(_, message: Message) -> bool:
    # Check if the message is Class E object
    try:
        if message.forward_from_chat:
            cid = message.forward_from_chat.id
            if cid in glovar.except_ids["channels"]:
                return True

        content = get_content(None, message)
        if content:
            if (content in glovar.except_ids["long"]
                    or content in glovar.except_ids["temp"]):
                return True
    except Exception as e:
        logger.warning(f"Is class e error: {e}", exc_info=True)

    return False


def is_declared_message(_, message: Message) -> bool:
    # Check if the message is declared by other bots
    try:
        if message.chat:
            gid = message.chat.id
            mid = message.message_id
            return is_declared_message_id(gid, mid)
    except Exception as e:
        logger.warning(f"Is declared message error: {e}", exc_info=True)

    return False


def is_hide_channel(_, message: Message) -> bool:
    # Check if the message is sent from the hide channel
    try:
        if message.chat:
            cid = message.chat.id
            if cid == glovar.hide_channel_id:
                return True
    except Exception as e:
        logger.warning(f"Is hide channel error: {e}", exc_info=True)

    return False


def is_new_user(_, message: Message) -> bool:
    # Check if the message is sent from a new joined member
    try:
        if message.from_user:
            uid = message.from_user.id
            if glovar.user_ids.get(uid, {}):
                now = get_now()
                join = glovar.user_ids[uid]["join"]
                if now - join < glovar.time_new:
                    return True
    except Exception as e:
        logger.warning(f"Is new user error: {e}", exc_info=True)

    return False


def is_watch_ban(_, message: Message) -> bool:
    # Check if the message is sent by a watch ban user
    try:
        if message.from_user:
            return is_watch_user(message, "ban")
    except Exception as e:
        logger.warning(f"Is watch ban error: {e}", exc_info=True)

    return False


def is_watch_delete(_, message: Message) -> bool:
    # Check if the message is sent by a watch delete user
    try:
        if message.from_user:
            return is_watch_user(message, "delete")
    except Exception as e:
        logger.warning(f"Is watch delete error: {e}", exc_info=True)

    return False


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

declared_message = Filters.create(
    func=is_declared_message,
    name="Declared message"
)

hide_channel = Filters.create(
    func=is_hide_channel,
    name="Hide Channel"
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


def is_ban_name(text: str) -> bool:
    # Check if the name will be banned
    try:
        if (is_regex_text("nm", text)
                or is_regex_text("ban", text)
                or (is_regex_text("ad", text) and is_regex_text("con", text))
                or is_regex_text("bio", text)):
            return True
    except Exception as e:
        logger.warning(f"Is ban name error: {e}", exc_info=True)

    return False


def is_ban_text(text: str) -> bool:
    # Check if the text is ban text
    try:
        if is_regex_text("ban", text):
            return True

        if is_regex_text("ad", text) and is_regex_text("con", text):
            return True
    except Exception as e:
        logger.warning(f"Is ban text error: {e}", exc_info=True)

    return False


def is_declared_message_id(gid: int, mid: int) -> bool:
    # Check if the message's ID is declared by other bots
    try:
        if mid in glovar.declared_message_ids.get(gid, set()):
            return True
    except Exception as e:
        logger.warning(f"Is declared message id error: {e}", exc_info=True)

    return False


def is_exe(message: Message) -> bool:
    # Check if the message contain a exe
    try:
        if message.document:
            if message.document.file_name:
                file_name = message.document.file_name
                for file_type in ["apk", "bat", "cmd", "com", "exe", "vbs"]:
                    if re.search(f"[.]{file_type}$", file_name, re.I):
                        return True

            if message.document.mime_type:
                mime_type = message.document.mime_type
                if "executable" in mime_type:
                    return True

        links = get_links(message)
        for link in links:
            for file_type in ["apk", "bat", "cmd", "exe", "vbs"]:
                if re.search(f"[.]{file_type}$", link, re.I):
                    return True
    except Exception as e:
        logger.warning(f"Is exe error: {e}", exc_info=True)

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


def is_regex_text(word_type: str, text: str, again: bool = False) -> bool:
    # Check if the text hit the regex rules
    result = False
    try:
        if text:
            if not again:
                text = re.sub(r"\s{2,}", " ", text)
            elif " " in text:
                text = re.sub(r"\s", "", text)
            else:
                return False
        else:
            return False

        for word in list(eval(f"glovar.{word_type}_words")):
            if re.search(word, text, re.I | re.S | re.M):
                result = True

            # Match, count and return
            if result:
                count = eval(f"glovar.{word_type}_words").get(word, 0)
                count += 1
                eval(f"glovar.{word_type}_words")[word] = count
                save(f"{word_type}_words")
                return result

        # Try again
        return is_regex_text(word_type, text, True)
    except Exception as e:
        logger.warning(f"Is regex text error: {e}", exc_info=True)

    return result


def is_tgl(client: Client, message: Message) -> bool:
    # Check if the message includes the Telegram link
    try:
        bypass = get_stripped_link(get_channel_link(message))
        links = get_links(message)
        tg_links = filter(lambda l: is_regex_text("tgl", l), links)
        if not all([f"{bypass}/" in f"{link}/" for link in tg_links]):
            return True

        if message.entities:
            for en in message.entities:
                if en.type == "mention":
                    username = get_entity_text(message, en)[1:]
                    if message.chat.username and username == message.chat.username:
                        continue

                    peer_type, peer_id = resolve_username(client, username)
                    if peer_type == "channel" and peer_id not in glovar.except_ids["channels"]:
                        return True

                    if peer_type == "user":
                        member = get_chat_member(client, message.chat.id, peer_id)
                        if member is False:
                            return True

                        if member and member.status not in {"creator", "administrator", "member"}:
                            return True
    except Exception as e:
        logger.warning(f"Is tgl error: {e}", exc_info=True)

    return False


def is_watch_message(client: Client, message: Message) -> str:
    # Check if the message should be watched
    result = ""
    need_delete = []
    if glovar.locks["message"].acquire():
        try:
            gid = message.chat.id
            uid = message.from_user.id
            if not init_user_id(uid):
                return ""

            # Start detect watch ban

            # Check if the user already recorded in this group
            if gid in glovar.user_ids[uid]["ban"]:
                return ""

            # Check detected records
            content = get_content(client, message)
            if content:
                detection = glovar.contents.get(content, "")
                if detection == "ban":
                    return detection

            # Check the message's text
            message_text = get_text(message)
            if message_text:
                if is_ban_text(message_text):
                    return ""

                if is_wb_text(message_text):
                    return "ban"

            # Check the forward from name:
            forward_name = get_forward_name(message)
            if forward_name:
                if is_ban_text(forward_name):
                    return ""

                if is_wb_text(forward_name):
                    return "ban"

            # Check the document filename:
            file_name = get_document_filename(message)
            if file_name:
                if is_ban_text(file_name):
                    return ""

                if is_wb_text(file_name):
                    return "ban"

            # Check exe file
            if is_exe(message):
                return "ban"

            # Check image
            ocr = ""
            file_id, big = get_file_id(message)
            image_path = get_downloaded_path(client, file_id)
            if is_declared_message(None, message):
                return ""
            elif image_path:
                need_delete.append(image_path)
                if big:
                    qrcode = get_qrcode(image_path)
                    if qrcode:
                        if is_ban_text(qrcode):
                            return ""

                        return "ban"

                    ocr = get_ocr(image_path)
                    if ocr:
                        if is_ban_text(ocr):
                            return ""

                        if is_wb_text(ocr):
                            return "ban"

            # Check preview
            preview_text = ""
            web_page: WebPage = message.web_page
            if web_page:
                preview_text = web_page.display_url + "\n\n"

                if web_page.site_name:
                    preview_text += web_page.site_name + "\n\n"

                if web_page.title:
                    preview_text += web_page.title + "\n\n"

                if web_page.description:
                    preview_text += web_page.description + "\n\n"

                if is_ban_text(preview_text):
                    return ""

                if is_wb_text(preview_text):
                    return "ban"

                if web_page.photo:
                    if web_page.photo.file_size <= glovar.image_size:
                        file_id = web_page.photo.file_id
                        image_path = get_downloaded_path(client, file_id)
                        if image_path:
                            need_delete.append(image_path)
                            qrcode = get_qrcode(image_path)
                            if qrcode:
                                if is_ban_text(qrcode):
                                    return ""

                                return "ban"

                            ocr = get_ocr(image_path)
                            if ocr:
                                if is_ban_text(ocr):
                                    return ""

                                if is_wb_text(ocr):
                                    return "ban"

            # Start detect watch delete

            # Check if the user is already in watch delete
            if not is_watch_delete(None, message):
                return ""

            # Check if the user already recorded in this group
            if gid in glovar.user_ids[uid]["delete"]:
                return ""

            # Check detected records
            if content:
                detection = glovar.contents.get(content, "")
                if detection == "delete":
                    return detection

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
                if is_wd_text(message_text):
                    return "delete"

            # Check the message's mention
            if message.entities:
                for en in message.entities:
                    if en.type == "mention":
                        return "delete"

            # Check Telegram link
            if is_tgl(client, message):
                return "delete"

            # Check image
            if ocr:
                if is_wd_text(message_text):
                    return "delete"

            # Check preview
            if preview_text:
                if is_wd_text(preview_text):
                    return "delete"

            if web_page:
                if (web_page.audio
                        or web_page.document
                        or web_page.animation
                        or web_page.video):
                    return "delete"
        except Exception as e:
            logger.warning(f"Is watch message error: {e}", exc_info=True)
        finally:
            glovar.locks["message"].release()
            for file in need_delete:
                delete_file(file)

    return result


def is_watch_user(message: Message, the_type: str) -> bool:
    # Check if the message is sent by a watch user
    try:
        if message.from_user:
            uid = message.from_user.id
            if glovar.user_ids.get(uid, {}):
                if glovar.user_ids[uid]["type"] == the_type:
                    now = get_now()
                    until = glovar.user_ids[uid]["until"]
                    if now < until:
                        return True
    except Exception as e:
        logger.warning(f"Is watch user error: {e}", exc_info=True)

    return False


def is_wb_text(text: str) -> bool:
    # Check if the text is wb text
    try:
        if (is_regex_text("wb", text)
                or is_regex_text("iml", text)
                or is_regex_text("ad", text)
                or is_regex_text("aff", text)
                or is_regex_text("spc", text)
                or is_regex_text("spe", text)):
            return True
    except Exception as e:
        logger.warning(f"Is wb text error: {e}", exc_info=True)

    return False


def is_wd_text(text: str) -> bool:
    # Check if the text is wd text
    try:
        if (is_regex_text("wd", text)
                or is_regex_text("con", text)
                or is_regex_text("sho", text)
                or is_regex_text("tgp", text)):
            return True
    except Exception as e:
        logger.warning(f"Is wd text error: {e}", exc_info=True)

    return False
