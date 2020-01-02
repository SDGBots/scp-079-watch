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
from copy import deepcopy
from string import ascii_lowercase
from typing import Match, Optional, Union

from pyrogram import Client, Filters, Message, User, WebPage

from .. import glovar
from .channel import get_content
from .etc import get_channel_link, get_entity_text, get_filename, get_forward_name, get_lang, get_md5sum, get_now
from .etc import get_links, get_stripped_link, get_text, thread
from .file import delete_file, get_downloaded_path, save
from .group import get_description, get_member, get_pinned
from .ids import init_user_id
from .image import get_color, get_file_id, get_ocr, get_qrcode
from .telegram import get_sticker_title, resolve_username

# Enable logging
logger = logging.getLogger(__name__)


def is_class_c(_, message: Message) -> bool:
    # Check if the message is sent from Class C personnel
    try:
        if not message.from_user:
            return False

        # Basic data
        uid = message.from_user.id

        # Check permission
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

        content = get_content(message)

        if not content:
            return False

        if (content in glovar.except_ids["long"]
                or content in glovar.except_ids["temp"]):
            return True
    except Exception as e:
        logger.warning(f"Is class e error: {e}", exc_info=True)

    return False


def is_declared_message(_, message: Message) -> bool:
    # Check if the message is declared by other bots
    try:
        if not message.chat:
            return False

        gid = message.chat.id
        mid = message.message_id
        return is_declared_message_id(gid, mid)
    except Exception as e:
        logger.warning(f"Is declared message error: {e}", exc_info=True)

    return False


def is_from_user(_, message: Message) -> bool:
    # Check if the message is sent from a user
    try:
        if message.from_user and message.from_user.id != 777000:
            return True
    except Exception as e:
        logger.warning(f"Is from user error: {e}", exc_info=True)

    return False


def is_hide_channel(_, message: Message) -> bool:
    # Check if the message is sent from the hide channel
    try:
        if not message.chat:
            return False

        cid = message.chat.id
        if cid == glovar.hide_channel_id:
            return True
    except Exception as e:
        logger.warning(f"Is hide channel error: {e}", exc_info=True)

    return False


def is_new_user(_, message: Message) -> bool:
    # Check if the message is sent from a new joined member
    try:
        if not message.from_user:
            return False

        uid = message.from_user.id
        if not glovar.user_ids.get(uid, {}):
            return False

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
        if not message.from_user:
            return False

        return is_watch_user(message.from_user, "ban")
    except Exception as e:
        logger.warning(f"Is watch ban error: {e}", exc_info=True)

    return False


def is_watch_delete(_, message: Message) -> bool:
    # Check if the message is sent by a watch delete user
    try:
        if not message.from_user:
            return False

        return is_watch_user(message.from_user, "delete")
    except Exception as e:
        logger.warning(f"Is watch delete error: {e}", exc_info=True)

    return False


class_c = Filters.create(
    func=is_class_c,
    name="Class C"
)

class_d = Filters.create(
    func=is_class_d,
    name="Class D"
)

class_e = Filters.create(
    func=is_class_e,
    name="Class E"
)

declared_message = Filters.create(
    func=is_declared_message,
    name="Declared message"
)

from_user = Filters.create(
    func=is_from_user,
    name="From User"
)

hide_channel = Filters.create(
    func=is_hide_channel,
    name="Hide Channel"
)

new_user = Filters.create(
    func=is_new_user,
    name="New User"
)

watch_ban = Filters.create(
    func=is_watch_ban,
    name="Watch Ban"
)

watch_delete = Filters.create(
    func=is_watch_delete,
    name="Watch Delete"
)


def is_ad_text(text: str, ocr: bool, matched: str = "") -> str:
    # Check if the text is ad text
    try:
        if not text:
            return ""

        for c in ascii_lowercase:
            if c != matched and is_regex_text(f"ad{c}", text, ocr):
                return c
    except Exception as e:
        logger.warning(f"Is ad text error: {e}", exc_info=True)

    return ""


def is_ban_text(text: str, ocr: bool, message: Message = None) -> bool:
    # Check if the text is ban text
    try:
        if is_regex_text("ban", text, ocr):
            return True

        # ad + con
        ad = is_regex_text("ad", text, ocr)
        con = is_con_text(text, ocr)

        if ad and con:
            return True

        # emoji + con
        emoji = is_emoji("ad", text, message)

        if emoji and con:
            return True

        # ad_ + con
        ad = is_ad_text(text, ocr)

        if ad and con:
            return True

        # ad_ + emoji
        if ad and emoji:
            return True

        # ad_ + ad_
        if ad:
            ad = is_ad_text(text, ocr, ad)
            return bool(ad)
    except Exception as e:
        logger.warning(f"Is ban text error: {e}", exc_info=True)

    return False


def is_bio_text(text: str) -> bool:
    # Check if the text is bio text
    try:
        if (is_regex_text("bio", text)
                or is_ban_text(text, False)):
            return True
    except Exception as e:
        logger.warning(f"Is bio text error: {e}", exc_info=True)

    return False


def is_class_e_user(user: Union[int, User]) -> bool:
    # Check if the user is a Class E personnel
    try:
        if isinstance(user, int):
            uid = user
        else:
            uid = user.id

        if uid in glovar.bot_ids:
            return True

        group_list = list(glovar.admin_ids)
        for gid in group_list:
            if uid in glovar.admin_ids.get(gid, set()):
                return True
    except Exception as e:
        logger.warning(f"Is class e user error: {e}", exc_info=True)

    return False


def is_class_d_user(user: Union[int, User]) -> bool:
    # Check if the user is a Class D personnel
    try:
        if isinstance(user, int):
            uid = user
        else:
            uid = user.id

        if uid in glovar.bad_ids["users"]:
            return True
    except Exception as e:
        logger.warning(f"Is class d user error: {e}", exc_info=True)

    return False


def is_con_text(text: str, ocr: bool) -> bool:
    # Check if the text is con text
    try:
        if (is_regex_text("con", text, ocr)
                or is_regex_text("iml", text, ocr)
                or is_regex_text("pho", text, ocr)):
            return True
    except Exception as e:
        logger.warning(f"Is con text error: {e}", exc_info=True)

    return False


def is_declared_message_id(gid: int, mid: int) -> bool:
    # Check if the message's ID is declared by other bots
    try:
        if mid in glovar.declared_message_ids.get(gid, set()):
            return True
    except Exception as e:
        logger.warning(f"Is declared message id error: {e}", exc_info=True)

    return False


def is_emoji(the_type: str, text: str, message: Message = None) -> bool:
    # Check the emoji type
    try:
        if message:
            text = get_text(message, False, False)

        emoji_dict = {}
        emoji_set = {emoji for emoji in glovar.emoji_set if emoji in text and emoji not in glovar.emoji_protect}
        emoji_old_set = deepcopy(emoji_set)

        for emoji in emoji_old_set:
            if any(emoji in emoji_old and emoji != emoji_old for emoji_old in emoji_old_set):
                emoji_set.discard(emoji)

        for emoji in emoji_set:
            emoji_dict[emoji] = text.count(emoji)

        # Check ad
        if the_type == "ad":
            if any(emoji_dict[emoji] >= glovar.emoji_ad_single for emoji in emoji_dict):
                return True

            if sum(emoji_dict.values()) >= glovar.emoji_ad_total:
                return True

        # Check many
        elif the_type == "many":
            if sum(emoji_dict.values()) >= glovar.emoji_many:
                return True

        # Check wb
        elif the_type == "wb":
            if any(emoji_dict[emoji] >= glovar.emoji_wb_single for emoji in emoji_dict):
                return True

            if sum(emoji_dict.values()) >= glovar.emoji_wb_total:
                return True
    except Exception as e:
        logger.warning(f"Is emoji error: {e}", exc_info=True)

    return False


def is_exe(message: Message) -> bool:
    # Check if the message contain a exe
    try:
        extensions = ["apk", "bat", "cmd", "com", "exe", "msi", "pif", "scr", "vbs"]
        if message.document:
            if message.document.file_name:
                file_name = message.document.file_name
                for file_type in extensions:
                    if re.search(f"[.]{file_type}$", file_name, re.I):
                        return True

            if message.document.mime_type:
                mime_type = message.document.mime_type
                if "application/x-ms" in mime_type or "executable" in mime_type:
                    return True

        extensions.remove("com")
        links = get_links(message)
        for link in links:
            for file_type in extensions:
                if re.search(f"[.]{file_type}$", link, re.I):
                    return True
    except Exception as e:
        logger.warning(f"Is exe error: {e}", exc_info=True)

    return False


def is_friend_username(client: Client, gid: int, username: str, friend: bool, friend_user: bool = False) -> bool:
    # Check if it is a friend username
    try:
        username = username.strip()
        if not username:
            return False

        if username[0] != "@":
            username = "@" + username

        if not re.search(r"\B@([a-z][0-9a-z_]{4,31})", username, re.I | re.M | re.S):
            return False

        peer_type, peer_id = resolve_username(client, username)
        if peer_type == "channel":
            if friend:
                if peer_id in glovar.except_ids["channels"]:
                    return True

        if peer_type == "user":
            if friend and friend_user:
                return True

            member = get_member(client, gid, peer_id)
            if member and member.status in {"creator", "administrator", "member"}:
                return True
    except Exception as e:
        logger.warning(f"Is friend username: {e}", exc_info=True)

    return False


def is_high_score_user(user: User) -> float:
    # Check if the message is sent by a high score user
    try:
        if is_class_e_user(user):
            return 0.0

        uid = user.id
        user_status = glovar.user_ids.get(uid, {})

        if not user_status:
            return 0.0

        score = sum(user_status["score"].values())
        if score >= 3.0:
            return score
    except Exception as e:
        logger.warning(f"Is high score user error: {e}", exc_info=True)

    return 0.0


def is_lang(the_type: str, text: str) -> bool:
    # Check language
    try:
        the_lang = get_lang(text)

        if not the_lang:
            return False

        if the_type == "bio":
            return the_lang in glovar.lang_bio
        elif the_type == "name":
            return the_lang in glovar.lang_name
        elif the_type == "sticker":
            return the_lang in glovar.lang_sticker
        elif the_type == "text":
            return the_lang in glovar.lang_text
    except Exception as e:
        logger.warning(f"Is lang error: {e}", exc_info=True)

    return False


def is_nm_text(text: str) -> bool:
    # Check if the text is nm text
    try:
        if (is_regex_text("nm", text)
                or is_regex_text("bio", text)
                or is_ban_text(text, False)):
            return True
    except Exception as e:
        logger.warning(f"Is nm text error: {e}", exc_info=True)

    return False


def is_restricted_channel(message: Message) -> bool:
    # Check if the message is forwarded form restricted channel
    try:
        if not message.forward_from_chat:
            return False

        if message.forward_from_chat.restrictions:
            return True
    except Exception as e:
        logger.warning(f"Is restricted channel error: {e}", exc_info=True)

    return False


def is_regex_text(word_type: str, text: str, ocr: bool = False, again: bool = False) -> Optional[Match]:
    # Check if the text hit the regex rules
    result = None
    try:
        if text:
            if not again:
                text = re.sub(r"\s{2,}", " ", text)
            elif " " in text:
                text = re.sub(r"\s", "", text)
            else:
                return None
        else:
            return None

        with glovar.locks["regex"]:
            words = list(eval(f"glovar.{word_type}_words"))

        for word in words:
            if ocr and "(?# nocr)" in word:
                continue

            result = re.search(word, text, re.I | re.S | re.M)

            # Count and return
            if result:
                count = eval(f"glovar.{word_type}_words").get(word, 0)
                count += 1
                eval(f"glovar.{word_type}_words")[word] = count
                save(f"{word_type}_words")
                return result

        # Try again
        return is_regex_text(word_type, text, ocr, True)
    except Exception as e:
        logger.warning(f"Is regex text error: {e}", exc_info=True)

    return result


def is_tgl(client: Client, message: Message, friend: bool = False) -> bool:
    # Check if the message includes the Telegram link
    try:
        # Bypass prepare
        gid = message.chat.id
        description = get_description(client, gid).lower()
        pinned_message = get_pinned(client, gid)
        pinned_text = get_text(pinned_message).lower()

        # Check links
        bypass = get_stripped_link(get_channel_link(message))
        links = get_links(message)
        tg_links = [lk.lower() for lk in links if is_regex_text("tgl", lk)]

        # Define a bypass link filter function
        def is_bypass_link(link: str) -> bool:
            try:
                link_username = re.match(r"t\.me/([a-z][0-9a-z_]{4,31})/", f"{link}/")
                if link_username:
                    link_username = link_username.group(1).lower()

                    if link_username in glovar.invalid:
                        return True

                    if link_username == "joinchat":
                        link_username = ""
                    else:
                        if is_friend_username(client, gid, link_username, friend):
                            return True

                if (f"{bypass}/" in f"{link}/"
                        or link in description
                        or (link_username and link_username in description)
                        or link in pinned_text
                        or (link_username and link_username in pinned_text)):
                    return True
            except Exception as ee:
                logger.warning(f"Is bypass link error: {ee}", exc_info=True)

            return False

        bypass_list = [link for link in tg_links if is_bypass_link(link)]
        if len(bypass_list) != len(tg_links):
            return True

        # Check text
        message_text = get_text(message, True, True).lower()
        for bypass in bypass_list:
            message_text = message_text.replace(bypass, "")

        if is_regex_text("tgl", message_text):
            return True

        # Check mentions
        entities = message.entities or message.caption_entities
        if not entities:
            return False

        for en in entities:
            if en.type == "mention":
                username = get_entity_text(message, en)[1:].lower()

                if username in glovar.invalid:
                    continue

                if message.chat.username and username == message.chat.username.lower():
                    continue

                if username in description:
                    continue

                if username in pinned_text:
                    continue

                if not is_friend_username(client, gid, username, friend):
                    return True

            if en.type == "user":
                uid = en.user.id
                member = get_member(client, gid, uid)
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
    try:
        if not message.chat:
            return ""

        # Basic data
        gid = message.chat.id
        uid = message.from_user.id

        if not init_user_id(uid):
            return ""

        # Start detect watch ban

        # Check detected records
        message_content = get_content(message)
        if message_content:
            detection = glovar.contents.get(message_content, "")
            if detection:
                return detection

        # Work with NOSPAM, check the message's text
        message_text = get_text(message, True, True)
        if message_text:
            if is_ban_text(message_text, False):
                return ""

        # Bypass
        message_text = get_text(message)
        description = get_description(client, gid)
        if (description and message_text) and message_text in description:
            return ""

        pinned_message = get_pinned(client, gid)
        pinned_content = get_content(pinned_message)
        if (pinned_content and message_content) and message_content in pinned_content:
            return ""

        pinned_text = get_text(pinned_message)
        if (pinned_text and message_text) and message_text in pinned_text:
            return ""

        # Work with NOSPAM and default LANG, check the forward from name:
        forward_name = get_forward_name(message)
        if forward_name:
            if is_nm_text(forward_name) or is_lang("name", forward_name):
                return ""

        # Check the message's text
        message_text = get_text(message)
        if message_text:
            if is_wb_text(message_text, False) or is_lang("text", message_text):
                return "ban"

        # Check channel restriction
        if is_restricted_channel(message):
            return "ban"

        # Check the forward from name:
        if forward_name and forward_name not in glovar.except_ids["long"]:
            if is_wb_text(forward_name, False) or is_lang("name", forward_name):
                return "ban"

        # Check the filename:
        file_name = get_filename(message)
        if file_name:
            if is_regex_text("fil", file_name) or is_ban_text(file_name, False):
                return ""

            if is_wb_text(file_name, False) or is_lang("text", file_name):
                return "ban"

        # Check exe file
        if is_exe(message):
            return "ban"

        # Check Telegram link
        if is_tgl(client, message):
            return "delete"

        # Check image
        ocr = ""
        all_text = ""

        # Get the image
        file_id, file_ref, big = get_file_id(message)
        image_path = big and get_downloaded_path(client, file_id, file_ref)
        image_path and need_delete.append(image_path)

        # Check declared status
        if is_declared_message(None, message):
            return ""

        # Check hash
        image_hash = image_path and get_md5sum("file", image_path)
        if image_path and image_hash and image_hash not in glovar.except_ids["temp"]:
            # Check declare status
            if is_declared_message(None, message):
                return ""

            if big:
                # Get QR code
                qrcode = get_qrcode(image_path)
                if qrcode:
                    if is_ban_text(qrcode, False):
                        return ""

                    return "ban"

                # Get OCR
                ocr = get_ocr(image_path)
                if ocr:
                    if is_ban_text(ocr, True):
                        return ""

                    if is_wb_text(ocr, True):
                        return "ban"

                    if message_text:
                        all_text = message_text + ocr
                        if is_ban_text(all_text, False):
                            return ""

                        if is_wb_text(all_text, False):
                            return "ban"

        # Check sticker title
        sticker_title = ""

        if message.sticker:
            sticker_name = message.sticker.set_name
        else:
            sticker_name = ""

        if sticker_name:
            if sticker_name not in glovar.except_ids["long"]:
                if is_regex_text("wb", sticker_name):
                    return "ban"

            sticker_title = get_sticker_title(client, sticker_name)
            if is_regex_text("wb", sticker_title) or is_lang("sticker", sticker_title):
                return f"ban {sticker_title}"

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

            if is_ban_text(preview_text, False):
                return ""

            if is_wb_text(preview_text, False) or is_lang("text", preview_text):
                return "ban"

            if web_page.photo and web_page.photo.file_size <= glovar.image_size:
                # Get the image
                file_id = web_page.photo.file_id
                file_ref = web_page.photo.file_ref
                image_path = get_downloaded_path(client, file_id, file_ref)
                image_path and need_delete.append(image_path)

                # Check declared status
                if is_declared_message(None, message):
                    return ""

                # Check hash
                image_hash = image_path and get_md5sum("file", image_path)
                if image_path and image_hash and image_hash not in glovar.except_ids["temp"]:
                    # Check declare status
                    if is_declared_message(None, message):
                        return ""

                    # Get QR code
                    qrcode = get_qrcode(image_path)
                    if qrcode:
                        if is_ban_text(qrcode, False):
                            return ""

                        return "ban"

                    # Get OCR
                    ocr = get_ocr(image_path)
                    if ocr:
                        if is_ban_text(ocr, True):
                            return ""

                        if is_wb_text(ocr, True):
                            return "ban"

                        if message_text:
                            all_text = message_text + ocr
                            if is_ban_text(all_text, False):
                                return ""

                            if is_wb_text(all_text, False):
                                return "ban"

        # Start detect watch delete

        # Check if the user is already in watch delete
        if is_watch_delete(None, message):
            return ""

        # Check detected records
        if message_content:
            detection = glovar.contents.get(message_content, "")
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

        # Forwarded message
        if message.forward_from or message.forward_sender_name or message.forward_from_chat:
            return "delete"

        # Check the message's text
        if message_text:
            if is_wd_text(message_text, False):
                return "delete"

        # Check image
        if ocr:
            if is_wd_text(message_text, True):
                return "delete"

        if all_text:
            if is_wd_text(all_text, False):
                return "delete"

        if image_path:
            color = get_color(image_path)
            if color:
                return "delete"

        # Check sticker
        if sticker_title and sticker_title not in glovar.except_ids["long"]:
            if is_regex_text("wd", sticker_title):
                return f"delete {sticker_title}"

        # Check preview
        if preview_text:
            if is_wd_text(preview_text, False):
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
        for file in need_delete:
            thread(delete_file, (file,))

    return result


def is_watch_user(user: User, the_type: str) -> bool:
    # Check if the message is sent by a watch user
    try:
        uid = user.id

        if not glovar.user_ids.get(uid, {}):
            return False

        if glovar.user_ids[uid]["type"] != the_type:
            return False

        now = get_now()
        until = glovar.user_ids[uid]["until"]
        if now < until:
            return True
    except Exception as e:
        logger.warning(f"Is watch user error: {e}", exc_info=True)

    return False


def is_wb_text(text: str, ocr: bool) -> bool:
    # Check if the text is wb text
    try:
        if (is_regex_text("wb", text, ocr)
                or is_regex_text("ad", text, ocr)
                or is_regex_text("iml", text, ocr)
                or is_regex_text("pho", text, ocr)
                or is_regex_text("sho", text, ocr)
                or is_regex_text("spc", text, ocr)):
            return True

        for c in ascii_lowercase:
            if c not in {"i"} and is_regex_text(f"ad{c}", text, ocr):
                return True
    except Exception as e:
        logger.warning(f"Is wb text error: {e}", exc_info=True)

    return False


def is_wd_text(text: str, ocr: bool) -> bool:
    # Check if the text is wd text
    try:
        if (is_regex_text("wd", text, ocr)
                or is_regex_text("adi", text, ocr)
                or is_regex_text("con", text, ocr)
                or is_regex_text("spe", text, ocr)
                or is_regex_text("tgp", text, ocr)):
            return True
    except Exception as e:
        logger.warning(f"Is wd text error: {e}", exc_info=True)

    return False
