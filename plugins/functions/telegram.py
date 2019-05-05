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
from time import sleep
from typing import List, Optional, Union

from pyrogram import ChatMember, Client, InlineKeyboardMarkup, Message, ParseMode
from pyrogram.errors import ChannelInvalid, ChannelPrivate, FloodWait, PeerIdInvalid

# Enable logging
logger = logging.getLogger(__name__)


def answer_callback(client: Client, query_id: str, text: str) -> Optional[bool]:
    result = None
    try:
        flood_wait = True
        while flood_wait:
            flood_wait = False
            try:
                result = client.answer_callback_query(
                    callback_query_id=query_id,
                    text=text
                )
            except FloodWait as e:
                flood_wait = True
                sleep(e.x + 1)
    except Exception as e:
        logger.warning(f"Answer query to {query_id} error: {e}", exc_info=True)

    return result


def edit_message_text(client: Client, cid: int, mid: int, text: str,
                      markup: InlineKeyboardMarkup = None) -> Optional[Message]:
    result = None
    try:
        if text.strip():
            flood_wait = True
            while flood_wait:
                flood_wait = False
                try:
                    result = client.edit_message_text(
                        chat_id=cid,
                        message_id=mid,
                        text=text,
                        parse_mode=ParseMode.MARKDOWN,
                        disable_web_page_preview=True,
                        reply_markup=markup
                    )
                except FloodWait as e:
                    flood_wait = True
                    sleep(e.x + 1)
    except Exception as e:
        logger.warning(f"Edit message in {cid} error: {e}", exc_info=True)

    return result


def download_media(client: Client, file_id: str, file_path: str):
    result = None
    try:
        flood_wait = True
        while flood_wait:
            flood_wait = False
            try:
                result = client.download_media(message=file_id, file_name=file_path)
            except FloodWait as e:
                flood_wait = True
                sleep(e.x + 1)
    except Exception as e:
        logger.warning(f"Download media {file_id} to {file_path} error: {e}", exc_info=True)

    return result


def get_admins(client: Client, cid: int) -> Optional[Union[bool, List[ChatMember]]]:
    result = None
    try:
        flood_wait = True
        while flood_wait:
            flood_wait = False
            try:
                result = client.get_chat_members(chat_id=cid, filter="administrators")
            except FloodWait as e:
                flood_wait = True
                sleep(e.x + 1)
            except (PeerIdInvalid, ChannelInvalid, ChannelPrivate):
                return False

        result = result.chat_members
    except Exception as e:
        logger.warning(f"Get admin ids in {cid} error: {e}", exc_info=True)

    return result


def kick_chat_member(client: Client, cid: int, uid: int) -> Optional[Union[bool, Message]]:
    result = None
    try:
        flood_wait = True
        while flood_wait:
            flood_wait = False
            try:
                result = client.kick_chat_member(chat_id=cid, user_id=uid)
            except FloodWait as e:
                flood_wait = True
                sleep(e.x + 1)
    except Exception as e:
        logger.warning(f"Kick chat member {uid} in {cid} error: {e}", exc_info=True)

    return result


def send_document(client: Client, cid: int, file: str, text: str = None, mid: int = None,
                  markup: InlineKeyboardMarkup = None) -> Optional[Message]:
    result = None
    try:
        flood_wait = True
        while flood_wait:
            flood_wait = False
            try:
                result = client.send_document(
                    chat_id=cid,
                    document=file,
                    caption=text,
                    parse_mode=ParseMode.MARKDOWN,
                    reply_to_message_id=mid,
                    reply_markup=markup
                )
            except FloodWait as e:
                flood_wait = True
                sleep(e.x + 1)
    except Exception as e:
        logger.warning(f"Send document to {cid} error: {e}", exec_info=True)

    return result


def send_message(client: Client, cid: int, text: str, mid: int = None,
                 markup: InlineKeyboardMarkup = None) -> Optional[Message]:
    result = None
    try:
        if text.strip():
            flood_wait = True
            while flood_wait:
                flood_wait = False
                try:
                    result = client.send_message(
                        chat_id=cid,
                        text=text,
                        parse_mode=ParseMode.MARKDOWN,
                        disable_web_page_preview=True,
                        reply_to_message_id=mid,
                        reply_markup=markup
                    )
                except FloodWait as e:
                    flood_wait = True
                    sleep(e.x + 1)
    except Exception as e:
        logger.warning(f"Send message to {cid} error: {e}", exc_info=True)

    return result
