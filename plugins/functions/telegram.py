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
from struct import pack
from typing import List, Optional, Union

from pyrogram import ChatMember, Client, InlineKeyboardMarkup, Message
from pyrogram.api.functions.messages import GetWebPagePreview
from pyrogram.api.types import FileLocation, MessageMediaPhoto, MessageMediaWebPage, Photo, PhotoSize, WebPage
from pyrogram.client.ext.utils import encode
from pyrogram.errors import ChannelInvalid, ChannelPrivate, FloodWait, PeerIdInvalid

from .. import glovar
from .etc import get_text, wait_flood

# Enable logging
logger = logging.getLogger(__name__)


def download_media(client: Client, file_id: str, file_path: str):
    # Download a media file
    result = None
    try:
        flood_wait = True
        while flood_wait:
            flood_wait = False
            try:
                result = client.download_media(message=file_id, file_name=file_path)
            except FloodWait as e:
                flood_wait = True
                wait_flood(e)
    except Exception as e:
        logger.warning(f"Download media {file_id} to {file_path} error: {e}", exc_info=True)

    return result


def get_admins(client: Client, cid: int) -> Optional[Union[bool, List[ChatMember]]]:
    # Get a group's admins
    result = None
    try:
        flood_wait = True
        while flood_wait:
            flood_wait = False
            try:
                result = client.get_chat_members(chat_id=cid, filter="administrators")
            except FloodWait as e:
                flood_wait = True
                wait_flood(e)
            except (PeerIdInvalid, ChannelInvalid, ChannelPrivate):
                return False

        result = result.chat_members
    except Exception as e:
        logger.warning(f"Get admin ids in {cid} error: {e}", exc_info=True)

    return result


def get_preview(client: Client, message: Message) -> dict:
    # Get message's preview
    preview = {
        "text": None,
        "file_id": None
    }
    try:
        if should_preview(message):
            result = None
            message_text = get_text(message)
            flood_wait = True
            while flood_wait:
                flood_wait = False
                try:
                    result = client.send(GetWebPagePreview(message=message_text))
                except FloodWait as e:
                    flood_wait = True
                    wait_flood(e)

            if result:
                photo = None
                if isinstance(result, MessageMediaWebPage):
                    web_page = result.webpage
                    if isinstance(web_page, WebPage):
                        text = ""
                        if web_page.display_url:
                            text += web_page.display_url + "\n\n"

                        if web_page.site_name:
                            text += web_page.site_name + "\n\n"

                        if web_page.title:
                            text += web_page.title + "\n\n"

                        if web_page.description:
                            text += web_page.description + "\n\n"

                        preview["text"] = text.strip()
                        if web_page.photo:
                            if isinstance(web_page.photo, Photo):
                                photo = web_page.photo
                elif isinstance(result, MessageMediaPhoto):
                    media = result.photo
                    if isinstance(media, Photo):
                        photo = media

                if photo:
                    size = photo.sizes[-1]
                    if isinstance(size, PhotoSize):
                        file_size = size.size
                        if file_size < glovar.image_size:
                            loc = size.location
                            if isinstance(loc, FileLocation):
                                file_id = encode(
                                    pack(
                                        "<iiqqqqi",
                                        2,
                                        loc.dc_id,
                                        photo.id,
                                        photo.access_hash,
                                        loc.volume_id,
                                        loc.secret,
                                        loc.local_id
                                    )
                                )
                                preview["file_id"] = file_id
    except Exception as e:
        logger.warning(f"Get preview error: {e}", exc_info=True)

    return preview


def kick_chat_member(client: Client, cid: int, uid: int) -> Optional[Union[bool, Message]]:
    # Kick a chat member in a group
    result = None
    try:
        flood_wait = True
        while flood_wait:
            flood_wait = False
            try:
                result = client.kick_chat_member(chat_id=cid, user_id=uid)
            except FloodWait as e:
                flood_wait = True
                wait_flood(e)
    except Exception as e:
        logger.warning(f"Kick chat member {uid} in {cid} error: {e}", exc_info=True)

    return result


def send_document(client: Client, cid: int, file: str, text: str = None, mid: int = None,
                  markup: InlineKeyboardMarkup = None) -> Optional[Union[bool, Message]]:
    # Send a document to a chat
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
                    reply_to_message_id=mid,
                    reply_markup=markup
                )
            except FloodWait as e:
                flood_wait = True
                wait_flood(e)
            except (PeerIdInvalid, ChannelInvalid, ChannelPrivate):
                return False
    except Exception as e:
        logger.warning(f"Send document to {cid} error: {e}", exec_info=True)

    return result


def send_message(client: Client, cid: int, text: str, mid: int = None,
                 markup: InlineKeyboardMarkup = None) -> Optional[Union[bool, Message]]:
    # Send a message to a chat
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
                        disable_web_page_preview=True,
                        reply_to_message_id=mid,
                        reply_markup=markup
                    )
                except FloodWait as e:
                    flood_wait = True
                    wait_flood(e)
                except (PeerIdInvalid, ChannelInvalid, ChannelPrivate):
                    return False
    except Exception as e:
        logger.warning(f"Send message to {cid} error: {e}", exc_info=True)

    return result


def should_preview(message: Message) -> bool:
    # Check if the message should be previewed
    if message.entities or message.caption_entities:
        if message.entities:
            entities = message.entities
        else:
            entities = message.caption_entities

        for en in entities:
            if en.type in ["url", "text_link"]:
                return True

    return False
