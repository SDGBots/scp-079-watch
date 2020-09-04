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
from typing import Iterable, List, Optional, Union

from pyrogram import Client
from pyrogram.errors import (ChatAdminRequired, ButtonDataInvalid, ButtonUrlInvalid, ChannelInvalid, ChannelPrivate,
                             FloodWait, MessageIdInvalid, PeerIdInvalid, UsernameInvalid, UsernameNotOccupied,
                             UserNotParticipant)
from pyrogram.raw.base import InputChannel, InputUser, InputPeer
from pyrogram.raw.functions.messages import GetStickerSet
from pyrogram.raw.functions.users import GetFullUser
from pyrogram.raw.types import InputPeerUser, InputPeerChannel, InputStickerSetShortName, StickerSet, UserFull
from pyrogram.raw.types.messages import StickerSet as messages_StickerSet
from pyrogram.types import Chat, ChatMember, ChatPreview, InlineKeyboardMarkup, Message, ReplyKeyboardMarkup

from .. import glovar
from .decorators import retry
from .etc import get_int, t2t, wait_flood

# Enable logging
logger = logging.getLogger(__name__)


@retry
def download_media(client: Client, file_id: str, file_ref: str, file_path: str) -> Optional[str]:
    # Download a media file
    result = None

    try:
        result = client.download_media(message=file_id, file_ref=file_ref, file_name=file_path)
    except FloodWait as e:
        raise e
    except Exception as e:
        logger.warning(f"Download media {file_id} to {file_path} error: {e}", exc_info=True)

    return result


@retry
def forward_messages(client: Client, cid: int, fid: int,
                     mids: Union[int, Iterable[int]]) -> Union[bool, Message, List[Message], None]:
    # Forward messages of any kind
    result = None

    try:
        result = client.forward_messages(
            chat_id=cid,
            from_chat_id=fid,
            message_ids=mids,
            disable_notification=True
        )
    except FloodWait as e:
        raise e
    except (ChannelInvalid, ChannelPrivate, ChatAdminRequired, MessageIdInvalid, PeerIdInvalid):
        return False
    except Exception as e:
        logger.warning(f"Forward messages error: {e}", exc_info=True)

    return result


@retry
def get_chat(client: Client, cid: Union[int, str]) -> Union[Chat, ChatPreview, None]:
    # Get a chat
    result = None

    try:
        result = client.get_chat(chat_id=cid)
    except FloodWait as e:
        raise e
    except (ChannelInvalid, ChannelPrivate, PeerIdInvalid):
        return None
    except Exception as e:
        logger.warning(f"Get chat {cid} error: {e}", exc_info=True)

    return result


@retry
def get_chat_member(client: Client, cid: int, uid: int) -> Union[bool, ChatMember, None]:
    # Get information about one member of a chat
    result = None

    try:
        result = client.get_chat_member(chat_id=cid, user_id=uid)
    except FloodWait as e:
        raise e
    except (ChannelInvalid, ChannelPrivate, PeerIdInvalid, UserNotParticipant):
        result = False
    except Exception as e:
        logger.warning(f"Get chat member {uid} in {cid} error: {e}", exc_info=True)

    return result


@retry
def get_messages(client: Client, cid: int, mids: Union[int, Iterable[int]]) -> Union[Message, List[Message], None]:
    # Get some messages
    result = None

    try:
        result = client.get_messages(chat_id=cid, message_ids=mids)
    except FloodWait as e:
        raise e
    except PeerIdInvalid:
        return None
    except Exception as e:
        logger.warning(f"Get messages {mids} in {cid} error: {e}", exc_info=True)

    return result


def get_sticker_title(client: Client, short_name: str, normal: bool = False, printable: bool = True,
                      cache: bool = True) -> Optional[str]:
    # Get sticker set's title
    result = None
    try:
        result = glovar.sticker_titles.get(short_name)
        if result and cache:
            return glovar.sticker_titles[short_name]

        sticker_set = InputStickerSetShortName(short_name=short_name)
        flood_wait = True
        while flood_wait:
            flood_wait = False
            try:
                the_set = client.send(GetStickerSet(stickerset=sticker_set))
                if isinstance(the_set, messages_StickerSet):
                    inner_set = the_set.set
                    if isinstance(inner_set, StickerSet):
                        result = t2t(inner_set.title, normal, printable)
            except FloodWait as e:
                flood_wait = True
                wait_flood(e)

        glovar.sticker_titles[short_name] = result
    except Exception as e:
        logger.warning(f"Get sticker {short_name} title error: {e}", exc_info=True)

    return result


@retry
def get_user_full(client: Client, uid: int) -> Optional[UserFull]:
    # Get a full user
    result = None

    try:
        user_id = resolve_peer(client, uid)

        if not user_id:
            return None

        result = client.send(GetFullUser(id=user_id))
    except FloodWait as e:
        raise e
    except Exception as e:
        logger.warning(f"Get user {uid} full error: {e}", exc_info=True)

    return result


@retry
def resolve_peer(client: Client, pid: Union[int, str]) -> Union[bool, InputChannel, InputPeer, InputUser, None]:
    # Get an input peer by id
    result = None

    try:
        result = client.resolve_peer(pid)
    except FloodWait as e:
        raise e
    except (PeerIdInvalid, UsernameInvalid, UsernameNotOccupied):
        return False
    except Exception as e:
        logger.warning(f"Resolve peer {pid} error: {e}", exc_info=True)

    return result


def resolve_username(client: Client, username: str, cache: bool = True) -> (str, int):
    # Resolve peer by username
    peer_type = ""
    peer_id = 0

    try:
        username = username.strip("@")

        if not username:
            return "", 0

        the_cache = glovar.usernames.get(username)

        if cache and the_cache:
            return the_cache["peer_type"], the_cache["peer_id"]

        result = resolve_peer(client, username)

        if not result:
            glovar.usernames[username] = {}
            glovar.usernames[username]["peer_type"] = peer_type
            glovar.usernames[username]["peer_id"] = peer_id
            return peer_type, peer_id

        if isinstance(result, InputPeerChannel):
            peer_type = "channel"
            peer_id = result.channel_id
            peer_id = get_int(f"-100{peer_id}")
        elif isinstance(result, InputPeerUser):
            peer_type = "user"
            peer_id = result.user_id

        glovar.usernames[username] = {
            "peer_type": peer_type,
            "peer_id": peer_id
        }
    except Exception as e:
        logger.warning(f"Resolve username {username} error: {e}", exc_info=True)

    return peer_type, peer_id


@retry
def send_document(client: Client, cid: int, document: str, file_ref: str = None, caption: str = "", mid: int = None,
                  markup: Union[InlineKeyboardMarkup, ReplyKeyboardMarkup] = None) -> Union[bool, Message, None]:
    # Send a document to a chat
    result = None

    try:
        result = client.send_document(
            chat_id=cid,
            document=document,
            file_ref=file_ref,
            caption=caption,
            parse_mode="html",
            reply_to_message_id=mid,
            reply_markup=markup
        )
    except FloodWait as e:
        raise e
    except (ButtonDataInvalid, ButtonUrlInvalid):
        logger.warning(f"Send document {document} to {cid} - invalid markup: {markup}")
    except (ChannelInvalid, ChannelPrivate, ChatAdminRequired, PeerIdInvalid):
        return False
    except Exception as e:
        logger.warning(f"Send document {document} to {cid} error: {e}", exc_info=True)

    return result


@retry
def send_message(client: Client, cid: int, text: str, mid: int = None,
                 markup: Union[InlineKeyboardMarkup, ReplyKeyboardMarkup] = None) -> Union[bool, Message, None]:
    # Send a message to a chat
    result = None

    try:
        if not text.strip():
            return None

        result = client.send_message(
            chat_id=cid,
            text=text,
            parse_mode="html",
            disable_web_page_preview=True,
            reply_to_message_id=mid,
            reply_markup=markup
        )
    except FloodWait as e:
        raise e
    except (ButtonDataInvalid, ButtonUrlInvalid):
        logger.warning(f"Send message to {cid} - invalid markup: {markup}")
    except (ChannelInvalid, ChannelPrivate, ChatAdminRequired, PeerIdInvalid):
        return False
    except Exception as e:
        logger.warning(f"Send message to {cid} error: {e}", exc_info=True)

    return result
