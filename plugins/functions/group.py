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
from typing import Optional

from pyrogram import Client
from pyrogram.types import Chat, ChatMember, Message

from .. import glovar
from .etc import t2t
from .ids import init_group_id
from .telegram import get_chat, get_chat_member, get_messages

# Enable logging
logger = logging.getLogger(__name__)


def get_description(client: Client, gid: int) -> str:
    # Get group's description
    result = ""
    try:
        group = get_group(client, gid)
        if group and group.description:
            result = t2t(group.description, False, False)
    except Exception as e:
        logger.warning(f"Get description error: {e}", exc_info=True)

    return result


def get_group(client: Client, gid: int, cache: bool = True) -> Optional[Chat]:
    # Get the group
    result = None
    try:
        the_cache = glovar.chats.get(gid)

        if the_cache:
            result = the_cache
        else:
            result = get_chat(client, gid)

        if cache and result:
            glovar.chats[gid] = result
    except Exception as e:
        logger.warning(f"Get group error: {e}", exc_info=True)

    return result


def get_group_sticker(client: Client, gid: int) -> str:
    # Get group sticker set name
    result = ""
    try:
        group = get_group(client, gid)
        if group and group.sticker_set_name:
            result = group.sticker_set_name
    except Exception as e:
        logger.warning(f"Get group sticker error: {e}", exc_info=True)

    return result


def get_member(client: Client, gid: int, uid: int, cache: bool = True) -> Optional[ChatMember]:
    # Get a member in the group
    result = None
    try:
        if not init_group_id(gid):
            return None

        the_cache = glovar.members[gid].get(uid)

        if the_cache:
            result = the_cache
        else:
            result = get_chat_member(client, gid, uid)

        if cache and result:
            glovar.members[gid][uid] = result
    except Exception as e:
        logger.warning(f"Get member error: {e}", exc_info=True)

    return result


def get_message(client: Client, gid: int, mid: int) -> Optional[Message]:
    # Get a single message
    result = None
    try:
        mids = [mid]
        result = get_messages(client, gid, mids)
        if result:
            result = result[0]
    except Exception as e:
        logger.warning(f"Get message error: {e}", exc_info=True)

    return result


def get_pinned(client: Client, gid: int) -> Optional[Message]:
    # Get group's pinned message
    result = None
    try:
        group = get_group(client, gid)
        if group and group.pinned_message:
            result = group.pinned_message
    except Exception as e:
        logger.warning(f"Get pinned error: {e}", exc_info=True)

    return result
