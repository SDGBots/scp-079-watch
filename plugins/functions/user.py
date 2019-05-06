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

from pyrogram import Client, Message

from .. import glovar
from .channel import share_watch_user
from .etc import crypt_str
from .ids import init_user_id

# Enable logging
logger = logging.getLogger(__name__)


def add_watch_count(watch_type: str, gid: int, uid: int) -> bool:
    # Change a user's watch count
    try:
        init_user_id(uid)
        glovar.user_ids[uid][watch_type].add(gid)
        if len(glovar.user_ids[uid][watch_type]) == eval(f"glovar.limit_{watch_type}"):
            return True
    except Exception as e:
        logger.warning(f"Add watch count error: {e}", exc_info=True)

    return False


def add_watch_user(client, watch_type: str, uid: int) -> bool:
    # Add watch user, and share it
    try:
        now = time()
        until = now + eval(f"glovar.time_{watch_type}")
        glovar.watch_ids[watch_type][uid] = until
        until = crypt_str("encrypt", until, glovar.key)
        share_watch_user(client, watch_type, uid, until)
        return True
    except Exception as e:
        logger.warning(f"Add watch user error: {e}", exc_info=True)

    return False


def terminate_watch_user(client: Client, message: Message, watch_type: str) -> bool:
    # Add user to watch list
    try:
        gid = message.chat.id
        uid = message.from_user.id
        should_watch = add_watch_count(watch_type, gid, uid)
        if should_watch:
            add_watch_user(client, watch_type, uid)

        return True
    except Exception as e:
        logger.warning(f"Terminate watch user error: {e}", exc_info=True)

    return False
