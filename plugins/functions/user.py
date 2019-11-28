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

from pyrogram import Client, Message, User

from .. import glovar
from .channel import forward_evidence, share_watch_user
from .etc import crypt_str, get_now, lang
from .file import save
from .filters import is_class_d, is_declared_message, is_watch_user
from .ids import init_user_id

# Enable logging
logger = logging.getLogger(__name__)


def add_watch_count(the_type: str, gid: int, user: User) -> bool:
    # Change a user's watch count
    try:
        # Basic data
        uid = user.id
        now = get_now()

        if not init_user_id(uid):
            return False

        glovar.user_ids[uid][the_type][gid] = now

        if len(glovar.user_ids[uid][the_type]) != eval(f"glovar.limit_{the_type}"):
            save("user_ids")
            return False

        if is_watch_user(user, the_type):
            save("user_ids")
            return False

        glovar.user_ids[uid]["type"] = the_type
        glovar.user_ids[uid][the_type] = {}

        if the_type == "ban":
            glovar.user_ids[uid]["delete"] = {}

        save("user_ids")

        return True
    except Exception as e:
        logger.warning(f"Add watch count error: {e}", exc_info=True)

    return False


def add_watch_user(client: Client, the_type: str, uid: int, mid: int) -> bool:
    # Add a watch ban user, share it
    try:
        # Basic data
        now = get_now()
        until = now + glovar.time_ban

        # Add locally
        glovar.user_ids[uid]["type"] = the_type
        glovar.user_ids[uid]["until"] = until

        # Share the user
        until = str(until)
        until = crypt_str("encrypt", until, glovar.key)
        share_watch_user(client, the_type, uid, until, mid)

        # Store the data
        save("user_ids")

        return True
    except Exception as e:
        logger.warning(f"Add watch user error: {e}", exc_info=True)

    return False


def terminate_user(client: Client, message: Message, the_type: str) -> bool:
    # Add user to watch list
    try:
        # Check if it is necessary
        if is_class_d(None, message) or is_declared_message(None, message):
            return False

        gid = message.chat.id
        uid = message.from_user.id
        the_type_list = the_type.split()
        the_type = the_type_list[0]

        if len(the_type_list) == 2:
            sticker_title = the_type_list[1]
        else:
            sticker_title = None

        should_watch = add_watch_count(the_type, gid, message.from_user)

        if not should_watch:
            return True

        result = forward_evidence(
            client=client,
            message=message,
            level=lang(the_type),
            more=sticker_title
        )
        if result:
            add_watch_user(client, the_type, uid, result.message_id)

        return True
    except Exception as e:
        logger.warning(f"Terminate watch user error: {e}", exc_info=True)

    return False
