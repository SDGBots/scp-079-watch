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
from time import sleep, time
from typing import List, Optional, Union

from pyrogram import Client, Message
from pyrogram.errors import FloodWait

from .. import glovar
from .etc import code, format_data, thread
from .file import crypt_file
from .telegram import send_document, send_message


# Enable logging
logger = logging.getLogger(__name__)


def forward_evidence(client: Client, message: Message, level: str) -> Optional[Union[bool, int]]:
    # Forward the message to logging channel as evidence
    result = None
    try:
        uid = message.from_user.id
        flood_wait = True
        while flood_wait:
            flood_wait = False
            try:
                result = message.forward(glovar.watch_channel_id)
            except FloodWait as e:
                flood_wait = True
                sleep(e.x + 1)
            except Exception as e:
                logger.info(f"Forward evidence message error: {e}", exc_info=True)
                return False

        result = result.message_id
        text = (f"用户 ID：{code(uid)}\n"
                f"操作等级：{code(level)}\n")
        thread(send_message, (client, glovar.watch_channel_id, text, result))
    except Exception as e:
        logger.warning(f"Forward evidence error: {e}", exc_info=True)

    return result


def share_data(client: Client, receivers: List[str], action: str, action_type: str, data: Union[dict, int, str],
               file: str = None) -> bool:
    # Use this function to share data in hide channel
    try:
        if glovar.sender in receivers:
            receivers.remove(glovar.sender)

        if file:
            text = format_data(
                sender=glovar.sender,
                receivers=receivers,
                action=action,
                action_type=action_type,
                data=data
            )
            crypt_file("encrypt", f"data/{file}", f"tmp/{file}")
            thread(send_document, (client, glovar.hide_channel_id, f"tmp/{file}", text))
        else:
            text = format_data(
                sender=glovar.sender,
                receivers=receivers,
                action=action,
                action_type=action_type,
                data=data
            )
            thread(send_message, (client, glovar.hide_channel_id, text))

        return True
    except Exception as e:
        logger.warning(f"Share data error: {e}", exc_info=True)

    return False


def share_watch_user(client: Client, uid: int, watch_type: str) -> bool:
    # Share a watch user with other bots
    try:
        now = time()
        if watch_type == "ban":
            until = now + glovar.time_ban
        else:
            until = now + glovar.time_delete

        share_data(
            client=client,
            receivers=glovar.receivers_status,
            action="add",
            action_type="watch",
            data={
                "id": uid,
                "type": watch_type,
                "until": until
            }
        )
        return True
    except Exception as e:
        logger.warning(f"Share watch user error: {e}", exc_info=True)
