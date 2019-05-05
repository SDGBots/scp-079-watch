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

from pyrogram import Client, Filters

from .. import glovar
from ..functions.etc import bold, thread, user_mention
from ..functions.filters import class_a
from ..functions.telegram import send_message

# Enable logging
logger = logging.getLogger(__name__)


@Client.on_message(Filters.incoming & Filters.group & class_a
                   & Filters.command(["version"], glovar.prefix))
def version(client, message):
    try:
        cid = message.chat.id
        aid = message.from_user.id
        mid = message.message_id
        text = (f"版本：{bold(glovar.version)}\n"
                f"管理员：{user_mention(aid)}\n")
        thread(send_message, (client, cid, text, mid))
    except Exception as e:
        logger.warning(f"Version error: {e}", exc_info=True)
