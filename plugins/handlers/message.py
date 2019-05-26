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
from copy import deepcopy

from pyrogram import Client, Filters

from .. import glovar
from ..functions.etc import crypt_str, receive_data
from ..functions.file import save
from ..functions.filters import class_a, class_c, class_d, class_e, new_user, watch_ban, is_watch_message
from ..functions.user import terminate_watch_user

# Enable logging
logger = logging.getLogger(__name__)


@Client.on_message(Filters.incoming & Filters.group & ~class_a & ~class_c & ~class_d & ~class_e & ~watch_ban & new_user)
def check(client, message):
    try:
        watch_type = is_watch_message(client, message)
        if watch_type:
            terminate_watch_user(client, message, watch_type)
    except Exception as e:
        logger.warning(f"Check error: {e}", exc_info=True)


@Client.on_message(Filters.channel & ~Filters.command(glovar.all_commands, glovar.prefix))
def process_data(_, message):
    try:
        data = receive_data(message)
        if data:
            sender = data["from"]
            receivers = data["to"]
            action = data["action"]
            action_type = data["type"]
            data = data["data"]
            # This will look awkward,
            # seems like it can be simplified,
            # but this is to ensure that the permissions are clear,
            # so it is intentionally written like this
            if glovar.sender in receivers:
                if sender == "LANG":

                    if action == "add":
                        the_id = data["id"]
                        the_type = data["type"]
                        if action_type == "bad":
                            if the_type == "user":
                                glovar.bad_ids["users"].add(the_id)
                                save("bad_ids")
                        elif action_type == "watch":
                            until = int(crypt_str("decrypt", data["until"], glovar.key))
                            if the_type == "ban":
                                glovar.watch_ids["ban"][the_id] = until
                            elif the_type == "delete":
                                glovar.watch_ids["delete"][the_id] = until

                elif sender == "MANAGE":

                    if action == "add":
                        the_id = data["id"]
                        the_type = data["type"]
                        if action_type == "bad":
                            if the_type == "channel":
                                glovar.bad_ids["channels"].add(the_id)
                                save("bad_ids")
                        elif action_type == "except":
                            if the_type == "channel":
                                glovar.except_ids["channels"].add(the_id)
                            elif the_type == "user":
                                glovar.except_ids["users"].add(the_id)

                            save("except_ids")

                    elif action == "remove":
                        the_id = data["id"]
                        the_type = data["type"]
                        if action_type == "bad":
                            if the_type == "channel":
                                glovar.bad_ids["channels"].discard(the_id)
                            elif the_type == "user":
                                glovar.bad_ids["users"].discard(the_id)
                                glovar.watch_ids["ban"].pop(the_id, {})
                                glovar.watch_ids["delete"].pop(the_id, {})
                                if glovar.user_ids.get(the_id):
                                    glovar.user_ids[the_id] = deepcopy(glovar.default_user_status)

                                save("user_ids")

                            save("bad_ids")
                        elif action_type == "except":
                            if the_type == "channel":
                                glovar.except_ids["channels"].discard(the_id)
                            elif the_type == "user":
                                glovar.except_ids["users"].discard(the_id)

                            save("except_ids")
                        elif action_type == "watch":
                            if the_type == "all":
                                glovar.watch_ids["ban"].pop(the_id, 0)
                                glovar.watch_ids["delete"].pop(the_id, 0)

                elif sender == "NOFLOOD":

                    if action == "add":
                        the_id = data["id"]
                        the_type = data["type"]
                        if action_type == "bad":
                            if the_type == "user":
                                glovar.bad_ids["users"].add(the_id)
                                save("bad_ids")
                        elif action_type == "watch":
                            until = int(crypt_str("decrypt", data["until"], glovar.key))
                            if the_type == "ban":
                                glovar.watch_ids["ban"][the_id] = until
                            elif the_type == "delete":
                                glovar.watch_ids["delete"][the_id] = until

                elif sender == "NOPORN":

                    if action == "add":
                        the_id = data["id"]
                        the_type = data["type"]
                        if action_type == "bad":
                            if the_type == "user":
                                glovar.bad_ids["users"].add(the_id)
                                save("bad_ids")
                        elif action_type == "watch":
                            until = int(crypt_str("decrypt", data["until"], glovar.key))
                            if the_type == "ban":
                                glovar.watch_ids["ban"][the_id] = until
                            elif the_type == "delete":
                                glovar.watch_ids["delete"][the_id] = until

                elif sender == "NOSPAM":

                    if action == "add":
                        the_id = data["id"]
                        the_type = data["type"]
                        if action_type == "bad":
                            if the_type == "user":
                                glovar.bad_ids["users"].add(the_id)
                                save("bad_ids")
                        elif action_type == "watch":
                            until = int(crypt_str("decrypt", data["until"], glovar.key))
                            if the_type == "ban":
                                glovar.watch_ids["ban"][the_id] = until
                            elif the_type == "delete":
                                glovar.watch_ids["delete"][the_id] = until

                elif sender == "RECHECK":

                    if action == "add":
                        the_id = data["id"]
                        the_type = data["type"]
                        if action_type == "bad":
                            if the_type == "user":
                                glovar.bad_ids["users"].add(the_id)
                                save("bad_ids")
                        elif action_type == "watch":
                            until = int(crypt_str("decrypt", data["until"], glovar.key))
                            if the_type == "ban":
                                glovar.watch_ids["ban"][the_id] = until
                            elif the_type == "delete":
                                glovar.watch_ids["delete"][the_id] = until
    except Exception as e:
        logger.warning(f"Process data error: {e}", exc_info=True)
