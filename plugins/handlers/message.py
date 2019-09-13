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

from pyrogram import Client, Filters, Message

from .. import glovar
from ..functions.channel import get_content
from ..functions.etc import get_full_name, get_now
from ..functions.file import save
from ..functions.filters import class_c, class_d, class_e, declared_message, from_user, hide_channel, is_bio_text
from ..functions.filters import is_nm_text, is_declared_message, is_watch_message, is_watch_user, new_user, watch_ban
from ..functions.ids import init_user_id
from ..functions.receive import receive_add_bad, receive_add_except, receive_declared_message
from ..functions.receive import receive_regex, receive_remove_bad, receive_remove_except, receive_remove_watch
from ..functions.receive import receive_status_ask, receive_text_data, receive_version_ask, receive_watch_user
from ..functions.timers import send_count
from ..functions.user import terminate_user
from ..functions.telegram import get_user_bio

# Enable logging
logger = logging.getLogger(__name__)


@Client.on_message(Filters.incoming & Filters.group & from_user & ~Filters.service & ~watch_ban & new_user
                   & ~class_c & ~class_d & ~class_e & ~declared_message)
def check(client: Client, message: Message) -> bool:
    # Check the messages sent from groups
    if glovar.locks["message"].acquire():
        try:
            # Check declare status
            if is_declared_message(None, message):
                return True

            # Do not track again
            if is_watch_user(message, "ban"):
                return True

            # Watch message
            content = get_content(message)
            detection = is_watch_message(client, message)
            if detection:
                glovar.contents[content] = detection
                return terminate_user(client, message, detection)
            elif message.sticker:
                glovar.except_ids["temp"].add(content)
                save("except_ids")

            return True
        except Exception as e:
            logger.warning(f"Check error: {e}", exc_info=True)
        finally:
            glovar.locks["message"].release()

    return False


@Client.on_message(Filters.incoming & Filters.group & from_user & Filters.new_chat_members
                   & ~class_c)
def check_join(client: Client, message: Message) -> bool:
    # Check new joined user
    if glovar.locks["message"].acquire():
        try:
            for new in message.new_chat_members:
                uid = new.id

                # Check if the user is Class D personnel
                if uid in glovar.bad_ids["users"]:
                    continue

                if new.is_bot:
                    continue

                # Work with NOSPAM
                name = get_full_name(new)
                if name and is_nm_text(name):
                    continue

                bio = get_user_bio(client, new.username or new.id)
                if bio and is_bio_text(bio):
                    continue

                # Update user's join status
                if init_user_id(uid):
                    glovar.user_ids[uid]["join"] = get_now()
                    save("user_ids")

            return True
        except Exception as e:
            logger.warning(f"Check join error: {e}", exc_info=True)
        finally:
            glovar.locks["message"].release()

    return False


@Client.on_message(Filters.incoming & Filters.channel & hide_channel)
def process_data(client: Client, message: Message) -> bool:
    # Process the data in exchange channel
    try:
        data = receive_text_data(message)
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

                if sender == "CLEAN":

                    if action == "add":
                        if action_type == "bad":
                            receive_add_bad(sender, data)
                        elif action_type == "watch":
                            receive_watch_user(data)

                    elif action == "update":
                        if action_type == "declare":
                            receive_declared_message(data)

                elif sender == "HIDE":

                    if action == "version":
                        if action_type == "ask":
                            receive_version_ask(client, data)

                elif sender == "LANG":

                    if action == "add":
                        if action_type == "bad":
                            receive_add_bad(sender, data)
                        elif action_type == "watch":
                            receive_watch_user(data)

                    elif action == "update":
                        if action_type == "declare":
                            receive_declared_message(data)

                elif sender == "LONG":

                    if action == "add":
                        if action_type == "bad":
                            receive_add_bad(sender, data)
                        elif action_type == "watch":
                            receive_watch_user(data)

                    elif action == "update":
                        if action_type == "declare":
                            receive_declared_message(data)

                elif sender == "MANAGE":

                    if action == "add":
                        if action_type == "bad":
                            receive_add_bad(sender, data)
                        elif action_type == "except":
                            receive_add_except(client, data)

                    elif action == "remove":
                        if action_type == "bad":
                            receive_remove_bad(sender, data)
                        elif action_type == "except":
                            receive_remove_except(client, data)
                        elif action_type == "watch":
                            receive_remove_watch(data)

                    elif action == "status":
                        if action_type == "ask":
                            receive_status_ask(client, data)

                elif sender == "NOFLOOD":

                    if action == "add":
                        if action_type == "bad":
                            receive_add_bad(sender, data)
                        elif action_type == "watch":
                            receive_watch_user(data)

                    elif action == "update":
                        if action_type == "declare":
                            receive_declared_message(data)

                elif sender == "NOPORN":

                    if action == "add":
                        if action_type == "bad":
                            receive_add_bad(sender, data)
                        elif action_type == "watch":
                            receive_watch_user(data)

                    elif action == "update":
                        if action_type == "declare":
                            receive_declared_message(data)

                elif sender == "NOSPAM":

                    if action == "add":
                        if action_type == "bad":
                            receive_add_bad(sender, data)
                        elif action_type == "watch":
                            receive_watch_user(data)

                    elif action == "update":
                        if action_type == "declare":
                            receive_declared_message(data)

                elif sender == "RECHECK":

                    if action == "add":
                        if action_type == "bad":
                            receive_add_bad(sender, data)
                        elif action_type == "watch":
                            receive_watch_user(data)

                    elif action == "update":
                        if action_type == "declare":
                            receive_declared_message(data)

                elif sender == "REGEX":

                    if action == "regex":
                        if action_type == "update":
                            receive_regex(client, message, data)
                        elif action_type == "count":
                            if data == "ask":
                                send_count(client)

                elif sender == "USER":

                    if action == "remove":
                        if action_type == "bad":
                            receive_remove_bad(sender, data)

        return True
    except Exception as e:
        logger.warning(f"Process data error: {e}", exc_info=True)

    return False
