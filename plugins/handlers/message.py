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
from ..functions.etc import get_full_name, get_now, thread
from ..functions.file import save
from ..functions.filters import class_c, class_d, class_e, declared_message, from_user, hide_channel, is_bio_text
from ..functions.filters import is_nm_text, is_declared_message, is_high_score_user, is_lang, is_watch_message
from ..functions.filters import is_watch_user, new_user, watch_ban
from ..functions.ids import init_user_id
from ..functions.receive import receive_add_bad, receive_add_except, receive_clear_data, receive_declared_message
from ..functions.receive import receive_regex, receive_remove_bad, receive_remove_except, receive_remove_score
from ..functions.receive import receive_remove_watch, receive_rollback, receive_status_ask, receive_text_data
from ..functions.receive import receive_user_score, receive_version_ask, receive_watch_user
from ..functions.timers import backup_files, send_count
from ..functions.user import terminate_user
from ..functions.telegram import get_user_bio

# Enable logging
logger = logging.getLogger(__name__)


@Client.on_message(Filters.incoming & Filters.group & ~Filters.service
                   & from_user & ~class_c & ~class_d & ~class_e & new_user & ~watch_ban
                   & ~declared_message)
def check(client: Client, message: Message) -> bool:
    # Check the messages sent from groups

    has_text = bool(message and (message.text or message.caption))

    if has_text:
        glovar.locks["text"].acquire()
    else:
        glovar.locks["message"].acquire()

    try:
        # Check declare status
        if is_declared_message(None, message):
            return True

        # Do not track again
        if is_watch_user(message.from_user, "ban"):
            return True

        # Check high score user
        if is_high_score_user(message.from_user):
            return True

        # Watch message
        content = get_content(message)
        detection = is_watch_message(client, message)
        if detection:
            result = terminate_user(client, message, detection)
            if result:
                glovar.contents[content] = detection
        elif message.sticker:
            if content:
                glovar.except_ids["temp"].add(content)
                save("except_ids")

        return True
    except Exception as e:
        logger.warning(f"Check error: {e}", exc_info=True)
    finally:
        if has_text:
            glovar.locks["text"].release()
        else:
            glovar.locks["message"].release()

    return False


@Client.on_message(Filters.incoming & Filters.group & Filters.new_chat_members
                   & from_user & ~class_c)
def check_join(client: Client, message: Message) -> bool:
    # Check new joined user
    glovar.locks["message"].acquire()
    try:
        # Basic data
        now = message.date or get_now()

        for new in message.new_chat_members:
            # Basic data
            uid = new.id

            # Check if the user is Class D personnel
            if uid in glovar.bad_ids["users"]:
                continue

            # Check if the user is bot
            if new.is_bot:
                continue

            # Work with NOSPAM and LANG
            name = get_full_name(new)
            if name and (is_nm_text(name) or is_lang("name", name)):
                continue

            bio = get_user_bio(client, uid, True)
            if bio and (is_bio_text(bio) or is_lang("bio", bio)):
                continue

            # Init the user's status
            if not init_user_id(uid):
                continue

            # Update the user's join status
            glovar.user_ids[uid]["join"] = now
            save("user_ids")

        return True
    except Exception as e:
        logger.warning(f"Check join error: {e}", exc_info=True)
    finally:
        glovar.locks["message"].release()

    return False


@Client.on_message(Filters.incoming & Filters.channel
                   & hide_channel)
def process_data(client: Client, message: Message) -> bool:
    # Process the data in exchange channel
    glovar.locks["receive"].acquire()
    try:
        data = receive_text_data(message)

        if not data:
            return True

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

            if sender == "CAPTCHA":

                if action == "update":
                    if action_type == "declare":
                        receive_declared_message(data)
                    elif action_type == "score":
                        receive_user_score(sender, data)

            if sender == "CLEAN":

                if action == "add":
                    if action_type == "bad":
                        receive_add_bad(sender, data)
                    elif action_type == "watch":
                        receive_watch_user(data)

                elif action == "update":
                    if action_type == "declare":
                        receive_declared_message(data)
                    elif action_type == "score":
                        receive_user_score(sender, data)

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
                    elif action_type == "score":
                        receive_user_score(sender, data)

            elif sender == "LONG":

                if action == "add":
                    if action_type == "bad":
                        receive_add_bad(sender, data)
                    elif action_type == "watch":
                        receive_watch_user(data)

                elif action == "update":
                    if action_type == "declare":
                        receive_declared_message(data)
                    elif action_type == "score":
                        receive_user_score(sender, data)

            elif sender == "MANAGE":

                if action == "add":
                    if action_type == "bad":
                        receive_add_bad(sender, data)
                    elif action_type == "except":
                        receive_add_except(client, data)

                elif action == "backup":
                    if action_type == "now":
                        thread(backup_files, (client,))
                    elif action_type == "rollback":
                        receive_rollback(client, message, data)

                elif action == "clear":
                    receive_clear_data(client, action_type, data)

                elif action == "remove":
                    if action_type == "bad":
                        receive_remove_bad(data)
                    elif action_type == "except":
                        receive_remove_except(client, data)
                    elif action_type == "score":
                        receive_remove_score(data)
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
                    elif action_type == "score":
                        receive_user_score(sender, data)

            elif sender == "NOPORN":

                if action == "add":
                    if action_type == "bad":
                        receive_add_bad(sender, data)
                    elif action_type == "watch":
                        receive_watch_user(data)

                elif action == "update":
                    if action_type == "declare":
                        receive_declared_message(data)
                    elif action_type == "score":
                        receive_user_score(sender, data)

            elif sender == "NOSPAM":

                if action == "add":
                    if action_type == "bad":
                        receive_add_bad(sender, data)
                    elif action_type == "watch":
                        receive_watch_user(data)

                elif action == "update":
                    if action_type == "declare":
                        receive_declared_message(data)
                    elif action_type == "score":
                        receive_user_score(sender, data)

            elif sender == "RECHECK":

                if action == "add":
                    if action_type == "bad":
                        receive_add_bad(sender, data)
                    elif action_type == "watch":
                        receive_watch_user(data)

                elif action == "update":
                    if action_type == "declare":
                        receive_declared_message(data)
                    elif action_type == "score":
                        receive_user_score(sender, data)

            elif sender == "REGEX":

                if action == "regex":
                    if action_type == "update":
                        receive_regex(client, message, data)
                    elif action_type == "count":
                        if data == "ask":
                            send_count(client)

        return True
    except Exception as e:
        logger.warning(f"Process data error: {e}", exc_info=True)
    finally:
        glovar.locks["receive"].release()

    return False
