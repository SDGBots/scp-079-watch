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
import pickle
from codecs import getdecoder
from configparser import RawConfigParser
from os import mkdir
from os.path import exists
from shutil import rmtree
from string import ascii_lowercase
from threading import Lock
from typing import Dict, List, Set, Union

from emoji import UNICODE_EMOJI
from pyrogram import Chat, ChatMember

# Enable logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.WARNING,
    filename="log",
    filemode="w"
)
logger = logging.getLogger(__name__)

# Read data from config.ini

# [bots]
avatar_id: int = 0
captcha_id: int = 0
clean_id: int = 0
lang_id: int = 0
long_id: int = 0
noflood_id: int = 0
noporn_id: int = 0
nospam_id: int = 0
recheck_id: int = 0
tip_id: int = 0
user_id: int = 0
warn_id: int = 0

# [channels]
debug_channel_id: int = 0
hide_channel_id: int = 0
watch_channel_id: int = 0

# [custom]
backup: Union[bool, str] = ""
date_reset: str = ""
image_size: int = 0
invalid: Union[str, Set[str]] = ""
lang_bio: Union[str, Set[str]] = ""
lang_name: Union[str, Set[str]] = ""
lang_protect: Union[str, Set[str]] = ""
lang_sticker: Union[str, Set[str]] = ""
lang_text: Union[str, Set[str]] = ""
limit_ban: int = 0
limit_delete: int = 0
project_link: str = ""
project_name: str = ""
time_ban: int = 0
time_delete: int = 0
time_new: int = 0
time_forgive: int = 0
zh_cn: Union[bool, str] = ""

# [emoji]
emoji_ad_single: int = 0
emoji_ad_total: int = 0
emoji_many: int = 0
emoji_protect: str = ""
emoji_wb_single: int = 0
emoji_wb_total: int = 0

# [encrypt]
key: Union[str, bytes] = ""
password: str = ""

try:
    config = RawConfigParser()
    config.read("config.ini")
    # [bots]
    avatar_id = int(config["bots"].get("avatar_id", avatar_id))
    captcha_id = int(config["bots"].get("captcha_id", captcha_id))
    clean_id = int(config["bots"].get("clean_id", clean_id))
    lang_id = int(config["bots"].get("lang_id", lang_id))
    long_id = int(config["bots"].get("long_id", long_id))
    noflood_id = int(config["bots"].get("noflood_id", noflood_id))
    noporn_id = int(config["bots"].get("noporn_id", noporn_id))
    nospam_id = int(config["bots"].get("nospam_id", nospam_id))
    recheck_id = int(config["bots"].get("recheck_id", recheck_id))
    tip_id = int(config["bots"].get("tip_id", tip_id))
    user_id = int(config["bots"].get("user_id", user_id))
    warn_id = int(config["bots"].get("warn_id", warn_id))
    # [channels]
    debug_channel_id = int(config["channels"].get("debug_channel_id", debug_channel_id))
    hide_channel_id = int(config["channels"].get("hide_channel_id", hide_channel_id))
    watch_channel_id = int(config["channels"].get("watch_channel_id", watch_channel_id))
    # [custom]
    backup = config["custom"].get("backup", backup)
    backup = eval(backup)
    date_reset = config["custom"].get("date_reset", date_reset)
    image_size = int(config["custom"].get("image_size", image_size))
    invalid = config["custom"].get("invalid", invalid)
    invalid = set(invalid.split())
    invalid = {i.lower() for i in invalid}
    lang_bio = config["custom"].get("lang_bio", lang_bio)
    lang_bio = set(lang_bio.split())
    lang_name = config["custom"].get("lang_name", lang_name)
    lang_name = set(lang_name.split())
    lang_protect = config["custom"].get("lang_protect", lang_protect)
    lang_protect = set(lang_protect.split())
    lang_sticker = config["custom"].get("lang_sticker", lang_sticker)
    lang_sticker = set(lang_sticker.split())
    lang_text = config["custom"].get("lang_text", lang_text)
    lang_text = set(lang_text.split())
    limit_ban = int(config["custom"].get("limit_ban", limit_ban))
    limit_delete = int(config["custom"].get("limit_delete", limit_delete))
    project_link = config["custom"].get("project_link", project_link)
    project_name = config["custom"].get("project_name", project_name)
    time_ban = int(config["custom"].get("time_ban", time_ban))
    time_delete = int(config["custom"].get("time_delete", time_delete))
    time_new = int(config["custom"].get("time_new", time_new))
    time_forgive = int(config["custom"].get("time_forgive", time_forgive))
    zh_cn = config["custom"].get("zh_cn", zh_cn)
    zh_cn = eval(zh_cn)
    # [emoji]
    emoji_ad_single = int(config["emoji"].get("emoji_ad_single", emoji_ad_single))
    emoji_ad_total = int(config["emoji"].get("emoji_ad_total", emoji_ad_total))
    emoji_many = int(config["emoji"].get("emoji_many", emoji_many))
    emoji_protect = getdecoder("unicode_escape")(config["emoji"].get("emoji_protect", emoji_protect))[0]
    emoji_wb_single = int(config["emoji"].get("emoji_wb_single", emoji_wb_single))
    emoji_wb_total = int(config["emoji"].get("emoji_wb_total", emoji_wb_total))
    # [encrypt]
    key = config["encrypt"].get("key", key)
    key = key.encode("utf-8")
    password = config["encrypt"].get("password", password)
except Exception as e:
    logger.warning(f"Read data from config.ini error: {e}", exc_info=True)

# Check
if (captcha_id == 0
        or avatar_id == 0
        or clean_id == 0
        or lang_id == 0
        or long_id == 0
        or noflood_id == 0
        or noporn_id == 0
        or nospam_id == 0
        or recheck_id == 0
        or tip_id == 0
        or user_id == 0
        or warn_id == 0
        or debug_channel_id == 0
        or hide_channel_id == 0
        or watch_channel_id == 0
        or backup not in {False, True}
        or date_reset in {"", "[DATA EXPUNGED]"}
        or image_size == 0
        or invalid in {"", "[DATA EXPUNGED]"} or invalid == set()
        or lang_bio in {"", "[DATA EXPUNGED]"} or lang_bio == set()
        or lang_name in {"", "[DATA EXPUNGED]"} or lang_name == set()
        or lang_protect in {"", "[DATA EXPUNGED]"} or lang_protect == set()
        or lang_sticker in {"", "[DATA EXPUNGED]"} or lang_sticker == set()
        or lang_text in {"", "[DATA EXPUNGED]"} or lang_text == set()
        or limit_ban == 0
        or limit_delete == 0
        or project_link in {"", "[DATA EXPUNGED]"}
        or project_name in {"", "[DATA EXPUNGED]"}
        or time_ban == 0
        or time_delete == 0
        or time_new == 0
        or time_forgive == 0
        or zh_cn not in {False, True}
        or emoji_ad_single == 0
        or emoji_ad_total == 0
        or emoji_many == 0
        or emoji_protect in {"", "[DATA EXPUNGED]"}
        or emoji_wb_single == 0
        or emoji_wb_total == 0
        or key in {b"", b"[DATA EXPUNGED]", "", "[DATA EXPUNGED]"}
        or password in {"", "[DATA EXPUNGED]"}):
    logger.critical("No proper settings")
    raise SystemExit("No proper settings")

# Languages
lang: Dict[str, str] = {
    # Admin
    "admin": (zh_cn and "管理员") or "Admin",
    "admin_group": (zh_cn and "群管理") or "Group Admin",
    "admin_project": (zh_cn and "项目管理员") or "Project Admin",
    # Basic
    "action": (zh_cn and "执行操作") or "Action",
    "clear": (zh_cn and "清空数据") or "Clear Data",
    "colon": (zh_cn and "：") or ": ",
    "comma": (zh_cn and "，") or ", ",
    "description": (zh_cn and "说明") or "Description",
    "disabled": (zh_cn and "禁用") or "Disabled",
    "enabled": (zh_cn and "启用") or "Enabled",
    "name": (zh_cn and "名称") or "Name",
    "reason": (zh_cn and "原因") or "Reason",
    "reset": (zh_cn and "重置数据") or "Reset Data",
    "rollback": (zh_cn and "数据回滚") or "Rollback",
    "score": (zh_cn and "评分") or "Score",
    "status_failed": (zh_cn and "未执行") or "Failed",
    "version": (zh_cn and "版本") or "Version",
    # More
    "privacy": (zh_cn and "可能涉及隐私而未转发") or "Not Forwarded Due to Privacy Reason",
    "cannot_forward": (zh_cn and "此类消息无法转发至频道") or "The Message Cannot be Forwarded to Channel",
    # Message Types
    "gam": (zh_cn and "游戏") or "Game",
    "ser": (zh_cn and "服务消息") or "Service",
    # Record
    "project": (zh_cn and "项目编号") or "Project",
    "project_origin": (zh_cn and "原始项目") or "Original Project",
    "status": (zh_cn and "状态") or "Status",
    "user_id": (zh_cn and "用户 ID") or "User ID",
    "level": (zh_cn and "操作等级") or "Level",
    "rule": (zh_cn and "规则") or "Rule",
    "message_type": (zh_cn and "消息类别") or "Message Type",
    "message_game": (zh_cn and "游戏标识") or "Game Short Name",
    "message_lang": (zh_cn and "消息语言") or "Message Language",
    "message_len": (zh_cn and "消息长度") or "Message Length",
    "message_freq": (zh_cn and "消息频率") or "Message Frequency",
    "user_score": (zh_cn and "用户得分") or "User Score",
    "user_bio": (zh_cn and "用户简介") or "User Bio",
    "user_name": (zh_cn and "用户昵称") or "User Name",
    "from_name": (zh_cn and "来源名称") or "Forward Name",
    "contact": (zh_cn and "联系方式") or "Contact Info",
    "more": (zh_cn and "附加信息") or "Extra Info",
    # Special
    "ban": (zh_cn and "封禁追踪") or "Ban Watch",
    "delete": (zh_cn and "删除追踪") or "Delete Watch",
    "new_user": (zh_cn and "新用户") or "New User",
    "suggest_ban": (zh_cn and "建议封禁") or "Suggest Ban",
    "suggest_delete": (zh_cn and "建议删除") or "Suggest Delete",
    "track_ban": (zh_cn and "观察封禁") or "Track Ban",
    "track_delete": (zh_cn and "观察删除") or "Track Delete"
}

# Init

bot_ids: Set[int] = {avatar_id, captcha_id, clean_id, lang_id, long_id, noflood_id,
                     noporn_id, nospam_id, recheck_id, tip_id, user_id, warn_id}

chats: Dict[int, Chat] = {}
# chats = {
#     -10012345678: Chat
# }

contents: Dict[str, str] = {}
# contents = {
#     "content": "wb"
# }

declared_message_ids: Dict[int, Set[int]] = {}
# declared_message_ids = {
#     -10012345678: {123}
# }

default_user_status: Dict[str, Union[int, str, Dict[int, int]]] = {
    "join": 0,
    "type": "",
    "until": 0,
    "ban": {},
    "delete": {}
}

emoji_set: Set[str] = set(UNICODE_EMOJI)

locks: Dict[str, Lock] = {
    "message": Lock(),
    "receive": Lock(),
    "regex": Lock(),
    "text": Lock()
}

members: Dict[int, Dict[int, ChatMember]] = {}
# members = {
#     -10012345678: {
#         12345678: ChatMember
#     }
# }

receivers: Dict[str, List[str]] = {
    "watch": ["ANALYZE", "CAPTCHA", "CLEAN", "LANG", "LONG",
              "MANAGE", "NOFLOOD", "NOPORN", "NOSPAM", "RECHECK", "WATCH"]
}

regex: Dict[str, bool] = {
    "ad": True,
    "aff": True,
    "ban": False,
    "bio": False,
    "con": True,
    "del": False,
    "fil": True,
    "iml": True,
    "pho": True,
    "nm": False,
    "sho": True,
    "spc": True,
    "spe": True,
    "sti": True,
    "tgl": True,
    "tgp": True,
    "wb": True,
    "wd": True
}
for c in ascii_lowercase:
    regex[f"ad{c}"] = True

sender: str = "WATCH"

sticker_titles: Dict[str, str] = {}
# sticker_titles = {
#     "short_name": "sticker_title"
# }

usernames: Dict[str, Dict[str, Union[int, str]]] = {}
# usernames = {
#     "SCP_079": {
#         "peer_type": "channel",
#         "peer_id": -1001196128009
#     }
# }

version: str = "0.1.0"

# Load data from pickle

# Init dir
try:
    rmtree("tmp")
except Exception as e:
    logger.info(f"Remove tmp error: {e}")

for path in ["data", "tmp"]:
    if not exists(path):
        mkdir(path)

# Init ids variables

bad_ids: Dict[str, Set[int]] = {
    "channels": set(),
    "users": set()
}
# bad_ids = {
#     "channels": {-10012345678},
#     "users": {12345678}
# }

except_ids: Dict[str, Set[Union[int, str]]] = {
    "channels": set(),
    "long": set(),
    "temp": set()
}
# except_ids = {
#     "channels": {-10012345678},
#     "long": {"content"},
#     "temp": {"content"}
# }

user_ids: Dict[int, Dict[str, Union[int, str, Dict[int, int]]]] = {}
# user_ids = {
#     12345678: {
#         "join": 0,
#         "type": "",
#         "until": 0,
#         "ban": {},
#         "delete": {
#             -10012345678: 1512345678
#         }
#     }
# }

# Init word variables

for word_type in regex:
    locals()[f"{word_type}_words"]: Dict[str, Dict[str, Union[float, int]]] = {}

# type_words = {
#     "regex": 0
# }

# Load data
file_list: List[str] = ["bad_ids", "except_ids", "user_ids"]
file_list += [f"{f}_words" for f in regex]
for file in file_list:
    try:
        try:
            if exists(f"data/{file}") or exists(f"data/.{file}"):
                with open(f"data/{file}", "rb") as f:
                    locals()[f"{file}"] = pickle.load(f)
            else:
                with open(f"data/{file}", "wb") as f:
                    pickle.dump(eval(f"{file}"), f)
        except Exception as e:
            logger.error(f"Load data {file} error: {e}", exc_info=True)
            with open(f"data/.{file}", "rb") as f:
                locals()[f"{file}"] = pickle.load(f)
    except Exception as e:
        logger.critical(f"Load data {file} backup error: {e}", exc_info=True)
        raise SystemExit("[DATA CORRUPTION]")

# Generate special characters dictionary
for special in ["spc", "spe"]:
    locals()[f"{special}_dict"]: Dict[str, str] = {}
    for rule in locals()[f"{special}_words"]:
        # Check keys
        if "[" not in rule:
            continue

        # Check value
        if "?#" not in rule:
            continue

        keys = rule.split("]")[0][1:]
        value = rule.split("?#")[1][1]
        for k in keys:
            locals()[f"{special}_dict"][k] = value

# Start program
copyright_text = (f"SCP-079-{sender} v{version}, Copyright (C) 2019 SCP-079 <https://scp-079.org>\n"
                  "Licensed under the terms of the GNU General Public License v3 or later (GPLv3+)\n")
print(copyright_text)
