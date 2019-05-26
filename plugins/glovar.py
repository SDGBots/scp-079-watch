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
import re
from configparser import RawConfigParser
from os import mkdir
from os.path import exists
from shutil import rmtree
from threading import Lock
from typing import Dict, List, Set

from .functions.etc import random_str

# Enable logging
logger = logging.getLogger(__name__)

# Init

all_commands: List[str] = ["status", "version"]

default_user_status: Dict[str, Set[int]] = {
    "ban": set(),
    "delete": set()
}

file_ids: Dict[str, Set[str]] = {
    "ban": set(),
    "delete": set()
}
# file_ids = {
#     "ban": {"file_id"},
#     "delete": {"file_id"}
# }

lock_image: Lock = Lock()

lock_text: Lock = Lock()

names: dict = {
    "ad": "广告用语",
    "ava": "头像分析",
    "bad": "敏感检测",
    "ban": "自动封禁",
    "bio": "简介封禁",
    "con": "联系方式",
    "del": "自动删除",
    "eme": "应急模式",
    "nm": "名称封禁",
    "wb": "追踪封禁",
    "wd": "追踪删除",
    "sti": "贴纸删除",
    "test": "测试用例"
}

receivers_status: List[str] = ["CAPTCHA", "CLEAN", "LANG", "NOFLOOD", "NOPORN", "NOSPAM", "MANAGE", "RECHECK"]

sender = "WATCH"

version: str = "0.0.3"

watch_ids: Dict[str, Dict[int, int]] = {
    "ban": {},
    "delete": {}
}
# watch_ids = {
#     "ban": {
#         12345678: 0
#     },
#     "delete": {
#         12345678: 0
#     }
# }

# Read data from config.ini

# [basic]
prefix: List[str] = []
prefix_str: str = "/!"

# [bots]
captcha_id: int = 0
clean_id: int = 0
lang_id: int = 0
noflood_id: int = 0
noporn_id: int = 0
nospam_id: int = 0
tip_id: int = 0
user_id: int = 0
warn_id: int = 0

# [channels]
hide_channel_id: int = 0
watch_channel_id: int = 0

# [custom]
image_size: int = 0
limit_ban: int = 0
limit_delete: int = 0
reset_day: str = ""
time_ban: int = 0
time_delete: int = 0
time_new: int = 0

# [encrypt]
key: str = ""
password: str = ""

# [o5]
o5_1_id: int = 0

try:
    config = RawConfigParser()
    config.read("config.ini")
    # [basic]
    prefix = list(config["basic"].get("prefix", prefix_str))
    # [bots]
    captcha_id = int(config["bots"].get("captcha_id", captcha_id))
    clean_id = int(config["bots"].get("clean_id", clean_id))
    lang_id = int(config["bots"].get("lang_id", lang_id))
    noflood_id = int(config["bots"].get("noflood_id", noflood_id))
    noporn_id = int(config["bots"].get("noporn_id", noporn_id))
    nospam_id = int(config["bots"].get("nospam_id", nospam_id))
    tip_id = int(config["bots"].get("tip_id", tip_id))
    user_id = int(config["bots"].get("user_id", user_id))
    warn_id = int(config["bots"].get("warn_id", warn_id))
    # [channels]
    hide_channel_id = int(config["channels"].get("hide_channel_id", hide_channel_id))
    watch_channel_id = int(config["channels"].get("watch_channel_id", watch_channel_id))
    # [custom]
    image_size = int(config["custom"].get("image_size", image_size))
    limit_ban = int(config["custom"].get("limit_ban", limit_ban))
    limit_delete = int(config["custom"].get("limit_delete", limit_delete))
    reset_day = config["custom"].get("reset_day", reset_day)
    time_ban = int(config["custom"].get("time_ban", time_ban))
    time_delete = int(config["custom"].get("time_delete", time_delete))
    time_new = int(config["custom"].get("time_new", time_new))
    # [encrypt]
    key = config["encrypt"].get("key", key)
    password = config["encrypt"].get("password", password)
    # [o5]
    o5_1_id = int(config["o5"].get("o5_1_id", o5_1_id))
except Exception as e:
    logger.warning(f"Read data from config.ini error: {e}", exc_info=True)

# Check
if (prefix == []
        or captcha_id == 0
        or clean_id == 0
        or lang_id == 0
        or noflood_id == 0
        or noporn_id == 0
        or nospam_id == 0
        or tip_id == 0
        or user_id == 0
        or warn_id == 0
        or hide_channel_id == 0
        or watch_channel_id == 0
        or image_size == 0
        or limit_ban == 0
        or limit_delete == 0
        or reset_day in {"", "[DATA EXPUNGED]"}
        or time_ban == 0
        or time_delete == 0
        or time_new == 0
        or key in {"", "[DATA EXPUNGED]"}
        or password in {"", "[DATA EXPUNGED]"}
        or o5_1_id == 0):
    raise SystemExit('No proper settings')

bot_ids: Set[int] = {captcha_id, clean_id, lang_id, noflood_id, noporn_id, nospam_id, user_id, warn_id}

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

except_ids: Dict[str, Set[int]] = {
    "channels": set(),
    "users": set()
}
# except_ids = {
#     "channels": {-10012345678},
#     "users": {12345678}
# }

new_user_ids: Dict[int, Set[int]] = {}
# new_user_ids = {
#     0: {12345678},
#     1: {12345679}
# }

for i in range(time_new):
    new_user_ids[i] = set()

user_ids: Dict[int, Dict[str, Set[int]]] = {}
# user_ids = {
#     12345678: {
#         "ban": set(),
#         "delete": set()
#     }
# }

# Init compiled variable

compiled: dict = {}
# compiled = {
#     "test": re.compile("test text", re.I | re.M | re.S)
# }

for word_type in names:
    compiled[word_type] = re.compile(fr"预留{names[f'{word_type}']}词组 {random_str(16)}", re.I | re.M | re.S)

# Init time data

time_now: int = 0

# Load data
file_list: List[str] = ["bad_ids", "compiled", "except_ids", "new_user_ids", "time_now", "user_ids"]
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
            logger.error(f"Load data {file} error: {e}")
            with open(f"data/.{file}", "rb") as f:
                locals()[f"{file}"] = pickle.load(f)
    except Exception as e:
        logger.critical(f"Load data {file} backup error: {e}")
        raise SystemExit("[DATA CORRUPTION]")

if time_now > time_new:
    time_now = 0
    with open("data/time_now", "wb") as f:
        pickle.dump(eval("time_now"), f)

if len(new_user_ids) > time_new:
    for i in range(time_new, len(new_user_ids)):
        new_user_ids.pop(i, set())
        with open("data/new_user_ids", "wb") as f:
            pickle.dump(eval("new_user_ids"), f)

# Start program
copyright_text = (f"SCP-079-{sender} v{version}, Copyright (C) 2019 SCP-079 <https://scp-079.org>\n"
                  "Licensed under the terms of the GNU General Public License v3 or later (GPLv3+)\n")
print(copyright_text)
