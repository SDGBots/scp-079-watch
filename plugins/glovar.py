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
from configparser import RawConfigParser
from os import mkdir
from os.path import exists
from shutil import rmtree
from threading import Lock
from typing import Dict, List, Set, Union

# Enable logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.WARNING,
    filename='log',
    filemode='w'
)
logger = logging.getLogger(__name__)

# Init

contents: Dict[str, str] = {}
# contents = {
#     "content": "wb"
# }

declared_message_ids: Dict[int, Set[int]] = {}
# declared_message_ids = {
#     -10012345678: {123}
# }

default_user_status: Dict[str, Union[int, str, Set[int]]] = {
    "join": 0,
    "type": "",
    "until": 0,
    "ban": set(),
    "delete": set()
}

locks: Dict[str, Lock] = {
    "message": Lock(),
    "regex": Lock()
}

names: dict = {
    "ban": "封禁追踪",
    "delete": "删除追踪"
}

receivers: Dict[str, List[str]] = {
    "version": ["HIDE"],
    "watch": ["ANALYZE", "CAPTCHA", "CLEAN", "LANG", "LONG",
              "NOFLOOD", "NOPORN", "NOSPAM", "MANAGE", "RECHECK", "WATCH"]
}

regex: Dict[str, bool] = {
    "ad": True,
    "aff": True,
    "ban": False,
    "bio": False,
    "con": True,
    "del": False,
    "iml": True,
    "nm": False,
    "sho": True,
    "spc": True,
    "spe": True,
    "tgl": True,
    "tgp": True,
    "wb": True,
    "wd": True
}

sender: str = "WATCH"

version: str = "0.0.4"

# Read data from config.ini

# [basic]
prefix: List[str] = []
prefix_str: str = "/!"

# [bots]
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
hide_channel_id: int = 0
watch_channel_id: int = 0

# [custom]
image_size: int = 0
lang_name: Union[str, Set[str]] = ""
lang_text: Union[str, Set[str]] = ""
limit_ban: int = 0
limit_delete: int = 0
reset_day: str = ""
time_ban: int = 0
time_delete: int = 0
time_new: int = 0

# [encrypt]
key: Union[str, bytes] = ""
password: str = ""

try:
    config = RawConfigParser()
    config.read("config.ini")
    # [basic]
    prefix = list(config["basic"].get("prefix", prefix_str))
    # [bots]
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
    hide_channel_id = int(config["channels"].get("hide_channel_id", hide_channel_id))
    watch_channel_id = int(config["channels"].get("watch_channel_id", watch_channel_id))
    # [custom]
    image_size = int(config["custom"].get("image_size", image_size))
    lang_name = config["custom"].get("lang_name", lang_name)
    lang_name = set(lang_name.split())
    lang_text = config["custom"].get("lang_text", lang_text)
    lang_text = set(lang_text.split())
    limit_ban = int(config["custom"].get("limit_ban", limit_ban))
    limit_delete = int(config["custom"].get("limit_delete", limit_delete))
    reset_day = config["custom"].get("reset_day", reset_day)
    time_ban = int(config["custom"].get("time_ban", time_ban))
    time_delete = int(config["custom"].get("time_delete", time_delete))
    time_new = int(config["custom"].get("time_new", time_new))
    # [encrypt]
    key = config["encrypt"].get("key", key)
    key = key.encode("utf-8")
    password = config["encrypt"].get("password", password)
except Exception as e:
    logger.warning(f"Read data from config.ini error: {e}", exc_info=True)

# Check
if (prefix == []
        or captcha_id == 0
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
        or hide_channel_id == 0
        or watch_channel_id == 0
        or image_size == 0
        or lang_name in {"", "[DATA EXPUNGED]"} or lang_name == set()
        or lang_text in {"", "[DATA EXPUNGED]"} or lang_text == set()
        or limit_ban == 0
        or limit_delete == 0
        or reset_day in {"", "[DATA EXPUNGED]"}
        or time_ban == 0
        or time_delete == 0
        or time_new == 0
        or key in {"", b"[DATA EXPUNGED]"}
        or password in {"", "[DATA EXPUNGED]"}):
    logger.critical("No proper settings")
    raise SystemExit("No proper settings")

bot_ids: Set[int] = {captcha_id, clean_id, lang_id, long_id,
                     noflood_id, noporn_id, nospam_id, recheck_id, tip_id, user_id, warn_id}

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
#     "long": {content},
#     "temp": {content}
# }

user_ids: Dict[int, Dict[str, Union[int, str, Set[int]]]] = {}
# user_ids = {
#     12345678: {
#         "join": 0,
#         "type": "",
#         "until": 0,
#         "ban": set(),
#         "delete": set()
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
            logger.error(f"Load data {file} error: {e}")
            with open(f"data/.{file}", "rb") as f:
                locals()[f"{file}"] = pickle.load(f)
    except Exception as e:
        logger.critical(f"Load data {file} backup error: {e}")
        raise SystemExit("[DATA CORRUPTION]")

# Start program
copyright_text = (f"SCP-079-{sender} v{version}, Copyright (C) 2019 SCP-079 <https://scp-079.org>\n"
                  "Licensed under the terms of the GNU General Public License v3 or later (GPLv3+)\n")
print(copyright_text)
