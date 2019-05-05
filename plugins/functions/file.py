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
from os.path import exists
from pickle import dump
from shutil import copyfile
from threading import Thread
from typing import Optional

from pyAesCrypt import decryptFile, encryptFile
from pyrogram import Client

from .. import glovar
from .etc import random_str
from .telegram import download_media

# Enable logging
logger = logging.getLogger(__name__)


def crypt_file(operation: str, file_in: str, file_out: str) -> bool:
    # Encrypt or decrypt a file
    try:
        buffer = 64 * 1024
        if operation == "decrypt":
            decryptFile(file_in, file_out, glovar.password, buffer)
        else:
            encryptFile(file_in, file_out, glovar.password, buffer)

        return True
    except Exception as e:
        logger.warning(f"Crypt file error: {e}", exc_info=True)

    return False


def get_downloaded_path(client: Client, file_id: str) -> Optional[str]:
    # Download file, get it's path on local machine
    final_path = None
    if file_id:
        try:
            file_path = get_new_path()
            final_path = download_media(client, file_id, file_path)
        except Exception as e:
            logger.warning(f"Get image path error: {e}", exc_info=True)

    return final_path


def get_new_path() -> str:
    # Get a new path in tmp directory
    file_path = random_str(8)
    while exists(f"tmp/{file_path}"):
        file_path = random_str(8)

    return f"tmp/{file_path}"


def save(file: str) -> bool:
    # Save a global variable to a file
    t = Thread(target=save_thread, args=(file,))
    t.start()

    return True


def save_thread(file: str) -> bool:
    try:
        if glovar:
            with open(f"data/.{file}", "wb") as f:
                dump(eval(f"glovar.{file}"), f)

            copyfile(f"data/.{file}", f"data/{file}")

        return True
    except Exception as e:
        logger.error(f"Save data error: {e}", exc_info=True)

    return False
