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
from os import remove
from os.path import exists

from PIL import Image
from pyrogram import Message

from .. import glovar

# Enable logging
logger = logging.getLogger(__name__)


def get_color(image_path: str) -> bool:
    pass


def get_image_status(message: Message) -> dict:
    image = {
        "file_id": "",
        "ocr": False,
        "qrcode": False
    }
    try:
        if ((message.animation and message.animation.thumb)
                or (message.audio and message.audio.thumb)
                or (message.document and message.document.thumb)
                or message.photo
                or message.sticker
                or (message.video and message.video.thumb)
                or (message.video_note and message.video_note.thumb)):
            if message.animation:
                image["file_id"] = message.animation.thumb.file_id
            elif message.audio:
                image["file_id"] = message.audio.thumb.file_id
            elif message.document:
                if (message.document.mime_type
                        and "image" in message.document.mime_type
                        and "gif" not in message.document.mime_type
                        and message.document.file_size
                        and message.document.file_size <= glovar.image_size):
                    image["file_id"] = message.document.file_id
                    image["ocr"] = True
                    image["qrcode"] = True
                else:
                    image["file_id"] = message.document.thumb.file_id
            elif message.photo:
                image["file_id"] = message.photo.sizes[-1].file_id
                image["ocr"] = True
                image["qrcode"] = True
            elif message.sticker:
                image["file_id"] = message.sticker.file_id
                image["ocr"] = True
                image["qrcode"] = True
            elif message.video:
                image["file_id"] = message.video.thumb.file_id
            elif message.video_note:
                image["file_id"] = message.video_note.thumb.file_id
    except Exception as e:
        logger.warning(f"Get image status error: {e}", exc_info=True)

    return image


def get_ocr(image_path: str) -> str:
    pass


def get_qrcode(image_path: str) -> str:
    pass
