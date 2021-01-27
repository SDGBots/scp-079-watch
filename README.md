# SCP-079-WATCH

This bot is used to observe and track suspicious spam behaviors.

## How to use

- See [this article](https://scp-079.org/watch/) to build a bot by yourself
- Discuss [group](https://t.me/SCP_079_CHAT)

## To Do List

- [x] Basic functions

## Requirements

- Python 3.6 or higher
- Debian 10: `sudo apt update && sudo apt install libzbar0 opencc tesseract-ocr tesseract-ocr-chi-sim tesseract-ocr-chi-tra -y`
- pip: `pip install -r requirements.txt`
- or pip: `pip install -U APScheduler emoji guess_language-spirit langdetect OpenCC Pillow pyAesCrypt pyrogram[fast] pytesseract pyzbar textblob`

## Files

- plugins
    - functions
        - `channel.py` : Functions about channel
        - `etc.py` : Miscellaneous
        - `file.py` : Save files
        - `filters.py` : Some filters
        - `group.py` : Functions about group
        - `ids.py` : Modify id lists
        - `image.py` : Functions about image
        - `receive.py` : Receive data from exchange channel
        - `telegram.py` : Some telegram functions
        - `timers.py` : Timer functions
        - `user.py` : Functions about user and channel object
    - handlers
        - `message.py`: Handle messages
    - `glovar.py` : Global variables
- `.gitignore` : Ignore
- `config.ini.example` -> `config.ini` : Configuration
- `LICENSE` : GPLv3
- `main.py` : Start here
- `README.md` : This file
- `requirements.txt` : Managed by pip


## Contribute

Welcome to make this project even better. You can submit merge requests, or report issues.

## Credit

This is a fork (forked on 1/26/2021 PST) of the repo from scp-079 (https://github.com/scp-079) project.


## License

Licensed under the terms of the [GNU General Public License v3](LICENSE).
