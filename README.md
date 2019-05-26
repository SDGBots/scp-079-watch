# SCP-079-WATCH

This bot is used to observe and track suspicious spam behaviors.

## How to use

See [this article](https://scp-079.org/watch/).

## To Do List

- [x] Basic functions

## Requirements

- Python 3.6 or higher.
- `requirements.txt` : APScheduler OpenCC Pillow pyAesCrypt pyrogram[fast]
- Ubuntu: `sudo apt update && sudo apt install caffe-cpu`

## Files

- plugins
    - functions
        - `channel.py` : Send messages to channel
        - `etc.py` : Miscellaneous
        - `file.py` : Save files
        - `filters.py` : Some filters
        - `group.py` : Functions about group
        - `ids.py` : Modify id lists
        - `image.py` : Functions about image
        - `telegram.py` : Some telegram functions
        - `timers.py` : Timer functions
        - `user.py` : Functions about user
    - handlers
        - `callback.py` : Handle callbacks
        - `command` : Handle commands
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

## License

Licensed under the terms of the [GNU General Public License v3](LICENSE).
