---
title: DFIR Tools
description: A collection of tools used for DFIR
slug: dfir-tools
date: 2024-01-01 00:00:00+0000
image: image.png
categories:
    - tools
---

# Volatility 2

```bash
sudo apt install -y build-essential git libdistorm3-dev yara libraw1394-11 libcapstone-dev capstone-tool tzdata

sudo apt install -y python2 python2.7-dev libpython2-dev
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py
sudo python2 get-pip.py
sudo python2 -m pip install -U setuptools wheel

python2 -m pip install -U distorm3 yara pycrypto pillow openpyxl ujson pytz ipython capstone
sudo python2 -m pip install yara
sudo ln -s /usr/local/lib/python2.7/dist-packages/usr/lib/libyara.so /usr/lib/libyara.so
python2 -m pip install -U git+https://github.com/volatilityfoundation/volatility.git
```

Cheatsheet: https://blog.onfvp.com/post/volatility-cheatsheet/

# Volatility 3

```bash
sudo apt install -y build-essential git libdistorm3-dev yara libraw1394-11 libcapstone-dev capstone-tool tzdata

sudo apt install -y python3 python3-dev libpython3-dev python3-pip python3-setuptools python3-wheel

python3 -m pip install -U distorm3 yara pycrypto pillow openpyxl ujson pytz ipython capstone
python3 -m pip install -U git+https://github.com/volatilityfoundation/volatility3.git
```

# MFT Related

- **MFTECmd** -> https://download.ericzimmermanstools.com/MFTECmd.zip
- **MFTExplorer** -> https://download.ericzimmermanstools.com/net6/MFTExplorer.zip

# SQLite DB Browser

- https://sqlitebrowser.org/dl/
