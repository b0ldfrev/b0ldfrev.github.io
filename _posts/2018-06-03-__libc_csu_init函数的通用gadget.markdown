---
layout:     post
title:      "__libc_csu_init函数的通用gadget"
subtitle:   "x64 ROP 笔记"
date:       2018-06-03 12:00:00
author:     "Chris"
catalog: true
tags:
    - Pwn
    - 笔记
 
---

## 0x00 简介

x86中参数都是保存在栈上,但在x64中前六个参数依次保存在RDI, RSI, RDX, RCX, R8和 R9寄存器里，如果还有更多的参数的话才会保存在栈上。这样传参就有点难受，但是程序在编译过程中会加入一些通用函数用来进行初始化操作（比如加载libc.so的初始化函数），所以虽然很多程序的源码不同，但是初始化的过程是相同的，因此针对这些初始化函数，我们可以提取一些通用的gadgets加以使用，从而达到我们想要达到的效果。

## 0x01 3参数

输入 **objdump -d 文件名** ：反汇编文件中的需要执行指令的那些section

找到 <__libc_csu_init>  -- 有以下代码

1.执行gad1

	.text:000000000040089A                 pop     rbx  必须为0
	.text:000000000040089B                 pop     rbp  必须为1
	.text:000000000040089C                 pop     r12  call（由于下面call指令的寻址方式为间接寻址，所以此处应为got表地址） 
	.text:000000000040089E                 pop     r13  arg3
	.text:00000000004008A0                 pop     r14  arg2
	.text:00000000004008A2                 pop     r15  arg1
	.text:00000000004008A4                 retn  ——> to gad2

2.再执行gad2

	.text:0000000000400880                 mov     rdx, r13
	.text:0000000000400883                 mov     rsi, r14
	.text:0000000000400886                 mov     edi, r15
	.text:0000000000400889                 call    qword ptr [r12+rbx*8] call 
	.text:000000000040088D                 add     rbx, 1
	.text:0000000000400891                 cmp     rbx, rbp
	.text:0000000000400894                 jnz     short loc_400880
	.text:0000000000400896                 add     rsp, 8
	.text:000000000040089A                 pop     rbx
	.text:000000000040089B                 pop     rbp
	.text:000000000040089C                 pop     r12
	.text:000000000040089E                 pop     r13
	.text:00000000004008A0                 pop     r14
	.text:00000000004008A2                 pop     r15
	.text:00000000004008A4                 retn ——> 构造一些垫板(7*8=56byte)就返回了

这样的话

	r13 =rdx =arg3
	r14 =rsi =arg2
	r15 =edi =arg1
	r12 =call address

## 0x02 1-2参数

还有一个老司机才知道的x64 gadgets，就是 pop rdi，ret的gadgets。这个gadgets还是在这里，但是是由opcode错位产生的。

如上的例子中4008A2、4008A4两句的字节码如下

	0x41 0x5f 0xc3

意思是pop r15，ret，但是恰好pop rdi，ret的opcode如下

	0x5f 0xc3

因此如果我们指向0x4008A3就可以获得pop rdi，ret的opcode，从而对于单参数函数可以直接获得执行，这是1个参数的情况。

 

与此类似的，还有0x4008A1处的 

	pop rsi，pop r15，ret

那么这个有什么用呢？我们知道x64传参顺序是rdi,rsi,rdx,rcx。

所以rsi是第二个参数，我们可以在rop中配合pop rdi,ret来使用pop rsi，pop r15,ret，这样就可以轻松的调用2个参数的函数。

 