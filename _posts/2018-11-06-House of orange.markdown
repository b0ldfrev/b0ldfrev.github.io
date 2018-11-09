---
layout:     post
title:      "House of orange🍊"
subtitle:   "Overwrite TopChunk + Unsorted Bin Attack + Fsop"
date:       2018-11-06 12:00:00
author:     "Chris"
catalog: true
tags:
    - Pwn
    - 笔记
 
---

>为了学习"传说中"的House of orange🍊，我去把glibc源码的`malloc.c` `genops.c`关于内存分配和`I/O Operations`的源码研究了一下，梳理了整个流程，我把研究的一些细节的东西写下来，供分享。

## House of orange 概述

House of Orange 的利用比较特殊，首先需要目标漏洞是堆上的漏洞但是特殊之处在于题目中不存在 free 函数或其他释放堆块的函数。我们知道一般想要利用堆漏洞，需要对堆块进行 malloc 和 free 操作，但是在 House of Orange 利用中无法使用 free 函数，因此 House of Orange 核心就是通过漏洞利用获得 free 的效果。

## House of orange 原理

如我们前面所述，House of Orange 的核心在于在没有 free 函数的情况下得到一个释放的堆块 (unsorted bin)。 这种操作的原理简单来说是当前堆的 top chunk 尺寸不足以满足申请分配的大小的时候，原来的 top chunk 会被释放并被置入 unsorted bin 中，通过这一点可以在没有 free 函数情况下获取到 unsorted bins。

我们来看一下这个过程的详细情况，我们假设目前的 top chunk 已经不满足 malloc 的分配需求。 首先我们在程序中的malloc调用会执行到 libc.so 的`_int_malloc`函数中，在`int_malloc`函数中，会依次检验 fastbin、small bins、unsorted bin、large bins 是否可以满足分配要求，因为尺寸问题这些都不符合。接下来`_int_malloc`函数会试图使用 top chunk，在这里 top chunk 也不能满足分配的要求，因此会执行如下分支。

	/*
	Otherwise, relay to handle system-dependent cases
	*/
	else {
	      void *p = sysmalloc(nb, av);
	      if (p != NULL && __builtin_expect (perturb_byte, 0))
	    alloc_perturb (p, bytes);
	      return p;
	}

此时 ptmalloc 已经不能满足用户申请堆内存的操作，需要执行 sysmalloc 来向系统申请更多的空间。 但是对于堆来说有 mmap 和 brk 两种分配方式，我们需要让堆以 brk 的形式拓展，之后原有的 top chunk 会被置于 unsorted bin 中。


	if (av == NULL
	      || ((unsigned long) (nb) >= (unsigned long) (mp_.mmap_threshold)
	          && (mp_.n_mmaps < mp_.n_mmaps_max)))
	/*这里进行判断，判断分配的大小是否大于mmap分配的阀值，如果大于就是用mmap从新分配一个堆块，否则就会扩展top chunk*/
	    {
	    char *mm;           /* return value from mmap call*/
	    try_mmap:
	    .......

	    }

	.......
    brk = snd_brk = (char *) (MORECORE_FAILURE);
	assert ((old_top == initial_top (av) && old_size == 0) ||
	          ((unsigned long) (old_size) >= MINSIZE &&
	           prev_inuse (old_top) &&
	           ((unsigned long) old_end & (pagesize - 1)) == 0));
	
	/* Precondition: not enough current space to satisfy nb request */
	assert ((unsigned long) (old_size) < (unsigned long) (nb + MINSIZE));

综上，我们要实现 brk 拓展 top chunk，但是要实现这个目的需要绕过一些 libc 中的 check。 首先，malloc 的尺寸不能大于`mmp_.mmap_threshold`,使得top chunk以brk形式扩展。

后续检查`old_top_size`要求.

总结一下伪造的 top chunk size 的要求

* 伪造的 size 必须要对齐到内存页
* size 要大于 MINSIZE(0x10)
* size 要小于之后申请的 chunk size + MINSIZE(0x10)
* size 的 prev inuse 位必须为 1

之后原有的 top chunk 就会执行_int_free从而顺利进入 unsorted bin 中。

关于size对齐到页，可以这样理解，`top_chunk_addr` + `top_chunk_size` =Align [ 0x1000 (4kb) ]

比如，在覆盖之前 top chunk 的 size 大小是 20fe1，top chunk地址为0x602020，通过计算得知 0x602020+0x20fe0=0x623000 是对于 0x1000（4kb）对齐的。

在top chunk进入unsorted bin之后，我们就可以利用`unsorted bin attack`来修改`_IO_list_all`指向我们伪造的`_IO_FILE`，进入下一步攻击。关于`unsorted bin attack `的知识点,详见我的另一篇博文[https://sirhc.xyz/2018/09/06/Unsorted-Bin-Attack-%E7%AC%94%E8%AE%B0/](https://sirhc.xyz/2018/09/06/Unsorted-Bin-Attack-%E7%AC%94%E8%AE%B0/)

## glibc2.24以下的FSOP

这里简单介绍一下FSOP

FSOP 是 File Stream Oriented Programming 的缩写，根据前面对 FILE 的介绍得知进程内所有的`_IO_FILE` 结构会使用`_chain` 域相互连接形成一个链表，这个链表的头部由`_IO_list_all` 维护。

FSOP 的核心思想就是劫持`_IO_list_all` 的值来伪造链表和其中的`_IO_FILE` 项，但是单纯的伪造只是构造了数据还需要某种方法进行触发。FSOP 选择的触发方法是调用`_IO_flush_all_lockp`，这个函数会刷新`_IO_list_all` 链表中所有项的文件流，相当于对每个 FILE 调用 fflush，也对应着会调用`_IO_FILE_plus.vtable` 中的`_IO_overflow`。

这里随便贴一张`_IO_FILE`的结构，便于查看

![](/img/pic/house_of_orange/3.jpg)

我们的目标是触发`_IO_OVERFLOW`，下面是`_IO_flush_all_lockp`的源代码：


![](/img/pic/house_of_orange/1.jpg)

可以看出当`_IO_FILE`结构满足下面的条件：最外层（）里面的判断结果为ture时`（）&&_IO_OVERFLOW (fp, EOF)`才会被调用（&&有短路功能），转而通过`fp = fp->_chain`寻找新的`_IO_file`结构来使用。


	（
		(fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)

	       || (_IO_vtable_offset (fp) == 0
	           && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
	                    > fp->_wide_data->_IO_write_base)
	                     
	                    ）
	       
所以伪造的file结构体要通过的条件

	1.((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
	   
	或者是
	
	2._IO_vtable_offset (fp) == 0 
	&& fp->_mode > 0 
	&& (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base)

一般来说第一种比较好伪造,我的exp也是基于第一种的。



`_IO_flush_all_lockp `不需要攻击者手动调用，在一些情况下这个函数会被系统调用：

* 当 libc 执行 abort 流程时
* 当执行 exit 函数时
* 当执行流从 main 函数返回时

![](/img/pic/house_of_orange/2.jpg)

## hitcon-2016 相关PWN题

#### 代码分析

![](/img/pic/house_of_orange/4.jpg)

堆利用的题保护全开也不是什么见怪的....

程序有3个功能:

![](/img/pic/house_of_orange/5.jpg)

1.build功能代码如下：

![](/img/pic/house_of_orange/6.jpg)
![](/img/pic/house_of_orange/7.jpg)

2.see功能代码如下：

![](/img/pic/house_of_orange/8.jpg)

3.upgrade功能代码如下：

![](/img/pic/house_of_orange/9.jpg)

经分析，题目中创建了两种数据结构orange与house

	struct orange{
	  int price ;
	  int color ;
	};
	 
	struct house {
	  struct orange *org;
	  char *name ;
	};

题目中共分为4种操作

* build house  :
创建一个包含orange和name的house，其中orange 结构中包含其price与color
* see house  :
打印house的name与orange
* upgrade house  ：
更新house的信息，包括name与orange
* exit  ：
退出程序

其中build的操作限制次数为4次，upagrade的次数为3次。

漏洞：

在Upgrade中，重新输入house的name时没有判断大小，可能导致HeapOverflow

在输入name函数中,read在输入的字符串后没有加入’\0’可能导致信息泄露


![](/img/pic/house_of_orange/10.jpg)

#### 漏洞利用

我们在进行漏洞利用的时候会遇到以下困难：

* 使用House-Of-Force尝试去修改name指针，但是题目中限制了name的最大大小为0x1000，方案不可行。
* 题目中并没有进行free，所以尝试使用HeapOverflow溢出到name pointer必然会用到free后再malloc，方案不可行


官方的解决思路是利用House-Of-Orange
