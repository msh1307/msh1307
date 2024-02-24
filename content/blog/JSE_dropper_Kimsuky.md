---
title: "Kimsuky malware analysis"
dateString: February 2024
draft: false
tags: ["Kimsuky malware","jse dropper"]
weight: 30
date: 2024-02-24
categories: ["Malware"]
# cover:
    # image: ""
---
# Overview
---

북한 Kimsuky 위협 그룹에서 외교부를 타겟으로 악성코드를 유포했다.

# Analysis
---
## Procmon
외교부가판2021-05-07로 유포되었고, .pdf.jse의 형태를 취하고 있었다.
vm안에서 실행하고 process create로 필터링해서 확인해보면, 
WScript.exe가 돌면서 프로세스를 생성한다.

![](/blog/Kimsuky_JSE_dropper/95bb593a80b9cb51ee57f5d7978dc7c5.png)
dll를 regsvr32.exe로 등록한다.
그냥 pdf viewer처럼 동작하면서 외교부가판 문서를 열어준다.
하지만 procmon으로 확인해보면 process create를 걸고 확인해보면 실제로는 WScript가 실행되면서 실제 악성코드를 드랍한다.
![](/blog/Kimsuky_JSE_dropper/8cacca08b7bb4088e86c62097281ce23.png)
regsvr32.exe로 악성 dll을 로드하고 실행 흐름이 넘어간다.
이러한 형태는 백신을 우회하기 위해 사용된다.
## Dll Extraction
```python
with open('./1.jse','rb') as f:
    buf = f.read(0x2000000)
st = buf[(buf.find(b'd6rdVIu1CNC = "')):]
st = (st[st.find(b'"')+1:])
dropped = st[:st.find(b'"')]
with open('./dropped_base','wb') as f:
    f.write(dropped)
with open('./dropped_base','rb') as f:
    buf = f.read(0x20000000)
import base64
dec = (base64.decodebytes(buf))
with open('./dropped','wb') as f:
    f.write(dec) # dropped pdf 


with open('./1.jse','rb') as f:
    buf = f.read(0x2000000)
st = buf[(buf.find(b'tbPaitkT4N4 =')):]
st = (st[st.find(b'"')+1:])
dropped = st[:st.find(b'"')]
with open('./dropped_dll_base','wb') as f:
    f.write(dropped)
with open('./dropped_dll_base','rb') as f:
    buf = f.read(0x200000000)

dec = base64.decodebytes((base64.decodebytes(buf)))
with open('./dropped_dll.dll','wb') as f:
    f.write(dec) # dropped pdf 

```
추출하면 악성 dll과 pdf를 얻을 수 있다.

## Reverse engineering
## regsvr32.exe
처음에 실행흐름을 프록시하기 위해서 regsvr32.exe를 호출했다.
악성 dll 분석 이전에 regsvr32.exe에서 어떤 함수를 호출하는지 확인했다.
![](/blog/Kimsuky_JSE_dropper/4a47a0db6e60853dedfcfdf08a5ca249.png)
DllRegisterServer 문자열을을 로드한다.

![](/blog/Kimsuky_JSE_dropper/fb5c81ed3a220004b71069645f112867.png)
![](/blog/Kimsuky_JSE_dropper/10fb15c77258a991b0028080a64fb42d.png)
메인 부분이다. 
실질적으로 DllRegisterServer를 호출한다.

## dropped_dll.dll
분석하다보면 다음과 같은 패턴이 보인다.
```c
  obj[2] = 0i64;
  obj[3] = 7i64;
  LOWORD(obj[0]) = 0;     
  sub_7FFF20E781A0(obj, L"651a77c90efb857ab62008a5a730e362365c52c9a23ec8c4001329a13434e5b6e3cc8b774885327ffaef", 84ui64);
  v1 = sub_7FFF20E8B330(obj, v30);
```
sub_7FFF20E781A0는 문자열을 할당한다.
실질적으로 실행되는 로직은 아래와 같다.
![](/blog/Kimsuky_JSE_dropper/09dd8c2662b96ce14928333f055c5580.png)

최종적으로 다음과 같은 구조를 가지게된다.
넘겨지는 size 별로 처리가 다르다. size가 7 이하라면, a\[0\], a\[1\] 영역에 바로 문자열을 쓴다.
더 크다면 아래와 같은 구조로 할당한다.
```
a[0] = str_mem
...
a[2] = sz
```
이후 sub_7FFF20E8B330을 호출한다.

실질적으로 여기서 디코딩을 수행한다.
![](/blog/Kimsuky_JSE_dropper/8266e4bfeda1bd42d8f9794eb4ea0a13.png)
처음에 0x10개의 wchar_t를 읽고 rot_hex에 저장한다.
문자열 size가 8 이상이면, \*obj를 문자열로 참조한다.
루프를 돌면서 hex_rot\[iterator%0x10\]^ \*obj\[iter\_\] ^ dec_16을 한다.
dec_16은 전에 참조한 hex가 들어간다.

### loader.cpp
```cpp
#include <iostream>
#include <Windows.h>
#include <cstdint>
#include <stdio.h>

void hexdump(void *ptr, int buflen) {
  unsigned char *buf = (unsigned char*)ptr;
  int i, j;
  for (i=0; i<buflen; i+=16) {
    printf("%06x: ", i);
    for (j=0; j<16; j++) 
      if (i+j < buflen)
        printf("%02x ", buf[i+j]);
      else
        printf("   ");
    printf(" ");
    for (j=0; j<16; j++) 
      if (i+j < buflen)
        printf("%c", isprint(buf[i+j]) ? buf[i+j] : '.');
    printf("\n");
  }
}
int main() {
    const char* libraryPath = ".\\dropped_dll.dll";

    HINSTANCE hDLL = LoadLibraryA(libraryPath);
    if (hDLL == NULL) {
        DWORD error = GetLastError();
        std::cerr << "failed to load dll. Error code: " << error << std::endl;
        return 1;
    }

    const char* functionName = "DllRegisterServer";

    typedef int64_t * (*f_type)(int64_t * a, int64_t * b);
    typedef int64_t * (*f_type1)(int64_t * a, wchar_t * src, int64_t sz);


    uint64_t v = reinterpret_cast<uint64_t>(GetProcAddress(hDLL, functionName));
    if (v == NULL) {
        std::cerr << "failed to get the function." << std::endl;
        FreeLibrary(hDLL);
        return 1;
    }
    uint64_t t =  v - (0x7FFBE99D8CA0-0x7FFBE99CB330);
    uint64_t t1 = v - (0x7FFBE99D8CA0-0x07FFBE99B81A0);

    std::cout << "DllRegisterServer addr: 0x" << std::hex << v << std::endl;
    std::cout << "enc addr: 0x" << std::hex << t << std::endl;
    std::cout << "prep addr: 0x" << std::hex << t1 << std::endl << std::endl;

    f_type dec = reinterpret_cast<f_type>(t);
    f_type1 prep = reinterpret_cast<f_type1>(t1);

    
    int64_t a[4];
    a[1] = 0;
    a[2] = 0;
    a[3] = 7;
    int64_t * ret = prep(a,L"651a77c90efb857ab62008a5a730e362365c52c9a23ec8c4001329a13434e5b6e3cc8b774885327ffaef", 84);
    std::cout << "ret[0] = " << std::hex << ret[0] << " -> ";
    std::wcout << (wchar_t *)ret[0] << std::endl;
    std::cout << "ret[1] = " << std::hex << ret[1] << std::endl;
    std::cout << "ret[2] = " << std::hex << ret[2] << std::endl;
    std::cout << "ret[3] = " << std::hex << ret[3] << std::endl;

    int64_t b[4];
    int x;
    std::cin >> x;
    int64_t * ret1 = dec(a,b);
    std::wcout << (wchar_t *)ret1[0] << std::endl;

    FreeLibrary(hDLL);

    return 0;
}
```
분석할때 문자열 decryption을 쉽게하려고 위와 같은 dll로더를 작성했다.
근데 생각보다 저런 패턴의 hex 문자열들이 너무 많아서 하나씩 돌리기엔 무리인것 같아서 idapython을 작성했다.
### decrypt.py
```python
def dec(v):
    rot_hex = []
    out = ''
    for i in range(16):
        rot_hex.append(int(v[i*2:i*2+2],16))
    x = 0
    for i in range((len(v)-32)//2):
        hex_ = int(v[i*2+0x20: i*2+0x22],16)
        res = rot_hex[i%0x10] ^ x ^ hex_
        out += chr(res)
        x = hex_
    return out
def is_hex(v):
    f = 1
    for i in range(len(v)):
        if v[i] not in '0123456789abcdef':
            f = 0
            break
    return f

from idautils import *
import idaapi, ida_ua, idc

def comment(ea,comment):
    cfunc = idaapi.decompile(ea)
    tl = idaapi.treeloc_t()
    tl.ea = ea
    tl.itp = idaapi.ITP_SEMI
    cfunc.set_user_cmt(tl, comment)
    cfunc.save_user_cmts()


target = 0x07FFF20E781A0
for xref in XrefsTo(target, 0):
    args = idaapi.get_arg_addrs(xref.frm)
    if args:
        insn = ida_ua.insn_t()
        ida_ua.decode_insn(insn, args[1])
        if insn.itype == 0x5c:
            wstr = idc.get_operand_value(insn.ea,1)
            t = idc.get_operand_type(insn.ea,1)
            if t == 2:
                sz = idc.get_operand_value(args[2],1)
                if sz == 0 or idc.get_operand_type(args[2],1) == 1: # r8d == 0
                    continue
                if sz > 0x20 and sz & 1 == 0:
                    continue
                v = ida_bytes.get_bytes(wstr, sz*2)
                estr = ''
                for i in range(sz):
                    estr += chr(v[2*i])
                if is_hex(estr):
                    comment(xref.frm, dec(estr))
print("done")
```
적용시키면 다음과 같이 주석으로 decrypt시 string을 보여준다.
![](/blog/Kimsuky_JSE_dropper/f19c9085129709ee14d013be869df69b.png)

### Behavior
![](/blog/Kimsuky_JSE_dropper/9eb9cd58b9ea5e04c890326b5c1f471f.png)
대부분의 중요한 API들은 string decryption이후 런타임에 동적으로 호출된다
![](/blog/Kimsuky_JSE_dropper/602e8f042f463dc47ebfdf6a94ed5a6d.png)
ESTCommon.dll을 준비하고, 문자열을 연결한다.
![](/blog/Kimsuky_JSE_dropper/7afbb1602613ec52b265d7a54ad27330.png)
![](/blog/Kimsuky_JSE_dropper/586e508f161f26ce94633729ac56c602.png)
이후 data에 이 스트링을 넣는다.

![](/blog/Kimsuky_JSE_dropper/59b2900aa03cb2182a51cdb520b535b6.png)
레지스트리키를 등록한다.
![](/blog/Kimsuky_JSE_dropper/9eb60bc8bf2b004e4db7d1cc0d5f1d8c.png)
이렇게 등록해놓고나서 KeyboardMonitor, ScreenMonitor, FolderMonitor, UsbMonitor 플래그를 쓴다.
![](/blog/Kimsuky_JSE_dropper/c00b57557743e709b8b96933432e0dfa.png)
![](/blog/Kimsuky_JSE_dropper/7b6fbd4c592d356e087a0f1053751007.png)
특정 파일에 a로 쓰는것을 확인할 수 있다.

![](/blog/Kimsuky_JSE_dropper/d642f8c3d2d6c1ab174d170d2dc8ed78.png)
뮤텍스를 생성해서 중복 실행을 방지한다.
![](/blog/Kimsuky_JSE_dropper/1e412544122065c25107eadecd8208c7.png)
마지막으로 여러 쓰레드를 생성한다.
#### Input Capture
![](/blog/Kimsuky_JSE_dropper/c9baca3cda1c39194c04fe2170c3da65.png)
log.txt에 저장하는것으로 보인다. 
![](/blog/Kimsuky_JSE_dropper/88399fdcf82e54c15ebbaabe86ff3e5e.png)
![](/blog/Kimsuky_JSE_dropper/ba6beb7ae28ef0a97d7a0a038feb5060.png)
![](/blog/Kimsuky_JSE_dropper/079f4fb55b755f6f198bee97d7c95390.png)
v2를 0~255까지 순회시키면서 입력을 캡쳐한다.
#### Screen Capture
![](/blog/Kimsuky_JSE_dropper/7134f8f5aced525d1c11d229063305e7.png)
계속 루프를 돈다.
![](/blog/Kimsuky_JSE_dropper/75c168b671d4ce827fca23907d85f114.png)capture 함수에서 캡쳐하고 비트맵으로 저장한다.
![](/blog/Kimsuky_JSE_dropper/7ae5e99a8c2f19cd25f44313293553aa.png)
#### Collect media files
![](/blog/Kimsuky_JSE_dropper/2484a7df36877a14689574eebda6dd7c.png)
![](/blog/Kimsuky_JSE_dropper/a969aaab995e4aaddbfe5fc3781fa63b.png)
![](/blog/Kimsuky_JSE_dropper/258f63b9448490d648948081e23d86db.png)
![](/blog/Kimsuky_JSE_dropper/fff5c6cf4ca1543a72b64bf5dff0d8ef.png)
Desktop, Downloads, Documents, INetCache\\IE 같은곳을 돈다.
![](/blog/Kimsuky_JSE_dropper/b9153260449b3690d1c2c5963a8cd00f.png)
파일을 찾아서 저장한다.
#### Collect removable media files
![](/blog/Kimsuky_JSE_dropper/5004a2bbca35d7d745207c2f34e2b909.png)
이런식으로 A부터 다 돌려보는식으로 체크한다.
![](/blog/Kimsuky_JSE_dropper/19ee203f0229aae4b91567bff25442e5.png)


