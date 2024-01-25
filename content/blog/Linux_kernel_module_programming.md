---
title: "Linux kernel module programming"
description: "리눅스 커널 모듈 프로그래밍"
dateString: January 2023
draft: false
tags: ["kernel module programming", "Linux kernel module", "Linux kernel"]
weight: 100
cover:
    image: "/blog/Linux_kernel_module_programming/image.png"
---

# Kernel module?
모듈은 사용자의 혹은 커널의 요구로 읽혀지거나 아니면 없어지는 코드들로 이루어진 프로그램의 어떤 한 조각을 의미한다. 
커널은 하나의 큰 모듈들의 집합이라고 볼 수 있다. 
모듈들을 통해서 필요할때 더 추가, 혹은 제거를 통해서 커널을 재컴파일 혹은 재가동하지 않고도 커널의 기능을 확장하거나 축소시킬 수 있다.
# lsmod insmod rmmod
- `lsmod`를 통해서 현재 커널에 있는 모듈들의 정보를 확인할 수 있다. 
이때 lsmod는 `/proc/modules`를 읽고나서 좀 더 예쁘게 바꿔준다.
- `insmod`를 통해서 커널에 모듈을 적재할 수 있다.
- `rmmod`를 통해서 커널에 적재된 모듈을 제거할 수 있다.


# Hello World
```c
/*
* hello-1.c - The simplest kernel module.
*/
#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_INFO */
int init_module(void) { 
	printk(KERN_INFO "Hello world 1.\n");
	/*
	* A non 0 return means init_module failed; module can't be loaded. 
    */
	return 0;
}

void cleanup_module(void) {
	printk(KERN_INFO "Goodbye world 1.\n");
}
```
커널 모듈은 최소 두가지 함수를 갖추고 있어야 한다.
하나는 `init_module()`이고 또 하나는 `cleanup_module()`이다.
`init_module`은 `insmod`를 통해서 커널에 로딩될때 호출되는 초기화 함수이다.
`cleanup_module`은 `rmmod`를 통해서 모듈이 제거될때 호출되는 함수다.
이름과 상관없이 init, cleanup 함수를 작성할 수 있다. 뒤에서 더 알아볼 예정이다.


# printk, log level
printk()는 유저와 통신하기 위한 함수가 아니다.
이 함수가 호출되면 커널의 logging mechanism이 수행되고, 이 logging mechanism은 수행한 함수의 정보를 기록하거나 경고를 알린다.	
각각의 printk 선언은 우선순위를 통해서 제공되는데 그 우선순위는 아래와 같다.

<table class="docutils align-default">
<colgroup>
<col style="width: 23%">
<col style="width: 11%">
<col style="width: 66%">
</colgroup>
<thead>
<tr class="row-odd"><th class="head"><p>Name</p></th>
<th class="head"><p>String</p></th>
<th class="head"><p>Alias function</p></th>
</tr>
</thead>
<tbody>
<tr class="row-even"><td><p>KERN_EMERG</p></td>
<td><p>“0”</p></td>
<td><p><a class="reference internal" href="#c.pr_emerg" title="pr_emerg"><code class="xref c c-func docutils literal notranslate"><span class="pre">pr_emerg()</span></code></a></p></td>
</tr>
<tr class="row-odd"><td><p>KERN_ALERT</p></td>
<td><p>“1”</p></td>
<td><p><a class="reference internal" href="#c.pr_alert" title="pr_alert"><code class="xref c c-func docutils literal notranslate"><span class="pre">pr_alert()</span></code></a></p></td>
</tr>
<tr class="row-even"><td><p>KERN_CRIT</p></td>
<td><p>“2”</p></td>
<td><p><a class="reference internal" href="#c.pr_crit" title="pr_crit"><code class="xref c c-func docutils literal notranslate"><span class="pre">pr_crit()</span></code></a></p></td>
</tr>
<tr class="row-odd"><td><p>KERN_ERR</p></td>
<td><p>“3”</p></td>
<td><p><a class="reference internal" href="#c.pr_err" title="pr_err"><code class="xref c c-func docutils literal notranslate"><span class="pre">pr_err()</span></code></a></p></td>
</tr>
<tr class="row-even"><td><p>KERN_WARNING</p></td>
<td><p>“4”</p></td>
<td><p><a class="reference internal" href="#c.pr_warn" title="pr_warn"><code class="xref c c-func docutils literal notranslate"><span class="pre">pr_warn()</span></code></a></p></td>
</tr>
<tr class="row-odd"><td><p>KERN_NOTICE</p></td>
<td><p>“5”</p></td>
<td><p><a class="reference internal" href="#c.pr_notice" title="pr_notice"><code class="xref c c-func docutils literal notranslate"><span class="pre">pr_notice()</span></code></a></p></td>
</tr>
<tr class="row-even"><td><p>KERN_INFO</p></td>
<td><p>“6”</p></td>
<td><p><a class="reference internal" href="#c.pr_info" title="pr_info"><code class="xref c c-func docutils literal notranslate"><span class="pre">pr_info()</span></code></a></p></td>
</tr>
<tr class="row-odd"><td><p>KERN_DEBUG</p></td>
<td><p>“7”</p></td>
<td><p><a class="reference internal" href="#c.pr_debug" title="pr_debug"><code class="xref c c-func docutils literal notranslate"><span class="pre">pr_debug()</span></code></a> and <a class="reference internal" href="#c.pr_devel" title="pr_devel"><code class="xref c c-func docutils literal notranslate"><span class="pre">pr_devel()</span></code></a> if DEBUG is defined</p></td>
</tr>
<tr class="row-even"><td><p>KERN_DEFAULT</p></td>
<td><p>“”</p></td>
<td></td>
</tr>
<tr class="row-odd"><td><p>KERN_CONT</p></td>
<td><p>“c”</p></td>
<td><p><a class="reference internal" href="#c.pr_cont" title="pr_cont"><code class="xref c c-func docutils literal notranslate"><span class="pre">pr_cont()</span></code></a></p></td>
</tr>
</tbody>
</table>

따로 우선순위를 명시하지 않았다면, `DEFAULT_MESSAGE_LOGEVEL`이 사용된다.
`int_console_loglevel`에 따라서 더 높은 심각도, 즉 log level이 낮은 경우에 로그가 터미널에 출력된다.
```
cat /proc/sys/kernel/printk
```
다음을 통해서 현재 터미널의 `default log level`을 확인할 수 있다.
```
4       4       1       7
```
일반적으로 다음과 같은 결과가 나올텐데, 이때 가장 앞에 4가 `console_loglevel`이다.
`console log level`(여기선 4)보다 심각도가 높으면 콘솔에 출력된다.

# Kbuild
kbuild system은 리눅스 버젼 2.6.x대에 도입된 새로운 kernel build system이다. 
kbuild는 모든 복잡성을 숨길수 있는 간단한 하나의 makefile을 제공한다. 
이 makefile을 사용해서 make로 module을 build 할 수 있다.

## Goal
Goal을 정의하는 것은 Kbuild에서 가장 중요한 부분이다.
Goal은 build 과정을 통해 최종적으로 만들어져야 할 것, 컴파일 옵션, 사용되야하는 하위 디렉토리를 정의한다.
간단한 kbuild makefile의 일부를 확인해보면 아래와 같다.
```
obj-y += foo.o
```
위 구문이 의미하는 바는 디렉토리 내에 foo.o란 이름의 한개의 오브젝트가 있다는 것이다.
만약 모듈로 만든다면 obj-m이란 변수가 사용된다.
즉 아래와 같이 된다.
```
obj-$(CONFIG_FOO) += foo.o
```
`$(CONFIG_FOO)`는 `y(built-in)`나 `m(module)`의 값을 갖는다. 
만약 `CONFIG_FOO`가 y나 m의 값을 갖지 않는다면 이 파일은 컴파일되거나 링크되지 않는다.
# Kernel Module Compile
앞에 hello world 예제를 Makefile로 컴파일해보면 아래와 같다.
```
obj-m += hello-1.o
all:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
all과 clean은 단순 사용자의 편의를 위해 추가되었다고 볼 수 있다.
make로 컴파일을 하면, `.o`가 대체된 `.ko` 확장자를 가진 파일이 생긴다. 

`insmod`를 통해 해당 모듈을 적재할 수 있고, `rmmod`를 통해 제거할 수 있다.
`/var/log/messages`를 살펴보면, hello world 로그가 찍힌 것을 확인할 수 있다.

# Hello World - 2
init과 cleanup 함수를 재명명할 수 있다.
이때 `module_init`과 `module_exit` 매크로가 필요하다.
위 매크로들은 `linux/init.h`에 정의되어 있다.
예제는 다음과 같다.
```c
/*
* hello-2.c - Demonstrating the module_init() and module_exit() macros.
* This is preferred over using init_module() and cleanup_module().
*/
#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_INFO */
#include <linux/init.h> /* Needed for the macros */
static int __init hello_2_init(void)
{ 
	printk(KERN_INFO "Hello, world 2\n");
	return 0;
}
static void __exit hello_2_exit(void)
{ 
	printk(KERN_INFO "Goodbye, world 2\n");
}
module_init(hello_2_init);
module_exit(hello_2_exit);
```
# Modules VS Programs
프로그램들은 보통 Main 함수부터 시작된다. 
하지만 커널 모듈은 항상 `_init_module` 혹은 `module_init` 같은 함수의 호출로 시작된다.
위와 같은 함수들을 `entry function`이라고 부른다.
entry function은 모듈의 시작을 의미하는데, 기능적으로 모듈이 어떤 역할을 하는지, 필요로 할때 모듈이 작동될 수 있도록 커널을 설정하는 역할을 한다.

수행되고 나서 `cleanup_module` 혹은 `module_exit` 의 이름으로 사용자가 구체화한 함수의 호출을 통해 종료된다.
이와 같은 종료 함수는 `entry function`이 수행한 모든 기능들을 수행하기 전으로 되돌린다. 

# Functions available to modules
일반적으로 프로그램을 작성할때, `printf` 같은 자신이 정의하지 않은 라이브러리 함수를 사용한다.
이때 `printf` 같은 라이브러리 함수들은 나중에 사용되기 위해서 `linking`을 거치게 된다.

하지만 커널 모듈은 이런 부분에서 일반적인 프로그램과 다르다.
위에서 작성한 hello world 모듈을 예로 들어보면, `printk` 라는 라이브러리 함수를 사용했지만 실제로 `I/O library`를 include 하지 않았다.
그 이유는 모듈은 `insmod`가 수행되면서, `printk`와 같은 함수들의 symbol이 결정되는 object file이기 때문이다.
각 symbols의 함수적 정의는 커널이 제공한다.
이러한 symbol들은 `/proc/kallsyms`에서 확인할 수 있다.
# User Space VS Kernel Space
커널은 유저에게 자원에 대한 접근 권한을 부여하지 않는다.
다음 사진은 인텔 기준으로 총 4개의 ring이 있다.
OS가 CPU를 사용할때, 사용자가 CPU가 사용할때를 나눠놓았다.
별다른 의미는 없다.
![](/blog/Linux_kernel_module_programming/image1.png)
라이브러리 함수도 자원에 액세스해야할때는 Kernel에게 요청한다.
그 요청을 syscall이라고 한다.
syscall을 하면, Kernel에 그 syscall에 알맞는 처리를 해주고, 사용자에게 알려준다.
예를 들어 printf가 호출될때, printf는 format에 맞춘다던가 하는 처리를 해주고 결국 write syscall을 호출한다.
이때 커널이 superviser mode로 IO를 처리해주고, user mode로 돌아온다.
printf 함수를 일종의 거대한 wrapper로 볼 수 있다.
# Name Space
C 프로그램을 작성할때, 일반적으로 프로그래머는 가독성을 보장하는 변수를 사용한다.
만약 다른 사람의 전역변수에 해당하는 전역변수명을 재사용한다면, namespace pollution 문제가 생긴다. 

커널에서 아주 작은 모듈이라고 할지라도 작성된 모듈이 커널 전체에 linking 될텐데 위 문제를 고려한다면 이것은 분명히 주목할만한 문제가 된다.
위 문제점을 피하기 위한 가장 좋은 방법은, 프로그래머만의 잘 정의된 prefix를 사용하고, 모두 static으로 정의하는 것이다. 
# Code Space
프로세스가 만들어졌을때, 커널은 가상 메모리를 프로세스에게 할당한다.
그리고 프로세스를 위해 할당된 메모리 주소는 서로 겹치지 않는다. 
예를 들어 각각의 프로세스들이 0xbffff978 라는 주소에 접근할때 실제로 접근하는 물리적 메모리의 주소는 다르다.
일종의 offset 개념으로 위와 같은 주소를 사용한다.
대부분의 경우 프로세스는 다른 프로세스의 메모리 영역에 접근하지 못한다.

커널은 위 논리에 맞게 자신만의 메모리 영역을 가지고 있다.
모듈은 커널에 동적으로 탑재되고 제거될수 있으므로 각각의 모듈들은 자신만의 메모리보다 커널의 code space를 공유한다. 
그래서 만약 어떤 모듈이 segfault 같은 에러를 발생시킨다면, kernel panic이 발생하게 된다.

# Device drivers
드라이버는 모듈의 종류중 하나인데, 하드웨어를 위한 기능을 제공한다.
리눅스에서 VFS를 지원해서 통일되게 파일들을 다룰 수 있다.
각각의 하드웨어는 /dev에 위치해있는 파일 이름으로 나타내어질 수 있다.
VFS 덕분에 간단하게 파일을 다루듯이 read, write 등의 연산을 통해서 하드웨어를 컨트롤 할 수 있다.
![](/blog/Linux_kernel_module_programming/image2.png)
![](/blog/Linux_kernel_module_programming/image3.png)
application이 파일에 대한 IO를 수행하게 되면, 일반적으로 VFS는 inode 메타데이터를 확인해서 특정 파일시스템의 fops를 찾게 되며, 이 fops를 기반으로 read, write 등을 수행한다.
만약 device file이라면, major number를 통해 device driver를 찾는다.
이때 device driver의 초기화 과정에서 등록된 fops를 기반으로 호출하게 된다. 


## Major & Minor Numbers
다음 표는 3개의 IDE hard drive에 대한 정보가 나타나 있다.
```
# ls -l /dev/hda[1-3]
brw-rw---- 1 root disk 3, 1 Jul 5 2000 /dev/hda1
brw-rw---- 1 root disk 3, 2 Jul 5 2000 /dev/hda2
brw-rw---- 1 root disk 3, 3 Jul 5 2000 /dev/hda3
```
컴마 이후의 숫자는 장치의 `major number`를 나타낸다. 
두번째 번호는 `minor number`를 나타낸다. `major number`는 어떤 드라이버가 하드웨어에 접근하기 위해 사용되는가를 나타낸다. 

각각의 드라이버는 고유의 `major number`가 부여되어있다.
만약 모든 `major number`가 같다면, 해당 `major number`가 부여된 장치들은 모두 같은 드라이버에 의해 컨트롤 됨을 나타낸다.

`minor number`는 같은 드라이버에 의해 컨트롤되는 장치들을 구분하기 위한 용도로 사용된다.
## Device files
장치들은 두가지 타입 : `character device`와 `block device`로 나뉜다. 

block device와 character device의 가장 큰 차이점은 Application의 I/O 요구가 있을 시, 데이터를 File System에서 읽어오느냐 Character Device(Raw device)에서 읽어오느냐의 차이다.

`block device`는 `System Buffer`를 사용하여 블록이나 섹터 등의 정해진 단위로 데이터를 전송한다. 
hdd나 CD/DVD 같은 것들이 block device라고 볼 수 있다. 
I/O 전송 속도가 높은것이 특징이다.

`character device`는 block device와는 달리 buffer를 따로 사용하지 않는다. 
그래서 output이 block device에 비해서 유동적이다.
버퍼 처리를 Application이 제어해서 속도도 Application에 따라서 다를 수 있다.

```
# ls -l /dev/hda[1-3]
brw-rw---- 1 root disk 3, 1 Jul 5 2000 /dev/hda1
brw-rw---- 1 root disk 3, 2 Jul 5 2000 /dev/hda2
brw-rw---- 1 root disk 3, 3 Jul 5 2000 /dev/hda3
```
character device와 block device는 가장 앞에 문자를 보고 알 수 있다.
여기선 모두 b로 block device이다.
character device는 c로 표시된다.

시스템에 설치된 모든 device 파일들은 `mknod`를 통해 생성되었다.
major number가 12, minor number로 2를 가지는 coffee 라는 이름의 character device를 생성하기 위해서는 `mknod /dev/coffee c 12 2`를 입력하면 된다.
꼭 device file이 /dev에만 있어야 하는것은 아니지만 일반적으로 잘 관리하기 위해서 /dev에 많이 넣는다.

device file에 어떤 장치가 접근하려 할때, 커널은 device file의 `major number`를 사용해서 어떤 드라이버가 해당 `device file`에 대한 접근을 제어하기 위해서 사용되는지 판단한다.

즉, `minor number`는 커널에게 별 의미없는 숫자라고 말할 수 있다.
유일하게 드라이버가 minor number를 사용해 여러가지 하드웨어들을 구분한다.
여기서 하드웨어는 조금 추상적인 상태의 하드웨어를 의미한다.
다음 두개의 디바이스 파일을 살펴보자.
```
% ls -l /dev/fd0 /dev/fd0u1680
brwxrwxrwx 1 root floppy 2, 0 Jul 5 2000 /dev/fd0
brw-rw---- 1 root floppy 2, 44 Jul 5 2000 /dev/fd0u1680
```
하나의 플로피 디스크를 넣더라도, 위와 같은 결과가 나올것이다.
그 이유는 하나의 플로피 디스크가 두 개의 서로 다른 minor number를 가지고 있기 때문이다.
위 예시 때문에 조금 추상적인 상태의 하드웨어라고 언급한 것이다.

# file_operations structure
`file_operations` 구조체는 `/linux/fs.h`에 정의되어있다.
구조체의 각각의 부분은 드라이버가 정의한 어떤 함수들의 주소에 대응된다.

다음은 `file_operations` 구조체이다.
```c
struct file_operations {
    struct module *owner;
    loff_t (*llseek) (struct file *, loff_t, int);
    ssize_t (*read) (struct file *, char __user *, size_t, loff_t *);
    ssize_t (*write) (struct file *, const char __user *, size_t, loff_t *);
    ssize_t (*read_iter) (struct kiocb *, struct iov_iter *);
    ssize_t (*write_iter) (struct kiocb *, struct iov_iter *);
    int (*iterate) (struct file *, struct dir_context *);
    int (*iterate_shared) (struct file *, struct dir_context *);
    __poll_t (*poll) (struct file *, struct poll_table_struct *);
    long (*unlocked_ioctl) (struct file *, unsigned int, unsigned long);
    long (*compat_ioctl) (struct file *, unsigned int, unsigned long);
    int (*mmap) (struct file *, struct vm_area_struct *);
    unsigned long mmap_supported_flags;
    int (*open) (struct inode *, struct file *);
    int (*flush) (struct file *, fl_owner_t id);
    int (*release) (struct inode *, struct file *);
    int (*fsync) (struct file *, loff_t, loff_t, int datasync);
    int (*fasync) (int, struct file *, int);
    int (*lock) (struct file *, int, struct file_lock *);
    ssize_t (*sendpage) (struct file *, struct page *, int, size_t, loff_t *, int);
    unsigned long (*get_unmapped_area)(struct file *, unsigned long, unsigned long, unsigned long, unsigned long);
    int (*check_flags)(int);
    int (*setfl)(struct file *, unsigned long);
    int (*flock) (struct file *, int, struct file_lock *);
    ssize_t (*splice_write)(struct pipe_inode_info *, struct file *, loff_t *, size_t, unsigned int);
    ssize_t (*splice_read)(struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
    int (*setlease)(struct file *, long, struct file_lock **, void **);
    long (*fallocate)(struct file *file, int mode, loff_t offset,loff_t len);
    void (*show_fdinfo)(struct seq_file *m, struct file *f);
#ifndef CONFIG_MMU
    unsigned (*mmap_capabilities)(struct file *);
#endif
    ssize_t (*copy_file_range)(struct file *, loff_t, struct file *, loff_t, size_t, unsigned int);
    int (*clone_file_range)(struct file *, loff_t, struct file *, loff_t, u64);
    ssize_t (*dedupe_file_range)(struct file *, u64, u64, struct file *, u64);
} __randomize_layout;
```
드라이버가 구현하지 않는 몇몇 기능들도 존재한다.
그런 경우에는 진입점이 NULL로 세팅되어야 한다.
```c
struct file_operations fops = {
	.read = device_read,
	.write = device_write,
	.open = device_open,
	.release = device_release
};
```
위와 같은 방식으로 사용할 수 있다.
# file structure
각각의 디바이스들은 linux/fs.h에 정의된 커널의 file 구조체로 표현될 수 있다.
하지만 위의 구조체는 커널 수준에서 사용되므로 유저레벨의 사용 환경에선 확인할 수 없다.
file 구조체의 객체는 보통 flip라고 불린다.

# Registering a Device
시스템에 드라이버를 설치한다는 것은 커널에 등록을 해야한다는 것을 의미한다. 
이 말은 모듈의 초기화 동안 major number를 드라이버에 할당한다는 것과 같은 의미이다.

## register_chrdev()
register_chrdev 함수를 보면 다음과 같다.
```c
int register_chrdev(unsigned int major, const char *name, struct file_operations *fops);
```
커널에 디바이스 드라이버의 major number를 등록한다.

이때 `minor number`를 넘기지 않는 이유는 커널이 나중에 디바이스 파일을 이 major number를 보고 저기로 넘기기 때문이다.
minor number는 그냥 device files를 만들때 필요하다.
드라이버가 처리하기 위해 fops 등록하는 역할이다.

중복을 막기 위해서 `register_chrdev` 함수에 0을 전달하면, 커널은 동적으로 할당한 major number를 리턴한다. 

`register_chrdev()`대신 요즘엔 `register_chrdev_region`, `alloc_chrdev_region` 들을 써서 minor number도 미리 예약한다. 
device 파일을 만들려면 major, minor를 다 지정해서 `cdev_init`/`cdev_add` 혹은 `device_create`같은 애들을 사용해서 직접 디바이스 파일을 생성해도된다.
## dev_t
Device descriptor type. 
major, minor 번호가 조합되어있다.
```c
MAJOR(dev_t dev)
MINOR(dev_t dev)
MKDEV(int ma, int mi)
```
linux/kdev_t.h에서 정의된 매크로를 확인할 수 있다.
```c
#define MINORBITS       20
#define MINORMASK       ((1U << MINORBITS) - 1)

#define MAJOR(dev)      ((unsigned int) ((dev) >> MINORBITS))
#define MINOR(dev)      ((unsigned int) ((dev) & MINORMASK))
#define MKDEV(ma,mi)    (((ma) << MINORBITS) | (mi))
```
## cdev
커널 내부적으로 char dev 표현할때 쓰는 구조체이다.
```c
/* include/linux/cdev.h */
struct cdev {
	struct kobject kobj;
	struct module *owner;
	const struct file_operations *ops; /* 디바이스에서 정의된 file_operations */
	struct list_head list; /* cdev 리스트 */
	dev_t dev; /* 디바이스 번호 (주번호와 부번호가 각각 저장되어있음) */
	unsigned int count;
} __randomize_layout;
```
## alloc_chrdev_region()
`alloc_chrdev_region()` 은 동적으로 디바이스 번호 할당해주는 함수이다.
```c
int alloc_chrdev_region(dev_t *dev, unsigned int firstminor, unsigned int count, char* name)
```
원형은 위와 같다.
동적으로 할당해주기 때문에 미리 디바이스 파일을 못 만든다.
`/proc/devices` 읽고 major number 얻어서 자동으로 등록하는 스크립트를 통해서 해결할 수 있긴 하다.
## register_chrdev_region()
```c
int register_chrdev_region(dev_t first, unsigned int count, char *name);
```
`register_chrdev_region()` 함수는 디바이스 번호 알고있으면 쓰는 함수다.
## cdev_init()
```c
void cdev_init(struct cdev * cdev, const struct file_operations * fops);
```
cdev_init은 cdev 구조체 초기화 해주는 함수다.
## cdev_add()
```c
int cdev_add(struct cdev * p, dev_t dev, unsigned count);
```
cdev_add 함수는 디바이스를 등록해주는 함수다.

## class_create()
```c
struct class* class_create(struct module* owner, const char* name)
```
`class`는 디바이스의 그룹이다.
`/sys/class` 에서 클래스를 확인할 수 있다.
그룹을 나누기 위해 존재하는 것 같다.
## device_create()
```c
struct device* device_create(struct class* class, struct device parent, dev_t devt, const char* fmt, …)
```
장치를 생성한다.
/dev에 아직 디바이스 파일이 안생겼으니, `device_create` 함수로 디바이스 파일을 생성할 수 있다.

## THIS_MODULE
```c
#define THIS_MODULE (&__this_module)
```
이렇게 정의되어있다.
아래 모듈 구조체의 포인터라고 생각하면 된다.
```c
struct module {
	enum module_state state;

	/* Member of list of modules */
	struct list_head list;

	/* Unique handle for this module */
	char name[MODULE_NAME_LEN];

	/* Sysfs stuff. */
	struct module_kobject mkobj;
	struct module_attribute *modinfo_attrs;
	const char *version;
	const char *srcversion;
	struct kobject *holders_dir;

	/* Exported symbols */
	const struct kernel_symbol *syms;
	const s32 *crcs;
	unsigned int num_syms;

	/* Kernel parameters. */
#ifdef CONFIG_SYSFS
	struct mutex param_lock;
#endif
	struct kernel_param *kp;
	unsigned int num_kp;

	/* GPL-only exported symbols. */
	unsigned int num_gpl_syms;
	const struct kernel_symbol *gpl_syms;
	const s32 *gpl_crcs;

#ifdef CONFIG_UNUSED_SYMBOLS
	/* unused exported symbols. */
	const struct kernel_symbol *unused_syms;
	const s32 *unused_crcs;
	unsigned int num_unused_syms;

	/* GPL-only, unused exported symbols. */
	unsigned int num_unused_gpl_syms;
	const struct kernel_symbol *unused_gpl_syms;
	const s32 *unused_gpl_crcs;
#endif

#ifdef CONFIG_MODULE_SIG
	/* Signature was verified. */
	bool sig_ok;
#endif

	bool async_probe_requested;

	/* symbols that will be GPL-only in the near future. */
	const struct kernel_symbol *gpl_future_syms;
	const s32 *gpl_future_crcs;
	unsigned int num_gpl_future_syms;

	/* Exception table */
	unsigned int num_exentries;
	struct exception_table_entry *extable;

	/* Startup function. */
	int (*init)(void);

	/* Core layout: rbtree is accessed frequently, so keep together. */
	struct module_layout core_layout __module_layout_align;
	struct module_layout init_layout;

	/* Arch-specific module values */
	struct mod_arch_specific arch;

	unsigned long taints;	/* same bits as kernel:taint_flags */

#ifdef CONFIG_GENERIC_BUG
	/* Support for BUG */
	unsigned num_bugs;
	struct list_head bug_list;
	struct bug_entry *bug_table;
#endif

#ifdef CONFIG_KALLSYMS
	/* Protected by RCU and/or module_mutex: use rcu_dereference() */
	struct mod_kallsyms *kallsyms;
	struct mod_kallsyms core_kallsyms;

	/* Section attributes */
	struct module_sect_attrs *sect_attrs;

	/* Notes attributes */
	struct module_notes_attrs *notes_attrs;
#endif

	/* The command line arguments (may be mangled).  People like
	   keeping pointers to this stuff */
	char *args;

#ifdef CONFIG_SMP
	/* Per-cpu data. */
	void __percpu *percpu;
	unsigned int percpu_size;
#endif

#ifdef CONFIG_TRACEPOINTS
	unsigned int num_tracepoints;
	struct tracepoint * const *tracepoints_ptrs;
#endif
#ifdef HAVE_JUMP_LABEL
	struct jump_entry *jump_entries;
	unsigned int num_jump_entries;
#endif
#ifdef CONFIG_TRACING
	unsigned int num_trace_bprintk_fmt;
	const char **trace_bprintk_fmt_start;
#endif
#ifdef CONFIG_EVENT_TRACING
	struct trace_event_call **trace_events;
	unsigned int num_trace_events;
	struct trace_eval_map **trace_evals;
	unsigned int num_trace_evals;
#endif
#ifdef CONFIG_FTRACE_MCOUNT_RECORD
	unsigned int num_ftrace_callsites;
	unsigned long *ftrace_callsites;
#endif

#ifdef CONFIG_LIVEPATCH
	bool klp; /* Is this a livepatch module? */
	bool klp_alive;

	/* Elf information */
	struct klp_modinfo *klp_info;
#endif

#ifdef CONFIG_MODULE_UNLOAD
	/* What modules depend on me? */
	struct list_head source_list;
	/* What modules do I depend on? */
	struct list_head target_list;

	/* Destruction function. */
	void (*exit)(void);

	atomic_t refcnt;
#endif

#ifdef CONFIG_CONSTRUCTORS
	/* Constructor functions. */
	ctor_fn_t *ctors;
	unsigned int num_ctors;
#endif

#ifdef CONFIG_FUNCTION_ERROR_INJECTION
	struct error_injection_entry *ei_funcs;
	unsigned int num_ei_funcs;
#endif
} ____cacheline_aligned __randomize_layout;
```
다음과 같은 모듈 구조체를 가리킨다.
말 그대로 `THIS_MODULE`이다.

```c
#include <linux/module.h>
#include <linux/kernel.h>

static int myinit(void)
{
    /* Set by default based on the module file name. */
    pr_info("name    = %s\n", THIS_MODULE->name);
    pr_info("version = %s\n", THIS_MODULE->version);
    return 0;
}

static void myexit(void) {}

module_init(myinit)
module_exit(myexit)
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL");
```
이런식으로 `THIS_MODULE`을 쓸 수 있다.


# Example fops - open
```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/sched.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <asm/current.h>
#include <linux/uaccess.h>
 
#define DEVICE_NAME "chardev"
#define DEVICE_FILE_NAME "chardev"
#define MAJOR_NUM 100
 
static int chardev_open(struct inode *inode, struct file *file)
{
    printk("chardev_open");
    return 0;
}
 
struct file_operations chardev_fops = {
    .open    = chardev_open,
};
 
static int chardev_init(void)
{
    int ret_val;
    ret_val = register_chrdev(MAJOR_NUM, DEVICE_NAME, &chardev_fops);
 
    if (ret_val < 0) {
    printk(KERN_ALERT "%s failed with %d\n",
           "Sorry, registering the character device ", ret_val);
    return ret_val;
    }
 
    printk(KERN_INFO "%s The major device number is %d.\n",
       "Registeration is a success", MAJOR_NUM);
    printk(KERN_INFO "If you want to talk to the device driver,\n");
    printk(KERN_INFO "you'll have to create a device file. \n");
    printk(KERN_INFO "We suggest you use:\n");
    printk(KERN_INFO "mknod %s c %d 0\n", DEVICE_FILE_NAME, MAJOR_NUM);
    printk(KERN_INFO "The device file name is important, because\n");
    printk(KERN_INFO "the ioctl program assumes that's the\n");
    printk(KERN_INFO "file you'll use.\n");
 
    return 0;
}
 
static void chardev_exit(void)
{
    unregister_chrdev(MAJOR_NUM, DEVICE_NAME);
}
 
module_init(chardev_init);
module_exit(chardev_exit);
```
fops 구조체에 .open에 함수 주소를 따로 할당해놓고, device open시 커널 로그를 찍는 예제이다.


# Example fops - open, release, read, write
```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/sched.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <asm/current.h>
#include <linux/uaccess.h>
 
MODULE_LICENSE("Dual BSD/GPL");
 
#define DRIVER_NAME "chardev"
#define BUFFER_SIZE 256
     
static const unsigned int MINOR_BASE = 0;
static const unsigned int MINOR_NUM  = 2;
static unsigned int chardev_major;
static struct cdev chardev_cdev;
static struct class *chardev_class = NULL;
 
static int     chardev_open(struct inode *, struct file *);
static int     chardev_release(struct inode *, struct file *);
static ssize_t chardev_read(struct file *, char *, size_t, loff_t *);
static ssize_t chardev_write(struct file *, const char *, size_t, loff_t *);
 
struct file_operations chardev_fops = {
    .open    = chardev_open,
    .release = chardev_release,
    .read    = chardev_read,
    .write   = chardev_write,
};
 
struct data {
    unsigned char buffer[BUFFER_SIZE];
};
 
static int chardev_init(void)
{
    int alloc_ret = 0;
    int cdev_err = 0;
    int minor;
    dev_t dev;
 
    printk("The chardev_init() function has been called.");
     
    alloc_ret = alloc_chrdev_region(&dev, MINOR_BASE, MINOR_NUM, DRIVER_NAME);
    if (alloc_ret != 0) {
        printk(KERN_ERR  "alloc_chrdev_region = %d\n", alloc_ret);
        return -1;
    }
    //Get the major number value in dev.
    chardev_major = MAJOR(dev);
    dev = MKDEV(chardev_major, MINOR_BASE);
 
    //initialize a cdev structure
    cdev_init(&chardev_cdev, &chardev_fops);
    chardev_cdev.owner = THIS_MODULE;
 
    //add a char device to the system
    cdev_err = cdev_add(&chardev_cdev, dev, MINOR_NUM);
    if (cdev_err != 0) {
        printk(KERN_ERR  "cdev_add = %d\n", alloc_ret);
        unregister_chrdev_region(dev, MINOR_NUM);
        return -1;
    }
 
    chardev_class = class_create(THIS_MODULE, "chardev");
    if (IS_ERR(chardev_class)) {
        printk(KERN_ERR  "class_create\n");
        cdev_del(&chardev_cdev);
        unregister_chrdev_region(dev, MINOR_NUM);
        return -1;
    }
 
    for (minor = MINOR_BASE; minor < MINOR_BASE + MINOR_NUM; minor++) {
        device_create(chardev_class, NULL, MKDEV(chardev_major, minor), NULL, "chardev%d", minor);
    }
 
    return 0;
}
 
static void chardev_exit(void)
{
    int minor; 
    dev_t dev = MKDEV(chardev_major, MINOR_BASE);
     
    printk("The chardev_exit() function has been called.");
     
    for (minor = MINOR_BASE; minor < MINOR_BASE + MINOR_NUM; minor++) {
        device_destroy(chardev_class, MKDEV(chardev_major, minor));
    }
 
    class_destroy(chardev_class);
    cdev_del(&chardev_cdev);
    unregister_chrdev_region(dev, MINOR_NUM);
}
 
static int chardev_open(struct inode *inode, struct file *file)
{
    char *str = "helloworld";
    int ret;
 
    struct data *p = kmalloc(sizeof(struct data), GFP_KERNEL);
 
    printk("The chardev_open() function has been called.");
     
    if (p == NULL) {
        printk(KERN_ERR  "kmalloc - Null");
        return -ENOMEM;
    }
 
    ret = strlcpy(p->buffer, str, sizeof(p->buffer));
    if(ret > strlen(str)){
        printk(KERN_ERR "strlcpy - too long (%d)",ret);
    }
 
    file->private_data = p;
    return 0;
}
 
static int chardev_release(struct inode *inode, struct file *file)
{
    printk("The chardev_release() function has been called.");
    if (file->private_data) {
        kfree(file->private_data);
        file->private_data = NULL;
    }
    return 0;
}
 
static ssize_t chardev_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
    struct data *p = filp->private_data;
 
    printk("The chardev_write() function has been called.");   
    printk("Before calling the copy_from_user() function : %p, %s",p->buffer,p->buffer);
    if (copy_from_user(p->buffer, buf, count) != 0) {
        return -EFAULT;
    }
    printk("After calling the copy_from_user() function : %p, %s",p->buffer,p->buffer);
    return count;
}
 
static ssize_t chardev_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
    struct data *p = filp->private_data;
 
    printk("The chardev_read() function has been called.");
     
    if(count > BUFFER_SIZE){
        count = BUFFER_SIZE;
    }
 
    if (copy_to_user(buf, p->buffer, count) != 0) {
        return -EFAULT;
    }
 
    return count;
}
 
module_init(chardev_init);
module_exit(chardev_exit);
```
# IOCTL(input/output control)
read, write 오퍼레이션을 통한 읽기 쓰기는 가능할지 몰라도, 하드웨어 제어 및 상태 정보 확인은 불가능하다.
ioctl() 함수쓰면 하드웨어 제어가 가능하고, 상태 정보도 얻을 수 있다.

```c
#include <sys/ioctl.h>
int ioctl(int d, int request, ...);
```
첫번째 인자는 fd, 두번째 인자는 디바이스에게 전달할 명령이다.
개발자의 필요에 따라 추가적인 인자를 생성할 수 있다.

`/usr/include/asm/ioctl.h` 헤더파일에 ioctl의 커맨드 번호를 작성하는데 사용해야하는 매크로가 있다.
rw에 대한 정보를 담아서 고유한 ioctl 식별자를 만드는걸 도와주기 위한 매크로라고 생각하면 된다.

<div class="table-wrap"><table class="wrapped confluenceTable tablesorter tablesorter-default stickyTableHeaders" role="grid" resolved="" style="padding: 0px;"><colgroup><col><col></colgroup><thead class="tableFloatingHeaderOriginal"><tr role="row" class="tablesorter-headerRow"><th style="text-align: center; user-select: none;" class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="0" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Macro: No sort applied, activate to apply an ascending sort"><div class="tablesorter-header-inner">Macro</div></th><th style="text-align: center; user-select: none;" class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="1" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Description: No sort applied, activate to apply an ascending sort"><div class="tablesorter-header-inner">Description</div></th></tr></thead><thead class="tableFloatingHeader" style="display: none;"><tr role="row" class="tablesorter-headerRow"><th style="text-align: center; user-select: none;" class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="0" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Macro: No sort applied, activate to apply an ascending sort"><div class="tablesorter-header-inner">Macro</div></th><th style="text-align: center; user-select: none;" class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="1" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Description: No sort applied, activate to apply an ascending sort"><div class="tablesorter-header-inner">Description</div></th></tr></thead><tbody aria-live="polite" aria-relevant="all"><tr role="row"><td class="confluenceTd">_IO(int type, int number)</td><td class="confluenceTd">type, number 값만 전달하는 단순한 ioctl에 사용됩니다. </td></tr><tr role="row"><td class="confluenceTd">_IOR(int type, int number, data_type)&nbsp;</td><td class="confluenceTd">디바이스 드라이버에서&nbsp;데이터를 읽는 ioctl에 사용됩니다.</td></tr><tr role="row"><td class="confluenceTd">_IOW(int type, int number, data_type)</td><td class="confluenceTd"><span>디바이스 드라이버에서</span><span>&nbsp;데이터를 쓰는 ioctl에 사용됩니다.</span></td></tr><tr role="row"><td colspan="1" class="confluenceTd">_IORW(int type, int number, data_type)</td><td colspan="1" class="confluenceTd">디바이스 드라이버에서 데이터를 쓰고 읽는 ioctl에 사용됩니다.</td></tr></tbody></table></div>

- type
디바이스 드라이버에 할당된 8비트 정수이다.
- number
8비트 정수이다.
디바이스 드라이버내에서 서비스하는 서로 다른 종류의 ioctl 명령마다 각기 다른 고유번호를 가지고 있어야한다.
- data_type
클라이언트와 드라이버간에 교환되는 바이트 수를 계산하는 데 사용되는 유형 이름이다.

# Example ioctl
```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/sched.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <asm/current.h>
#include <linux/uaccess.h>
  
#include "chardev.h"
MODULE_LICENSE("Dual BSD/GPL");
  
#define DRIVER_NAME "chardev"
      
static const unsigned int MINOR_BASE = 0;
static const unsigned int MINOR_NUM  = 1;
static unsigned int chardev_major;
static struct cdev chardev_cdev;
static struct class *chardev_class = NULL;
 
static int     chardev_open(struct inode *, struct file *);
static int     chardev_release(struct inode *, struct file *);
static ssize_t chardev_read(struct file *, char *, size_t, loff_t *);
static ssize_t chardev_write(struct file *, const char *, size_t, loff_t *);
static long chardev_ioctl(struct file *, unsigned int, unsigned long);
 
struct file_operations s_chardev_fops = {
    .open    = chardev_open,
    .release = chardev_release,
    .read    = chardev_read,
    .write   = chardev_write,
    .unlocked_ioctl = chardev_ioctl,
};
 
static int chardev_init(void)
{
    int alloc_ret = 0;
    int cdev_err = 0;
    int minor = 0;
    dev_t dev;
  
    printk("The chardev_init() function has been called.");
      
    alloc_ret = alloc_chrdev_region(&dev, MINOR_BASE, MINOR_NUM, DRIVER_NAME);
    if (alloc_ret != 0) {
        printk(KERN_ERR  "alloc_chrdev_region = %d\n", alloc_ret);
        return -1;
    }
    //Get the major number value in dev.
    chardev_major = MAJOR(dev);
    dev = MKDEV(chardev_major, MINOR_BASE);
  
    //initialize a cdev structure
    cdev_init(&chardev_cdev, &s_chardev_fops);
    chardev_cdev.owner = THIS_MODULE;
  
    //add a char device to the system
    cdev_err = cdev_add(&chardev_cdev, dev, MINOR_NUM);
    if (cdev_err != 0) {
        printk(KERN_ERR  "cdev_add = %d\n", alloc_ret);
        unregister_chrdev_region(dev, MINOR_NUM);
        return -1;
    }
  
    chardev_class = class_create(THIS_MODULE, "chardev");
    if (IS_ERR(chardev_class)) {
        printk(KERN_ERR  "class_create\n");
        cdev_del(&chardev_cdev);
        unregister_chrdev_region(dev, MINOR_NUM);
        return -1;
    }
  
    device_create(chardev_class, NULL, MKDEV(chardev_major, minor), NULL, "chardev%d", minor);
    return 0;
}
  
static void chardev_exit(void)
{
    int minor = 0;
    dev_t dev = MKDEV(chardev_major, MINOR_BASE);
      
    printk("The chardev_exit() function has been called.");
 
    device_destroy(chardev_class, MKDEV(chardev_major, minor));
  
    class_destroy(chardev_class);
    cdev_del(&chardev_cdev);
    unregister_chrdev_region(dev, MINOR_NUM);
}
 
static int chardev_open(struct inode *inode, struct file *file)
{
    printk("The chardev_open() function has been called.");
    return 0;
}
  
static int chardev_release(struct inode *inode, struct file *file)
{
    printk("The chardev_close() function has been called.");
    return 0;
}
  
static ssize_t chardev_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
    printk("The chardev_write() function has been called.");  
    return count;
}
  
static ssize_t chardev_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
    printk("The chardev_read() function has been called.");
    return count;
}
  
static struct ioctl_info info;
static long chardev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    printk("The chardev_ioctl() function has been called.");
  
    switch (cmd) {
        case SET_DATA:
            printk("SET_DATA\n");
            if (copy_from_user(&info, (void __user *)arg, sizeof(info))) {
                return -EFAULT;
            }
        printk("info.size : %ld, info.buf : %s",info.size, info.buf);
            break;
        case GET_DATA:
            printk("GET_DATA\n");
            if (copy_to_user((void __user *)arg, &info, sizeof(info))) {
                return -EFAULT;
            }
            break;
        default:
            printk(KERN_WARNING "unsupported command %d\n", cmd);
  
        return -EFAULT;
    }
    return 0;
}
 
module_init(chardev_init);
module_exit(chardev_exit);
```
```c
#ifndef CHAR_DEV_H_
#define CHAR_DEV_H_
#include <linux/ioctl.h>
  
struct ioctl_info{
       unsigned long size;
       char buf[128];
};
   
#define             IOCTL_MAGIC         'G'
#define             SET_DATA            _IOW(IOCTL_MAGIC, 2 ,struct ioctl_info)
#define             GET_DATA            _IOR(IOCTL_MAGIC, 3 ,struct ioctl_info)
  
#endif
```
```
obj-m += chardev.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
유저모드에서 ioctl을 호출하면 `sys_ioctl`이 호출되고, fops에 등록된 `chardev_ioctl`이 최종적으로 호출된다.
테스트 코드는 다음과 같다.
```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include "chardev.h"
  
int main()
{
    int fd;
    struct ioctl_info set_info;
    struct ioctl_info get_info;
 
    set_info.size = 100;
    strncpy(set_info.buf,"lazenca.0x0",11);
 
    if ((fd = open("/dev/chardev0", O_RDWR)) < 0){
        printf("Cannot open /dev/chardev0. Try again later.\n");
    }
  
    if (ioctl(fd, SET_DATA, &set_info) < 0){
        printf("Error : SET_DATA.\n");
    }
 
 
    if (ioctl(fd, GET_DATA, &get_info) < 0){
        printf("Error : SET_DATA.\n");
    }
  
    printf("get_info.size : %ld, get_info.buf : %s\n", get_info.size, get_info.buf);
  
    if (close(fd) != 0){
        printf("Cannot close.\n");
    }
    return 0;
}
```