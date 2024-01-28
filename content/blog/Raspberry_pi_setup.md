---
title: "Raspberry pi server setup"
dateString: January 2024
draft: false
tags: ["Raspberry pi"]
weight: 30
date: 2024-01-29
categories: ["ETC"]
# cover:
    # image: ""
---

# setup
## raspi-img & switch 
평소에 포트포워딩해서 개인 nas겸 CTF시 request bin 같은걸로 잘 쓰고 있었는데, 본딩을 설정하다가 서버가 죽어버렸다.
라즈베리파이 5도 구매해서 4랑 같이 처음부터 밀고 다시 세팅했다.
집에 굴러다니던 랜선과 스위치를 이용해서 기존에 WiFi로만 동작하던 서버를 이더넷이 끊켰을때만 WiFi를 사용하도록 바꿨다.
![](image.png)
스위치에다 연결했다. 

그리고 케이스 분해하기 귀찮아서 라즈베리파이 전원도 주고, usb 허브까지 꼽아서 ssd에 라즈베리파이 이미지를 덮었다.
![](image-1.png)
## network interface
```bash
#!/bin/bash
if [ -z "$1" ]; then
  DELAY="30"
else
  DELAY="$1"
fi
sleep $DELAY

EthAddr=$(ip addr show eth0 | grep "inet\b" | awk '{print $2}' | cut -d/ -f1)
WiFiAddr=$(ip addr show wlan0 | grep "inet\b" | awk '{print $2}' | cut -d/ -f1)

if [ -z $EthAddr ]; then
  echo "Using WiFi"
  echo "wlan0 IP=$WiFiAddr"
else
  echo "Using Ethernet! Switching off WiFi"
  echo "eth0  IP=$EthAddr"
  echo "wlan0 IP=$WiFiAddr"
  ifconfig wlan0 down
fi
```
이렇게 작성해준다.
```bash
#!/bin/sh -e
#
# rc.local
#
# This script is executed at the end of each multiuser runlevel.
# Make sure that the script will "exit 0" on success or any other
# value on error.
#
# In order to enable or disable this script just change the execution
# bits.
#
# By default this script does nothing.
/home/msh/check_eth.sh &
# Print the IP address
_IP=$(hostname -I) || true
if [ "$_IP" ]; then
  printf "My IP address is %s\n" "$_IP"
fi

exit 0
```
그리고 /etc/rc.local에 등록해주면, 랜선이 꼽혀있는한 eth0 인터페이스만 활성화된다.
## auto reboot & fail2ban
```bash
00 00 * * * reboot
```
crontab -e로 넣어준다.

그리고 sudo apt install fail2ban 해주고 
```bash
[DEFAULT]
findtime = 1d
maxretry = 8
bantime = 3w
backend = systemd

ignoreip = 127.0.0.1/8 192.168.0.0/24

[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/fail2ban-ssh.log
```
/etc/fail2ban/jail.local을 세팅해준다.

## Port fowarding
![](image-2.png)
인터페이스 두개 MAC으로 dhcp ip를 고정시켜준다.
![](image-3.png)
그리고 포트 열어주면 된다.