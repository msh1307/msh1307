---
title: "Raspberry pi server setup"
dateString: January 2024
draft: false
tags: ["Raspberry pi"]
weight: 30
date: 2024-01-28
categories: ["ETC"]
# cover:
    # image: ""
---

# setup
## raspi-img & switch 
평소에 포트포워딩해서 개인 nas겸 CTF시 request bin 같은걸로 잘 쓰고 있었는데, 본딩을 설정하다가 서버가 죽어버렸다.
라즈베리파이 5도 구매해서 4랑 같이 처음부터 밀고 다시 세팅했다.
집에 굴러다니던 랜선과 스위치를 이용해서 기존에 WiFi로만 동작하던 서버를 이더넷이 끊켰을때만 WiFi를 사용하도록 바꿨다.
![](/blog/Raspberry_pi_setup/image.png)
스위치에다 연결했다. 

그리고 케이스 분해하기 귀찮아서 라즈베리파이 전원도 주고, usb 허브까지 꼽아서 ssd에 라즈베리파이 이미지를 덮었다.
![](/blog/Raspberry_pi_setup/image-1.png)
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
bantime = 3w``
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
![](/blog/Raspberry_pi_setup/image-2.png)
인터페이스 두개 MAC으로 dhcp ip를 고정시켜준다.
![](/blog/Raspberry_pi_setup/image-3.png)
그리고 포트 열어주면 된다.

## Cloudflare
![](/blog/Raspberry_pi_setup/image-4.png)
그리고 이제 네임서버 바꿔주고 A 레코드 DNS only로 서브도메인도 설정해줬다.
하나는 블로그라 깃허브로 연결되어있고, 서브도메인을 따로 두고 직접 라즈베리파이 서버로 들어가도록 했다.

## SSL
개인 nas처럼 쓰려는데 ssl을 자체적으로 지원은 안하는것 같아서 nginx로 프록시해서 ssl을 적용시켰다.
80번 포트 포트포워딩해주고, 설정해주면 된다.
```
sudo certbot
```
이후 서브도메인으로 주면 알아서 설정해준다.
/etc/nginx/sites-enabled/* 를 수정해준다.
을을
80번 포트는 proxy_pass로 https로 넘겨주게 설정했다.
```
    server_name raspi.msh1307.kr; # managed by Certbot

    location / {
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto $scheme;
      proxy_pass http://127.0.0.1:8080/;

      # First attempt to serve request as file, then
      # as directory, then fall back to displaying a 404.
      #try_files $uri $uri/ =404;
    }
```
cerbot이 자동으로 생성한 부분 조금 지워주고 수정하면 된다.

```
sudo nginx -t
sudo service nginx restart
```

그리고 crontab에 넣어서 자동으로 인증서를 갱신하게 해줄 수 있다.
```
00 02 * * 0 sudo certbot renew --quiet
```

