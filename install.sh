#!/bin/bash

# RPanel Install Script
# این اسکریپت برای نصب و راه‌اندازی RPanel استفاده می‌شود.
# لطفاً قبل از اجرا، اسکریپت را بررسی و از صحت دسترسی‌ها اطمینان حاصل کنید.
# تاریخ: 2025-06-15
# نویسنده: تیم توسعه RPanel
# هشدار: اجرای این اسکریپت با دسترسی root انجام شود و از صحت سورس اطمینان حاصل کنید.

#By setting DEBIAN_FRONTEND to noninteractive, any prompts or interactive dialogs from the package manager will proceed with the installation without user intervention.
export DEBIAN_FRONTEND=noninteractive
config_file="/etc/needrestart/needrestart.conf"
# Check if the configuration file exists
if [ -f "$config_file" ]; then
    # Disable "Pending kernel upgrade" popup during install
    sed -i "s/#\$nrconf{kernelhints} = -1;/\$nrconf{kernelhints} = -1;/g" "$config_file"

    # Disable "Daemons using outdated libraries" popup during install
    sudo sed -i 's/#$nrconf{restart} = '"'"'i'"'"';/$nrconf{restart} = '"'"'a'"'"';/g' "$config_file"
fi
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
CYAN="\e[36m"
ENDCOLOR="\e[0m"

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit
fi
ENV_FILE="/var/www/html/app/.env"
COPY_FILE="/var/www/html/.env_copy"

if [ -f "$ENV_FILE" ]; then
  cp "$ENV_FILE" "$COPY_FILE"
  chmod 644 /var/www/html/.env_copy
fi
# تابع بررسی سیستم عامل
checkOS() {
  # List of supported distributions
  #supported_distros=("Ubuntu" "Debian" "Fedora" "CentOS" "Arch")
  supported_distros=("Ubuntu")
  # Get the distribution name and version
  if [[ -f "/etc/os-release" ]]; then
    source "/etc/os-release"
    distro_name=$NAME
    distro_version=$VERSION_ID
  else
    echo "Unable to determine distribution."
    exit 1
  fi
  # Check if the distribution is supported
  if [[ " ${supported_distros[@]} " =~ " ${distro_name} " ]]; then
    echo "Your Linux distribution is ${distro_name} ${distro_version}"
    : #no-op command
  else
    # Print error message in red
    echo -e "\e[31mYour Linux distribution (${distro_name} ${distro_version}) is not currently supported.\e[0m"
    exit 1
  fi

  # This script only works on Ubuntu 20 and above
  if [ "$(uname)" == "Linux" ]; then
    version_info=$(lsb_release -rs | cut -d '.' -f 1)
    # Check if it's Ubuntu and version is below 20
    if [ "$(lsb_release -is)" == "Ubuntu" ] && [ "$version_info" -lt 20 ]; then
      echo "This script only works on Ubuntu 20 and above"
      exit
    fi
  fi
}
configSSH() {
  sed -i 's/#Port 22/Port 22/' /etc/ssh/sshd_config
  sed -i 's/Banner \/root\/banner.txt/#Banner none/g' /etc/ssh/sshd_config
  sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
  port=$(grep -oE 'Port [0-9]+' /etc/ssh/sshd_config | cut -d' ' -f2)
}
setCONFIG() {

source_file="/var/www/html/example/index.php"
destination_directory="/var/www/"
[ -f "$source_file" ] && cp "$source_file" "$destination_directory" && echo "index.php copied successfully."

  # Check if MySQL is installed
  if dpkg-query -W -f='${Status}' mariadb-server 2>/dev/null | grep -q "install ok installed"; then
    adminuser=$(mysql -N -e "use RPanel_plus; select username from admins where permission='admin';")
    adminpass=$(mysql -N -e "use RPanel_plus; select username from admins where permission='admin';")
    ssh_tls_port=$(mysql -N -e "use RPanel_plus; select tls_port from settings where id='1';")
  fi

  folder_path_cp="/var/www/html/cp"
  if [ -d "$folder_path_cp" ]; then
    rm -rf /var/www/html/cp
  fi
  folder_path_app="/var/www/html/app"
  if [ -d "$folder_path_app" ]; then
    rm -rf /var/www/html/app
  fi

  if [ -n "$ssh_tls_port" -a "$ssh_tls_port" != "NULL" ]; then
    sshtls_port=$ssh_tls_port
  else
    sshtls_port=444
  fi
  if test -f "/var/www/rpanelport"; then
    domainp=$(cat /var/www/rpanelport | grep "^DomainPanel")
    sslp=$(cat /var/www/rpanelport | grep "^SSLPanel")
    xpo=$(cat /var/www/rpanelport | grep "^RPanelport")
    xport=$(echo "$xpo" | sed "s/RPanelport //g")
    dmp=$(echo "$domainp" | sed "s/DomainPanel //g")
    dmssl=$(echo "$sslp" | sed "s/SSLPanel //g")
  else
    xport=""
    dmp=""
    dmssl=""
  fi
}
wellcomeINSTALL() {
  echo -e "${YELLOW}************ RPanel Nginx Installer ************"
  echo -e "${GREEN} نسخه فعلی: RPanel v4.0 (آخرین نسخه رسمی)"
  linkd="https://github.com/RmnJL/RPanel-SSH-User-Management/releases/latest"
  echo -e "\nلینک دریافت آخرین نسخه: $linkd"
}
userINPU() {
  # حذف درخواست IP سرور و مقداردهی خودکار
  # ip=$(curl -s https://ipinfo.io/ip)
  ip="127.0.0.1"
  adminusername=admin
  echo -e "\nPlease input Panel admin user."
  printf "Default user name is \e[33m${adminusername}\e[0m, let it blank to use this user name: "
  read usernametmp
  if [[ -n "${usernametmp}" ]]; then
    adminusername=${usernametmp}
  fi

  # Function to generate random uppercase character
  function random_uppercase {
    echo $((RANDOM % 26 + 65)) | awk '{printf("%c",$1)}'
  }

  # Function to generate random lowercase character
  function random_lowercase {
    echo $((RANDOM % 26 + 97)) | awk '{printf("%c",$1)}'
  }

  # Function to generate random digit
  function random_digit {
    echo $((RANDOM % 10))
  }

  # Generate a complex password
  password=""
  password="${password}$(random_uppercase)"
  password="${password}$(random_uppercase)"
  password="${password}$(random_uppercase)"
  password="${password}$(random_uppercase)"
  password="${password}$(random_digit)"
  password="${password}$(random_digit)"
  password="${password}$(random_digit)"
  password="${password}$(random_digit)"
  password="${password}$(random_lowercase)"
  password="${password}$(random_lowercase)"
  password="${password}$(random_lowercase)"

  adminpassword=${password}

  echo -e "\nPlease input Panel admin password."
  printf "Randomly generated password is \e[33m${adminpassword}\e[0m, leave it blank to use this random password : "
  read passwordtmp
  if [[ -n "${passwordtmp}" ]]; then
    adminpassword=${passwordtmp}
  fi
}
startINSTALL() {
  if [ "$dmp" != "" ]; then
    defdomain=$dmp
  else

    defdomain=$ip
  fi

  if [ "$dmssl" == "True" ]; then
    protcohttp=https

  else
    protcohttp=http
  fi
  ipv4=$ip
  sudo sed -i '/www-data/d' /etc/sudoers &
  wait

  if command -v apt-get >/dev/null; then
    sudo systemctl stop apache2
    sudo systemctl disable apache2
    sudo apt-get remove apache2 -y
    sudo apt autoremove -y

    sudo NEETRESTART_MODE=a apt-get update --yes
    sudo apt update -y
    sudo apt upgrade -y
    sudo apt -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade

    # نصب PHP و ماژول‌ها با مدیریت خطا و پیام مناسب
    install_package() {
        pkg="$1"
        if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
            echo -e "$pkg \e[34mقبلاً نصب شده است\e[0m"
        else
            echo -e "در حال نصب $pkg ..."
            sudo apt-get install -y "$pkg"
            if [ $? -ne 0 ]; then
                echo -e "\e[31mخطا در نصب $pkg. لطفاً اتصال اینترنت و مخازن را بررسی کنید. نصب متوقف شد.\e[0m"
                exit 1
            fi
        fi
    }

    # نصب پکیج‌های اصلی
    install_package stunnel4
    install_package cmake
    install_package screenfetch
    install_package openssl
    install_package software-properties-common

    # بررسی اتصال اینترنت قبل از اضافه کردن مخزن PPA
    if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        sudo add-apt-repository ppa:ondrej/php -y
    else
        echo -e "\e[31mاتصال اینترنت برقرار نیست یا دسترسی به سرورهای PPA وجود ندارد. نصب متوقف شد.\e[0m"
        exit 1
    fi
    sudo apt-get update -y

    # نصب سایر پکیج‌ها
    install_package nginx
    install_package zip
    install_package unzip
    install_package net-tools
    install_package mariadb-server
    install_package npm
    install_package python
    install_package python3
    install_package iftop
    install_package apt-transport-https
    install_package coreutils
    install_package curl
    install_package git
    install_package cron
    install_package php
    install_package php-cli
    install_package php-mbstring
    install_package php-dom
    install_package php-pdo
    install_package php-mysql
    install_package php8.1
    install_package php8.1-mysql
    install_package php8.1-xml
    install_package php8.1-curl
    install_package php8.1-fpm
    install_package php8.1-common
install_package php8.1-opcache
install_package php8.1-mbstring
install_package php8.1-zip
install_package php8.1-intl
install_package php8.1-simplexml
wait

# پیدا کردن آخرین نسخه PHP موجود در مخازن
latest_php_version=$(apt-cache search --names-only '^php[0-9]\.[0-9]$' | awk '{print $1}' | sort -V | tail -n1 | grep -oP 'php\K[0-9]\.[0-9]')
if [ -z "$latest_php_version" ]; then
  latest_php_version="8.1" # پیش‌فرض اگر پیدا نشد
fi

# نصب PHP و ماژول‌های اصلی برای آخرین نسخه
php_packages=(php${latest_php_version} php${latest_php_version}-mysql php${latest_php_version}-xml php${latest_php_version}-curl php${latest_php_version}-fpm php${latest_php_version}-cli php${latest_php_version}-common php${latest_php_version}-opcache php${latest_php_version}-mbstring php${latest_php_version}-zip php${latest_php_version}-intl php${latest_php_version}-simplexml)
for pkg in "${php_packages[@]}"; do
  install_package "$pkg"
done
wait

# بررسی نسخه نصب شده PHP
phpv=$(php -v | head -n1)
installed_php_version=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
if dpkg-query -W -f='${Status}' "php${installed_php_version}" 2>/dev/null | grep -q "install ok installed"; then
  apt autoremove -y
  echo "PHP $installed_php_version is installed."
else
  # حذف نسخه‌های قدیمی و نصب آخرین نسخه
  sudo apt-get purge '^php[0-9]\.[0-9].*' -y
  apt remove php* -y
  apt autoremove -y
  for pkg in "${php_packages[@]}"; do
    install_package "$pkg"
  done
  echo "PHP $latest_php_version and required modules installed."
fi
  curl -sS https://getcomposer.org/installer | sudo php -- --install-dir=/usr/local/bin --filename=composer
  echo "/bin/false" >>/etc/shells
  echo "/usr/sbin/nologin" >>/etc/shells

  #Banner
  cat <<EOF >/root/banner.txt
Connect To Server
EOF
  #Configuring stunnel
  sudo mkdir /etc/stunnel
  cat <<EOF >/etc/stunnel/stunnel.conf
 cert = /etc/stunnel/stunnel.pem
 [openssh]
 accept = $sshtls_port
 connect = 0.0.0.0:$port
 sslVersion = TLSv1.2
 options = NO_SSLv2
 options = NO_SSLv3
 options = SINGLE_DH_USE
 options = SINGLE_ECDH_USE
 ciphers = ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+3DES:!aNULL:!MD5:!DSS
EOF

    echo "=================  RPanel OpenSSL ======================"
    country=ID
    state=Semarang
    locality=RPanel
    organization=hidessh
    organizationalunit=HideSSH
    commonname=hidessh.com
    email=admin@hidessh.com
    openssl genrsa -out key.pem 2048
    openssl req -new -x509 -key key.pem -out cert.pem -days 1095 -subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"
    cat key.pem cert.pem >>/etc/stunnel/stunnel.pem
    sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
    service stunnel4 restart

    if test -f "/var/www/rpanelport"; then
      echo "File exists rpanelport"
    else
      touch /var/www/rpanelport
    fi
    link=$(sudo curl -Ls "$linkd" | grep '"browser_download_url":' | sed -E 's/.*"([^"]+)".*/\1/')
    sudo wget -O /var/www/html/update.zip $link
    sudo unzip -o /var/www/html/update.zip -d /var/www/html/ &
    wait
    sudo wget -4 -O /usr/local/bin/cronx https://raw.githubusercontent.com/RmnJL/RPanel-SSH-User-Management/main/cronx
    chmod +x /usr/local/bin/cronx
    sudo wget -4 -O /usr/local/bin/cronxfixed https://raw.githubusercontent.com/RmnJL/RPanel-SSH-User-Management/main/cronxfixed
    chmod +x /usr/local/bin/cronxfixed
    bash <(curl -Ls https://raw.githubusercontent.com/RmnJL/RPanel-SSH-User-Management/main/ioncube.sh --ipv4)
    wait
    echo 'www-data ALL=(ALL:ALL) NOPASSWD:/usr/local/bin/cronx' | sudo EDITOR='tee -a' visudo &
    wait
    echo 'www-data ALL=(ALL:ALL) NOPASSWD:/usr/local/bin/cronxfixed' | sudo EDITOR='tee -a' visudo &
    wait
    echo 'www-data ALL=(ALL:ALL) NOPASSWD:/usr/sbin/adduser' | sudo EDITOR='tee -a' visudo &
    wait
    echo 'www-data ALL=(ALL:ALL) NOPASSWD:/usr/sbin/userdel' | sudo EDITOR='tee -a' visudo &
    wait
    echo 'www-data ALL=(ALL:ALL) NOPASSWD:/usr/bin/sed' | sudo EDITOR='tee -a' visudo &
    wait
    echo 'www-data ALL=(ALL:ALL) NOPASSWD:/usr/bin/passwd' | sudo EDITOR='tee -a' visudo &
    wait
    echo 'www-data ALL=(ALL:ALL) NOPASSWD:/usr/bin/kill' | sudo EDITOR='tee -a' visudo &
    wait
    echo 'www-data ALL=(ALL:ALL) NOPASSWD:/usr/bin/killall' | sudo EDITOR='tee -a' visudo &
    wait
    echo 'www-data ALL=(ALL:ALL) NOPASSWD:/usr/bin/lsof' | sudo EDITOR='tee -a' visudo &
    wait
    echo 'www-data ALL=(ALL:ALL) NOPASSWD:/usr/sbin/lsof' | sudo EDITOR='tee -a' visudo &
    wait
    echo 'www-data ALL=(ALL:ALL) NOPASSWD:/usr/bin/sed' | sudo EDITOR='tee -a' visudo &
    wait
    echo 'www-data ALL=(ALL:ALL) NOPASSWD:/usr/bin/rm' | sudo EDITOR='tee -a' visudo &
    wait
    echo 'www-data ALL=(ALL:ALL) NOPASSWD:/usr/bin/crontab' | sudo EDITOR='tee -a' visudo &
    wait
    echo 'www-data ALL=(ALL:ALL) NOPASSWD:/usr/bin/mysqldump' | sudo EDITOR='tee -a' visudo &
    wait
    echo 'www-data ALL=(ALL:ALL) NOPASSWD:/usr/bin/pgrep' | sudo EDITOR='tee -a' visudo &
    wait
    echo 'www-data ALL=(ALL:ALL) NOPASSWD:/usr/sbin/nethogs' | sudo EDITOR='tee -a' visudo &
    wait
    echo 'www-data ALL=(ALL:ALL) NOPASSWD:/usr/bin/nethogs' | sudo EDITOR='tee -a' visudo &
    wait
    echo 'www-data ALL=(ALL:ALL) NOPASSWD:/usr/local/sbin/nethogs' | sudo EDITOR='tee -a' visudo &
    wait
    echo 'www-data ALL=(ALL:ALL) NOPASSWD:/usr/bin/netstat' | sudo EDITOR='tee -a' visudo &
    wait
    echo 'www-data ALL=(ALL:ALL) NOPASSWD:/usr/sbin/service' | sudo EDITOR='tee -a' visudo &
    wait
    echo 'www-data ALL=(ALL:ALL) NOPASSWD:/usr/sbin/reboot' | sudo EDITOR='tee -a' visudo &
    wait
    echo 'www-data ALL=(ALL:ALL) NOPASSWD:/usr/bin/cp' | sudo EDITOR='tee -a' visudo &
    wait
    echo 'www-data ALL=(ALL:ALL) NOPASSWD:/usr/bin/rm' | sudo EDITOR='tee -a' visudo &
    wait
    echo 'www-data ALL=(ALL:ALL) NOPASSWD:/usr/bin/zip' | sudo EDITOR='tee -a' visudo &
    wait
    echo 'www-data ALL=(ALL:ALL) NOPASSWD:/usr/bin/zip -r' | sudo EDITOR='tee -a' visudo &
    wait
    clear

    # Random port number generator to prevent xpanel detection by potential attackers
    randomPort=""
    # Check if $RANDOM is available in the shell
    if [ -z "$RANDOM" ]; then
      # If $RANDOM is not available, use a different random number generation method
      random_number=$(od -A n -t d -N 2 /dev/urandom | tr -d ' ')
    else
      # Generate a random number between 0 and 63000 using $RANDOM
      random_number=$((RANDOM % 63001))
    fi

    # Add 2000 to the random number to get a range between 2000 and 65000
    randomPort=$((random_number + 2000))

    # Use port 8081 if the random_number is zero (in case $RANDOM was not available and port 8081 was chosen)
    if [ "$random_number" -eq 0 ]; then
      randomPort=8081
    fi

    echo -e "\nPlease input Panel admin Port, or leave blank to use randomly generated port"
    printf "Random port \033[33m$randomPort:\033[0m "
    read porttmp
    if [[ -n "${porttmp}" ]]; then
      #Get the server port number from my settings file
      serverPort=${porttmp}
      serverPortssl=$((serverPort + 1))
      echo $serverPort
    else
      serverPort=$randomPort
      serverPortssl=$((serverPort + 1))
      echo $serverPort
    fi
    if [ "$dmssl" == "True" ]; then
      sshttp=$((serverPort + 1))
    else
      sshttp=$serverPort
    fi
    udpport=7300
    echo -e "\nPlease input UDPGW Port ."
    printf "Default Port is \e[33m${udpport}\e[0m, leave it blank to
    read udpport
    sudo bash -c "$(curl -Ls https://raw.githubusercontent.com/RmnJL/Nethogs-Json-main/main/install.sh --ipv4)"
    git clone https://github.com/ambrop72/badvpn.git /root/badvpn
    mkdir /root/badv
    cd /root/badvpn/badvpn-build
    cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 &
    wait
    make &
    wait
    cp udpgw/badvpn-udpgw /usr/local/bin
    cat >/etc/systemd/system/videocall.service <<ENDOFFILE
[Unit]
Description=UDP forwarding for badvpn-tun2socks
After=nss-lookup.target

[Service]
ExecStart=/usr/local/bin/badvpn-udpgw --loglevel none --listen-addr 127.0.0.1:$udpport --max-clients 999
User=videocall

[Install]
WantedBy=multi-user.target
ENDOFFILE
    useradd -m videocall
    systemctl enable videocall
    systemctl start videocall

    ##Get just the port number from the settings variable I just grabbed
    serverPort=${serverPort##*=}
    ##Remove the "" marks from the variable as they will not be needed
    serverPort=${serverPort//''/}
    sudo tee /etc/nginx/sites-available/default <<'EOF'
server {
    listen 80;
    server_name example.com;
    root /var/www/html/example;
    index index.php index
    root /var/www/html/example;
    index index.php index.html;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
        fastcgi_param PHP_VALUE "memory_limit=4096M";
    }
    location ~ /\.ht {
        deny all;
    }
     location /ws
    {
    proxy_pass http://127.0.0.1:8880/;
    proxy_redirect off;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_read_timeout 52w;
    }
    location /drp
    {
    proxy_pass http://127.0.0.1:9990/;
    proxy_redirect off;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_read_timeout 52w;
    }
}
server {
    listen 8443 ssl;
    server_name example.com;

    root /var/www/html/example;
    index index.php index.html;

    ssl_certificate /root/cert.pem;
    ssl_certificate_key /root/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
        fastcgi_param PHP_VALUE "memory_limit=4096M";
    }

    location ~ /\.ht {
        deny all;
    }

    location /ws {
        if ($http_upgrade != "websocket") {
                return 404;
        }
        proxy_pass http://127.0.0.1:8880;
        proxy_redirect off;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 52w;
    }
    location /drp {
        if ($http_upgrade != "websocket") {
                return 404;
        }
        proxy_pass http://127.0.0.1:9990;
        proxy_redirect off;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 52w;
    }
}
server {
    listen 8443 ssl;
    server_name example.com;
    root /var/www/html/cp;
    index index.php index.html;
    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
        fastcgi_param PHP_VALUE "memory_limit=4096M";
        fastcgi_param IONCUBE "/usr/local/ioncube/ioncube_loader_lin_8.1.so";
        fastcgi_param PHP_ADMIN_VALUE "zend_extension=/usr/local/ioncube/ioncube_loader_lin_8.1.so";
    }
    location ~ /\.ht {
        deny all;
    }
}
EOF
    sed -i "s/serverPort/$serverPort/g" /etc/nginx/sites-available/default
    sudo ln -s /etc/nginx/sites-available/default /etc/nginx/sites-enabled/
    echo '#RPanel' >/var/www/rpanelport
    sudo sed -i -e '$a\nRPanelport '$serverPort /var/www/rpanelport
    wait
    ##Restart the webserver server to use new port
    sudo nginx -t
    sudo systemctl start nginx
    sudo systemctl enable nginx
    sudo systemctl reload nginx
    # Getting Proxy Template
    sudo wget -q -O /usr/local/bin/wss https://raw.githubusercontent.com/RmnJL/RPanel-SSH-User-Management/main/wss
    sudo chmod +x /usr/local/bin/wss
    sudo wget -q -O /usr/local/bin/wssd https://raw.githubusercontent.com/RmnJL/RPanel-SSH-User-Management/main/wssd
    sudo chmod +x /usr/local/bin/wssd

    # Installing Service
    cat >/etc/systemd/system/wss.service <<END
[Unit]
Description=Python Proxy XPanel
Documentation=https://t.me/Xpanelssh
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/bin/python -O /usr/local/bin/wss 8880
Restart=on-failure

[Install]
WantedBy=multi-user.target
END

    systemctl daemon-reload
    systemctl enable wss
    systemctl restart wss

    cat >/etc/systemd/system/wssd.service <<END
[Unit]
Description=Python Proxy XPanel
Documentation=https://t.me/Xpanelssh
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/bin/python -O /usr/local/bin/wssd 9990
Restart=on-failure

[Install]
WantedBy=multi-user.target
END

    systemctl daemon-re
    systemctl enable wssd
    systemctl restart wssd

    chown www-data:www-data /var/www/html/cp/* &
    wait
    systemctl restart mariadb &
    wait
    systemctl enable mariadb &
    wait
    PHP_INI=$(php -i | grep /.+/php.ini -oE)
    sed -i
    sed -i 's/extension=intl/;extension=intl/' ${PHP_INI}
    wait
    po=$(cat /etc/ssh/sshd_config | grep "^Port")
    port=$(echo "$po" | sed "s/Port //g")
    sed -i "s/DEFAULT_HOST =.*/DEFAULT_HOST = '127.0.0.1:${port}'/g" /usr/local/bin/wss
    systemctl daemon-reload
    systemctl enable wss
    systemctl restart wss
    systemctl enable stunnel4
    systemctl restart stunnel4
    wait
}
# ======= پایان تابع startINSTALL =======

moreCONFIG() {
  sed -i "s/PORT_SSH=.*/PORT_SSH=$port/g" /var/www/html/app/.env
  sed -i "s/PORT_UDPGW=.*/PORT_UDPGW=$udpport/g" /var/www/html/app/.env
  sudo chown -R www-data:www-data /var/www/html/app
  crontab -r
  wait

  multiin=$(echo "$protcohttp://${defdomain}:$sshttp/fixer/multiuser")
  cat >/var/www/html/kill.sh <<ENDOFFILE
#!/bin/bash
#By Alireza
i=0
while [ 1i -lt 10 ]; do
cmd=(bbh '$multiin')
echo cmd &
sleep 6
i=(( i + 1 ))
done
ENDOFFILE
  wait
  sudo sed -i 's/(bbh/$(curl -v -H "A: B"/' /var/www/html/kill.sh
  wait
  sudo sed -i 's/cmd/$cmd/' /var/www/html/kill.sh
  wait
  sudo sed -i 's/1i/$i/' /var/www/html/kill.sh
  wait
  sudo sed -i 's/((/$((/' /var/www/html/kill.sh
  wait
  chmod +x /var/www/html/
  (crontab -l ; echo "*/15 * * * * wget -q -O /dev/null '$protcohttp://${defdomain}:$sshttp/fixer/checkfilter' > /dev/null 2>&1") | crontab -
  (crontab -l ; echo "0 0 * * * wget -q -O /dev/null '$protcohttp://${defdomain}:$sshttp/fixer/send/email/3day' > /dev/null 2>&1") | crontab -
  (crontab -l ; echo "0 0 * * * wget -q -O /dev/null '$protcohttp://${defdomain}:$sshttp/fixer/send/email/24h' > /dev/null 2>&1") | crontab -
  crontab -l | sed '/dropbear\.sh/d' | crontab -
  if [ -f "/var/www/html/dropbear.sh" ]; then
    rm -rf "/var/www/html/dropbear.sh"
  fi
  wait
  systemctl enable stunnel4 &
  wait
  systemctl restart stunnel4 &
  wait
  sudo mkdir -p /rpanel
  wait
  curl -sL -o /usr/local/bin/xp_user_limit https://raw.githubusercontent.com/xpanel-cp/XPanel-SSH-User-Management/master/xp_user_limit.sh
  chmod +x /usr/local/bin/xp_user_limit
  echo 'www-data ALL=(ALL:ALL) NOPASSWD:/usr/local/bin/xp_user_limit' | sudo EDITOR='tee -a' visudo
  wait
  curl -o /root/xpanel.sh https://raw.githubusercontent.com/xpanel-cp/XPanel-SSH-User-Management/master/cli.sh
  sudo wget -4 -O /usr/local/bin/xpanel https://raw.githubusercontent.com/xpanel-cp/XPanel-SSH-User-Management/master/cli.sh
  chmod +x /usr/local/bin/xpanel
  chown www-data:www-data /var/www/html/example/
  chown www-data:www-data /var/www/html/example/index.php
  sed -i "s/PORT_PANEL=.*/PORT_PANEL=$sshttp/g" /var/www/html/app/.env
  DEFAULT_APP_LOCALE=en
  DEFAULT_APP_MODE=light
  DEFAULT_PANEL_DIRECT=cp
  DEFAULT_CRON_TRAFFIC=active
  DEFAULT_DAY=active
  DEFAULT_PORT_DROPBEAR=2083
  DEFAULT_TRAFFIC_BASE=12
  DEFAULT_STATUS_LOG=deactive
  DEFAULT_BOT_TOKEN=
  DEFAULT_BOT_ID_ADMIN=
  DEFAULT_BOT_API_ACCESS=
  DEFAULT_ANTI=
  DEFAULT_TRAFFIC_SERVER=
  DEFAULT_BOT_LOG=
  DEFAULT_PORT_UDPGW=
  DEFAULT_MAIL_STATUS=
  DEFAULT_MAIL_HOST=
  DEFAULT_MAIL_PORT=
  DEFAULT_MAIL_USERNAME=
  DEFAULT_MAIL_PASSWORD=
  DEFAULT_MAIL_FROM_ADDRESS=
  DEFAULT_MAIL_FROM_NAME=
  DEFAULT_GB_CHANGE=

  if [ -f /var/www/html/.env_copy ]; then
    while IFS= read -r line; do
      key=$(echo "$line" | awk -F'=' '{print $1}')
      value=$(echo "$line" | awk -F'=' '{print $2}')

      if [ "$key" = "APP_LOCALE" ]; then
        APP_LOCALE="$value"
      elif [ "$key" = "APP_MODE" ]; then
        APP_MODE="$value"
      elif [ "$key" = "PANEL_DIRECT" ]; then
        PANEL_DIRECT="$value"
      elif [ "$key" = "CRON_TRAFFIC" ]; then
        CRON_TRAFFIC="$value"
      elif [ "$key" = "DAY" ]; then
        DAY="$value"
      elif [ "$key" = "PORT_DROPBEAR" ]; then
        PORT_DROPBEAR="$value"
      elif [ "$key" = "TRAFFIC_BASE" ]; then
        TRAFFIC_BASE="$value"
      elif [ "$key" = "STATUS_LOG" ]; then
        STATUS_LOG="$value"
      elif [ "$key" = "BOT_TOKEN" ]; then
        BOT_TOKEN="$value"
      elif [ "$key" = "BOT_ID_ADMIN" ]; then
        BOT_ID_ADMIN="$value"
      elif [ "$key" = "BOT_API_ACCESS" ]; then
        BOT_API_ACCESS="$value"
      elif [ "$key" = "ANTI_USER" ]; then
        ANTI_USER="$value"
      elif [ "$key" = "TRAFFIC_SERVER" ]; then
        TRAFFIC_SERVER="$value"
      elif [ "$key" = "BOT_LOG" ]; then
        BOT_LOG="$value"
      elif [ "$key" = "PORT_UDPGW" ]; then
        PORT_UDPGW="$value"
      elif [ "$key" = "MAIL_STATUS" ]; then
        MAIL_STATUS="$value"
      elif [ "$key" = "MAIL_HOST" ]; then
        MAIL_HOST="$value"  
      elif [ "$key" = "MAIL_PORT" ]; then
        MAIL_PORT="$value" 
      elif [ "$key" = "MAIL_USERNAME" ]; then
        MAIL_USERNAME="$value" 
      elif [ "$key" = "MAIL_PASSWORD" ]; then
        MAIL_PASSWORD="$value" 
      elif [ "$key" = "MAIL_FROM_ADDRESS" ]; then
        MAIL_FROM_ADDRESS="$value" 
      elif [ "$key" = "MAIL_FROM_NAME" ]; then
        MAIL_FROM_NAME="$value" 
      elif [ "$key" = "GB_CHANGE" ]; then
        GB_CHANGE="$value" 
      fi
    done </var/www/html/.env_copy
  fi

  APP_LOCALE="${APP_LOCALE:-$DEFAULT_APP_LOCALE}"
  APP_MODE="${APP_MODE:-$DEFAULT_APP_MODE}"
  PANEL_DIRECT="${PANEL_DIRECT:-$DEFAULT_PANEL_DIRECT}"
  CRON_TRAFFIC="${CRON_TRAFFIC:-$DEFAULT_CRON_TRAFFIC}"
  DAY="${DAY:-$DEFAULT_DAY}"
  PORT_DROPBEAR="${PORT_DROPBEAR:-$DEFAULT_PORT_DROPBEAR}"
  TRAFFIC_BASE="${TRAFFIC_BASE:-$DEFAULT_TRAFFIC_BASE}"
  STATUS_LOG="${STATUS_LOG:-$DEFAULT_STATUS_LOG}"
  BOT_TOKEN="${BOT_TOKEN:-$DEFAULT_BOT_TOKEN}"
  BOT_ID_ADMIN="${BOT_ID_ADMIN:-$DEFAULT_BOT_ID_ADMIN}"
  BOT_API_ACCESS="${BOT_API_ACCESS:-$DEFAULT_BOT_API_ACCESS}"
  ANTI_USER="${ANTI_USER:-$DEFAULT_ANTI_USER}"
  TRAFFIC_SERVER="${TRAFFIC_SERVER:-$DEFAULT_TRAFFIC_SERVER}"
  BOT_LOG="${BOT_LOG:-$DEFAULT_BOT_LOG}"
  PORT_UDPGW="${PORT_UDPGW:-$DEFAULT_PORT_UDPGW}"
  MAIL_STATUS="${MAIL_STATUS:-$DEFAULT_MAIL_STATUS}"
  MAIL_HOST="${BOT_MAIL_HOST:-$DEFAULT_MAIL_HOST}"
  MAIL_PORT="${BOT_MAIL_PORT:-$DEFAULT_MAIL_PORT}"
  MAIL_USERNAME="${BOT_MAIL_USERNAME:-$DEFAULT_MAIL_USERNAME}"
  MAIL_PASSWORD="${MAIL_PASSWORD:-$DEFAULT_MAIL_PASSWORD}"
  MAIL_FROM_ADDRESS="${MAIL_FROM_ADDRESS:-$DEFAULT_MAIL_FROM_ADDRESS}"
  MAIL_FROM_NAME="${MAIL_FROM_NAME:-$DEFAULT_MAIL_FROM_NAME}"
  GB_CHANGE="${GB_CHANGE:-$DEFAULT_GB_CHANGE}"

  sed -i "s/APP_LOCALE=.*/APP_LOCALE=$APP_LOCALE/g" /var/www/html/app/.env
  sed -i "s/APP_MODE=.*/APP_MODE=$APP_MODE/g" /var/www/html/app/.env
  sed -i "s/PANEL_DIRECT=.*/PANEL_DIRECT=$PANEL_DIRECT/g" /var/www/html/app/.env
  sed -i "s/CRON_TRAFFIC=.*/CRON_TRAFFIC=$CRON_TRAFFIC/g" /var/www/html/app/.env
  sed -i "s/DAY=.*/DAY=$DAY/g" /var/www/html/app/.env
  sed -i "s/PORT_DROPBEAR=.*/PORT_DROPBEAR=$PORT_DROPBEAR/g" /var/www/html/app/.env
  sed -i "s/TRAFFIC_BASE=.*/TRAFFIC_BASE=$TRAFFIC_BASE/g" /var/www/html/app
  sed -i "s/MAIL_PORT=.*/MAIL_PORT=$MAIL_PORT/g" /var/www/html/app/.env
  sed -i "s/MAIL_USERNAME=.*/MAIL_USERNAME=$MAIL_USERNAME/g" /var/www/html/app/.env
  sed -i "s/MAIL_PASSWORD=.*/MAIL_PASSWORD=$MAIL_PASSWORD/g" /var/www/html/app/.env
  sed -i "s/MAIL_FROM_ADDRESS=.*/MAIL_FROM_ADDRESS=$MAIL_FROM_ADDRESS/g" /var/www/html/app/.env
  sed -i "s/MAIL_FROM_NAME=.*/MAIL_FROM_NAME=$MAIL_FROM_NAME/g" /var/www/html/app/.env
  sed -i "s/GB_CHANGEE=.*/GB_CHANGE=$GB_CHANGE/g" /var/www/html/app/.env
  sudo systemctl stop apache2
  sudo systemctl disable apache2
  sudo apt-get remove apache2 -y
  sudo apt autoremove -y
  cp /var/www/index.php /var/www/html/example/
  clear
}
endINSTALL() {
  echo -e "************ RPanel ************ \n"
  echo -e "RPanel Link : $protcohttp://${defdomain}:$sshttp/login"
  echo -e "Username : ${adminusername}"
  echo -e "Password : ${adminpassword}"
  echo -e "-------- Connection Details ----------- \n"
  echo -e "IP : $ipv4 "
  echo -e "SSH port : ${port} "
  echo -e "SSH + TLS port : ${sshtls_port} \n"
  echo -e "************ Check Install Packag and Moudels ************ \n"
}
check_install() {
  if dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"; then
    echo -e "$1 \e[34m is installed \e[0m"
  else
    if which $1 &>/dev/null; then
      echo -e "$1 \e[34m is installed \e[0m"
    else
      echo -e "$1 \e[31m is not installed \e[0m"
    fi
  fi
}

# TODO: برای افزایش امنیت و پایداری، قبل از نصب هر پکیج، وجود آن بررسی و در صورت نیاز نصب شود. همچنین، مدیریت خطا و لاگ‌گیری بهبود یابد.

# پاک‌سازی نصب قبلی RPanel
clean_previous_install() {
  echo -e "\e[33mدر حال بررسی و پاک‌سازی نصب قبلی RPanel...\e[0m"
  # حذف دیتابیس RPanel_plus در صورت وجود
  if mysql -u root -e "USE RPanel_plus;" 2>/dev/null; then
    mysql -u root -e "DROP DATABASE RPanel_plus;"
    echo "دیتابیس RPanel_plus حذف شد."
  fi
  # حذف فایل‌ها و دایرکتوری‌های اصلی
  rm -rf /var/www/html/app
  rm -rf /var/www/html/cp
  rm -rf /var/www/html/example
  rm -f /var/www/rpanelport
  rm -f /var/www/html/.env_copy
  rm -f /var/www/html/update.zip
  # حذف سرویس‌های systemd مرتبط
  for svc in wss wssd videocall; do
    systemctl stop $svc 2>/dev/null
    systemctl disable $svc 2>/dev/null
    rm -f /etc/systemd/system/$svc.service
  done
  systemctl daemon-reload
  # حذف کاربر سیستم videocall
  id videocall &>/dev/null && userdel -r videocall
  # حذف ruleهای visudo اضافه شده برای www-data
  sed -i '/www-data ALL=(ALL:ALL) NOPASSWD:/d' /etc/sudoers
  echo -e "\e[32mپاک‌سازی نصب قبلی RPanel انجام شد.\e[0m"
}

# اجرای پاک‌سازی قبل از هر نصب جدید
clean_previous_install
checkOS
configSSH
setCONFIG
wellcomeINSTALL
userINPU
startINSTALL
checkDATABASE
moreCONFIG
endINSTALL
# Check and display status for each package
check_install software-properties-common
check_install stunnel4
check_install cmake
check_install screenfetch
check_install openssl
check_install nginx
check_install zip
check_install unzip
check_install net-tools
check_install curl
check_install mariadb-server
check_install php
check_install npm
check_install coreutils
check_install php8.1
check_install php8.1-mysql
check_install php8.1-xml
check_install php8.1-curl
check_install cron
check_install nethogs
