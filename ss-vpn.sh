#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#=================================================
#	System Required: CentOS/Debian/Ubuntu
#	Description: Shadowsocks VPN
#	Version: 1.0.0
#	Author: Legenda
#=================================================

sh_ver="7.7.7"
filepath=$(cd "$(dirname "$0")"; pwd)
file=$(echo -e "${filepath}"|awk -F "$0" '{print $1}')
ss_folder="/usr/local/shadowsocks"
config_file="${ss_folder}/config.json"
config_user_file="${ss_folder}/user-config.json"
config_user_api_file="${ss_folder}/userapiconfig.py"
config_user_mudb_file="${ss_folder}/mudb.json"
ss_log_file="${ss_folder}/ssserver.log"
Libsodiumr_file="/usr/local/lib/libsodium.so"
Libsodiumr_ver_backup="1.0.15"
Server_Speeder_file="/serverspeeder/bin/serverSpeeder.sh"
BBR_file="${file}/bbr.sh

Green_font_prefix = " \ 033 [32m "  && Red_font_prefix = " \ 033 [31m "  && Green_background_prefix = " \ 033 [42; 37m »  && Red_background_prefix = " \ 033 [41; 37m "  && Font_color_suffix = " \ 033 [0m "
Info = " $ {Green_font_prefix} [Информация] $ {Font_color_suffix} "
Ошибка = " $ {Red_font_prefix} [Ошибка] $ {Font_color_suffix} "
Tip = " $ {Green_font_prefix} [Заметка] $ {Font_color_suffix} "
Separator_1 = " —————————————————————————————— "

check_root(){
	[[ $EUID != 0 ]] && echo -e "${Error} Скрипт не запущен от root. Пропишите ${Green_background_prefix} sudo su ${Font_color_suffix} И перезапустите программу." && exit 1
}
check_sys(){
	if [[ -f /etc/redhat-release ]]; then
		release="centos"
	elif cat /etc/issue | grep -q -E -i "debian"; then
		release="debian"
	elif cat /etc/issue | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
	elif cat /proc/version | grep -q -E -i "debian"; then
		release="debian"
	elif cat /proc/version | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
    fi
	bit=`uname -m`
}
check_pid(){
	PID=`ps -ef |grep -v grep | grep server.py |awk '{print $2}'`
}
check_crontab(){
	[[ ! -e "/usr/bin/crontab" ]] && echo -e "${Error} Отсутствует crontab: для установки на CentOS пропишите yum install crond -y , Debian/Ubuntu: apt-get install cron -y !" && exit 1
}
SSR_installation_status(){
	[[ ! -e ${ssr_folder} ]] && echo -e "${Error} Не найден ShadowsocksR!" && exit 1
}
Server_Speeder_installation_status(){
	[[ ! -e ${Server_Speeder_file} ]] && echo -e "${Error} Server Speeder не установлен !" && exit 1
}
# Настроить правила брандмауэра
Add_iptables(){
	if [[ ! -z "${ss_port}" ]]; then
		iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ss_port} -j ACCEPT
		iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${ss_port} -j ACCEPT
		ip6tables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ss_port} -j ACCEPT
		ip6tables -I INPUT -m state --state NEW -m udp -p udp --dport ${ss_port} -j ACCEPT
	fi
}
Del_iptables(){
	if [[ ! -z "${port}" ]]; then
		iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
		iptables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
		ip6tables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
		ip6tables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
	fi
}
Save_iptables(){
	if [[ ${release} == "centos" ]]; then
		service iptables save
		service ip6tables save
	else
		iptables-save > /etc/iptables.up.rules
		ip6tables-save > /etc/ip6tables.up.rules
	fi
}
Set_iptables(){
	if [[ ${release} == "centos" ]]; then
		service iptables save
		service ip6tables save
		chkconfig --level 2345 iptables on
		chkconfig --level 2345 ip6tables on
	else
		iptables-save > /etc/iptables.up.rules
		ip6tables-save > /etc/ip6tables.up.rules
		echo -e '#!/bin/bash\n/sbin/iptables-restore < /etc/iptables.up.rules\n/sbin/ip6tables-restore < /etc/ip6tables.up.rules' > /etc/network/if-pre-up.d/iptables
		chmod +x /etc/network/if-pre-up.d/iptables
	fi
}
# Прочтите информацию о конфигурации
Get_IP(){
	ip=$(wget -qO- -t1 -T2 ipinfo.io/ip)
	if [[ -z "${ip}" ]]; then
		ip=$(wget -qO- -t1 -T2 api.ip.sb/ip)
		if [[ -z "${ip}" ]]; then
			ip=$(wget -qO- -t1 -T2 members.3322.org/dyndns/getip)
			if [[ -z "${ip}" ]]; then
				ip="VPS_IP"
			fi
		fi
	fi
}
Get_User_info(){
	Get_user_port=$1
	user_info_get=$(python mujson_mgr.py -l -p "${Get_user_port}")
	match_info=$(echo "${user_info_get}"|grep -w "### user ")
	if [[ -z "${match_info}" ]]; then
		echo -e "${Error} Не удалось получить информацию о пользователе ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} " && exit 1
	fi
	user_name=$(echo "${user_info_get}"|grep -w "user :"|awk -F "user : " '{print $NF}')
	port=$(echo "${user_info_get}"|grep -w "port :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	password=$(echo "${user_info_get}"|grep -w "passwd :"|awk -F "passwd : " '{print $NF}')
	method=$(echo "${user_info_get}"|grep -w "method :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	protocol=$(echo "${user_info_get}"|grep -w "protocol :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	protocol_param=$(echo "${user_info_get}"|grep -w "protocol_param :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	[[ -z ${protocol_param} ]] && protocol_param="0(неограниченно)"
	obfs=$(echo "${user_info_get}"|grep -w "obfs :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	#transfer_enable=$(echo "${user_info_get}"|grep -w "transfer_enable :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}'|awk -F "ytes" '{print $1}'|sed 's/KB/ KB/;s/MB/ MB/;s/GB/ GB/;s/TB/ TB/;s/PB/ PB/')
	#u=$(echo "${user_info_get}"|grep -w "u :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	#d=$(echo "${user_info_get}"|grep -w "d :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	forbidden_port=$(echo "${user_info_get}"|grep -w "forbidden_port :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	[[ -z ${forbidden_port} ]] && forbidden_port="неограниченно"
	speed_limit_per_con=$(echo "${user_info_get}"|grep -w "speed_limit_per_con :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	speed_limit_per_user=$(echo "${user_info_get}"|grep -w "speed_limit_per_user :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	Get_User_transfer "${port}"
}
Get_User_transfer(){
	transfer_port=$1
	#echo "transfer_port=${transfer_port}"
	all_port=$(${jq_file} '.[]|.port' ${config_user_mudb_file})
	#echo "all_port=${all_port}"
	port_num=$(echo "${all_port}"|grep -nw "${transfer_port}"|awk -F ":" '{print $1}')
	#echo "port_num=${port_num}"
	port_num_1=$(echo $((${port_num}-1)))
	#echo "port_num_1=${port_num_1}"
	transfer_enable_1=$(${jq_file} ".[${port_num_1}].transfer_enable" ${config_user_mudb_file})
	#echo "transfer_enable_1=${transfer_enable_1}"
	u_1=$(${jq_file} ".[${port_num_1}].u" ${config_user_mudb_file})
	#echo "u_1=${u_1}"
	d_1=$(${jq_file} ".[${port_num_1}].d" ${config_user_mudb_file})
	#echo "d_1=${d_1}"
	transfer_enable_Used_2_1=$(echo $((${u_1}+${d_1})))
	#echo "transfer_enable_Used_2_1=${transfer_enable_Used_2_1}"
	transfer_enable_Used_1=$(echo $((${transfer_enable_1}-${transfer_enable_Used_2_1})))
	#echo "transfer_enable_Used_1=${transfer_enable_Used_1}"
	
	if [[ ${transfer_enable_1} -lt 1024 ]]; then
		transfer_enable="${transfer_enable_1} B"
	elif [[ ${transfer_enable_1} -lt 1048576 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1024'}')
		transfer_enable="${transfer_enable} KB"
	elif [[ ${transfer_enable_1} -lt 1073741824 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1048576'}')
		transfer_enable="${transfer_enable} MB"
	elif [[ ${transfer_enable_1} -lt 1099511627776 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1073741824'}')
		transfer_enable="${transfer_enable} GB"
	elif [[ ${transfer_enable_1} -lt 1125899906842624 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1099511627776'}')
		transfer_enable="${transfer_enable} TB"
	fi
	#echo "transfer_enable=${transfer_enable}"
	if [[ ${u_1} -lt 1024 ]]; then
		u="${u_1} B"
	elif [[ ${u_1} -lt 1048576 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1024'}')
		u="${u} KB"
	elif [[ ${u_1} -lt 1073741824 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1048576'}')
		u="${u} MB"
	elif [[ ${u_1} -lt 1099511627776 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1073741824'}')
		u="${u} GB"
	elif [[ ${u_1} -lt 1125899906842624 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1099511627776'}')
		u="${u} TB"
	fi
	#echo "u=${u}"
	if [[ ${d_1} -lt 1024 ]]; then
		d="${d_1} B"
	elif [[ ${d_1} -lt 1048576 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1024'}')
		d="${d} KB"
	elif [[ ${d_1} -lt 1073741824 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1048576'}')
		d="${d} MB"
	elif [[ ${d_1} -lt 1099511627776 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1073741824'}')
		d="${d} GB"
	elif [[ ${d_1} -lt 1125899906842624 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1099511627776'}')
		d="${d} TB"
	fi
	#echo "d=${d}"
	if [[ ${transfer_enable_Used_1} -lt 1024 ]]; then
		transfer_enable_Used="${transfer_enable_Used_1} B"
	elif [[ ${transfer_enable_Used_1} -lt 1048576 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1024'}')
		transfer_enable_Used="${transfer_enable_Used} KB"
	elif [[ ${transfer_enable_Used_1} -lt 1073741824 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1048576'}')
		transfer_enable_Used="${transfer_enable_Used} MB"
	elif [[ ${transfer_enable_Used_1} -lt 1099511627776 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1073741824'}')
		transfer_enable_Used="${transfer_enable_Used} GB"
	elif [[ ${transfer_enable_Used_1} -lt 1125899906842624 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1099511627776'}')
		transfer_enable_Used="${transfer_enable_Used} TB"
	fi
	#echo "transfer_enable_Used=${transfer_enable_Used}"
	if [[ ${transfer_enable_Used_2_1} -lt 1024 ]]; then
		transfer_enable_Used_2="${transfer_enable_Used_2_1} B"
	elif [[ ${transfer_enable_Used_2_1} -lt 1048576 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1024'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} KB"
	elif [[ ${transfer_enable_Used_2_1} -lt 1073741824 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1048576'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} MB"
	elif [[ ${transfer_enable_Used_2_1} -lt 1099511627776 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1073741824'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} GB"
	elif [[ ${transfer_enable_Used_2_1} -lt 1125899906842624 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1099511627776'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} TB"
	fi
	#echo "transfer_enable_Used_2=${transfer_enable_Used_2}"
}
Get_User_transfer_all(){
	if [[ ${transfer_enable_Used_233} -lt 1024 ]]; then
		transfer_enable_Used_233_2="${transfer_enable_Used_233} B"
	elif [[ ${transfer_enable_Used_233} -lt 1048576 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1024'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} KB"
	elif [[ ${transfer_enable_Used_233} -lt 1073741824 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1048576'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} MB"
	elif [[ ${transfer_enable_Used_233} -lt 1099511627776 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1073741824'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} GB"
	elif [[ ${transfer_enable_Used_233} -lt 1125899906842624 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1099511627776'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} TB"
	fi
}
urlsafe_base64(){
	date=$(echo -n "$1"|base64|sed ':a;N;s/\n/ /g;ta'|sed 's/ //g;s/=//g;s/+/-/g;s/\//_/g')
	echo -e "${date}"
}
ss_link_qr(){
	SSbase64=$(urlsafe_base64 "${method}:${password}@${ip}:${port}")
	SSurl="ss://${SSbase64}"
	SSQRcode="https://api.qrserver.com/v1/create-qr-code/?data=${SSurl}"
	ss_link=" SS link : ${Green_font_prefix}${SSurl}${Font_color_suffix} \n SS QR код : ${Green_font_prefix}${SSQRcode}${Font_color_suffix}"
}
# Отображение информации о конфигурации
View_User(){
	SS_installation_status
	List_port_user
	while true
	do
		echo -e "Введите порт аккаунта для анализа"
		read -e -p "(По умолчанию: отмена):" View_user_port
		[[ -z "${View_user_port}" ]] && echo -e "Отмена..." && exit 1
		View_user=$(cat "${config_user_mudb_file}"|grep '"port": '"${View_user_port}"',')
		if [[ ! -z ${View_user} ]]; then
			Get_User_info "${View_user_port}"
			View_User_info
			break
		else
			echo -e "${Error} Введите правильный порт !"
		fi
	done
}
View_User_info(){
	ip=$(cat ${config_user_api_file}|grep "SERVER_PUB_ADDR = "|awk -F "[']" '{print $2}')
	[[ -z "${ip}" ]] && Get_IP
	clear && echo "===================================================" && echo
	echo -e " Информация о пользователе [${user_name}] ：" && echo
	echo -e " IP\t    : ${Green_font_prefix}${ip}${Font_color_suffix}"
	echo -e " Порт\t    : ${Green_font_prefix}${port}${Font_color_suffix}"
	echo -e " Пароль\t    : ${Green_font_prefix}${password}${Font_color_suffix}"
	echo -e " Шифрование : ${Green_font_prefix}${method}${Font_color_suffix}"
	echo -e " Протокол   : ${Red_font_prefix}${protocol}${Font_color_suffix}"
	echo -e " Obfs\t    : ${Red_font_prefix}${obfs}${Font_color_suffix}"
	echo -e " Количество устройств : ${Green_font_prefix}${protocol_param}${Font_color_suffix}"
	echo -e " Общая скорость ключа : ${Green_font_prefix}${speed_limit_per_con} KB/S${Font_color_suffix}"
	echo -e " Скорость соединения у каждого пользователя : ${Green_font_prefix}${speed_limit_per_user} KB/S${Font_color_suffix}"
	echo -e " Запрещенные порты : ${Green_font_prefix}${forbidden_port} ${Font_color_suffix}"
	echo
	echo -e " Использованный трафик : Upload: ${Green_font_prefix}${u}${Font_color_suffix} + Download: ${Green_font_prefix}${d}${Font_color_suffix} = ${Green_font_prefix}${transfer_enable_Used_2}${Font_color_suffix}"
	echo -e " Осталось трафика : ${Green_font_prefix}${transfer_enable_Used} ${Font_color_suffix}"
	echo -e " Всего трафика : ${Green_font_prefix}${transfer_enable} ${Font_color_suffix}"
	echo -e "${ss_link}"
	echo -e " ${Green_font_prefix} Подсказка: ${Font_color_suffix}
 Откройте ссылку в браузере для получения QR кода。"
	echo && echo "==================================================="
}
# Создание юзера
Set_config_user(){
	echo "Имя пользователя (Авто указание даты)"
	read -e -p "(По умолчанию: Admin):" ssr_user
	[[ -z "${ss_user}" ]] && ss_user="Admin"
	ss_user=$(echo "${ss_user}_$(date +"%d/%m")" |sed 's/ //g')
	echo && echo ${Separator_1} && echo -e "	Имя пользователя : ${Green_font_prefix}${ss_user}${Font_color_suffix}" && echo ${Separator_1} && echo
}
Set_config_port(){
	echo "Порт
	1. Авто
	2. Вручную"	
	read -e -p "По умолчанию: (1.Авто)" how_to_port
	[[ -z "${how_to_port}" ]] && how_to_port="1"
	if [[ ${how_to_port} == "1" ]]; then
		echo -e "Порт автоматически сгенерирован."
		ssr_port=$(shuf -i 1000-9999 -n 1)
		while true
		do
		echo $((${ss_port}+0)) &>/dev/null
		if [[ $? == 0 ]]; then
		if [[ ${ss_port} -ge 1 ]] && [[ ${ss_port} -le 65535 ]]; then
			echo && echo ${Separator_1} && echo -e "	Порт: : ${Green_font_prefix}${ss_port}${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} Введите корректный порт(1-65535)"
		fi
	else
		echo -e "${Error} Введите корректный порт(1-65535)"
	fi
	done
	elif [[ ${how_to_port} == "2" ]]; then
		while true
		do
			read -e -p "Порт:" ssr_port
			[[ -z "$ss_port" ]] && break
			echo $((${ss_port}+0)) &>/dev/null
			if [[ $? == 0 ]]; then
				if [[ ${ssr_port} -ge 1 ]] && [[ ${ss_port} -le 65535 ]]; then
					echo && echo ${Separator_1} && echo -e "	Порт: : ${Green_font_prefix}${ss_port}${Font_color_suffix}" && echo ${Separator_1} && echo
					break
				else
					echo -e "${Error} Введите корректный порт(1-65535)"
				fi
			else
				echo -e "${Error} Введите корректный порт(1-65535)"
			fi
		done
	else 
		echo -e "Порт автоматически сгенерирован."
		ss_port=$(shuf -i 1000-9999 -n 1)
		while true
		do
		echo $((${ssr_port}+0)) &>/dev/null
		if [[ $? == 0 ]]; then
			if [[ ${ss_port} -ge 1 ]] && [[ ${ss_port} -le 65535 ]]; then
			echo && echo ${Separator_1} && echo -e "	Порт: : ${Green_font_prefix}${ss_port}${Font_color_suffix}" && echo ${Separator_1} && echo
			break
			else
			echo -e "${Error} Введите корректный порт(1-65535)"
			fi
		else
		echo -e "${Error} Введите корректный порт(1-65535)"
		fi
		done
	fi
}
Set_config_password(){
	echo "Пароль:
	1. Пароль = порт
	2. Рандомный пароль"
	read -e -p "По умолчанию: (1.Пароль = порт)" how_to_pass
	[[ -z "${how_to_pass}" ]] && how_to_pass="1"
	if [[ ${how_to_pass} == "1" ]]; then
		ss_password=${ss_port}
	elif [[ ${how_to_pass} == "2" ]]; then
		ss_password=$(date +%s%N | md5sum | head -c 16)
	else 
		ss_password=${ssr_port}
	fi
	echo && echo ${Separator_1} && echo -e "	Пароль : ${Green_font_prefix}${ssr_password}${Font_color_suffix}" && echo ${Separator_1} && echo
}
Set_config_method(){
	echo -e "Пожалуйста, выберите метод шифрования Shadowsocks
	
 ${Green_font_prefix} 1.${Font_color_suffix} aes-128-cfb
 ${Green_font_prefix} 2.${Font_color_suffix} aes-128-ctr
 ${Green_font_prefix} 3.${Font_color_suffix} aes-192-cfb
 ${Green_font_prefix} 4.${Font_color_suffix} aes-192-ctr
 ${Green_font_prefix} 5.${Font_color_suffix} aes-256-cfb
 ${Green_font_prefix} 6.${Font_color_suffix} aes-256-ctr
 ${Green_font_prefix} 7.${Font_color_suffix} chacha20-ietf
 ${Green_font_prefix} 8.${Font_color_suffix} xchacha20
 ${Green_font_prefix} 9.${Font_color_suffix} aes-128-gcm            (AEAD)
 ${Green_font_prefix}10.${Font_color_suffix} aes-192-gcm            (AEAD)
 ${Green_font_prefix}11.${Font_color_suffix} aes-256-gcm            (AEAD)
 ${Green_font_prefix}12.${Font_color_suffix} chacha20-ietf-poly1305 (AEAD)

${Tip} chacha20 Для серийных методов шифрования не требуется устанавливать libsodium, версия Shadowsocks VPN интегрирована по умолчанию !" && echo
	read -e -p "(по умолчанию: 12. chacha20-ietf-poly1305):" ss_method
	[[ -z "${ss_method}" ]] && ss_cipher="12"
	if [[ ${ss_method} == "1" ]]; then
		ss_method="aes-128-cfb"
	elif [[ ${ss_method} == "2" ]]; then
		ss_method="aes-128-ctr"
	elif [[ ${ss_method} == "3" ]]; then
		ss_method="aes-192-cfb"
	elif [[ ${ss_method} == "4" ]]; then
		ss_method="aes-192-ctr"
	elif [[ ${ss_method} == "5" ]]; then
		ss_method="aes-256-cfb"
	elif [[ ${ss_method} == "6" ]]; then
		ss_method="aes-256-ctr"
	elif [[ ${ss_method} == "7" ]]; then
		ss_method="chacha20-ietf"
	elif [[ ${ss_method} == "8" ]]; then
		ss_method="xchacha20"
	elif [[ ${ss_method} == "9" ]]; then
		ss_method="aead_aes_128_gcm"
	elif [[ ${ss_method} == "10" ]]; then
		ss_method="aead_aes_192_gcm"
	elif [[ ${ss_method} == "11" ]]; then
		ss_method="aead_aes_256_gcm"
	elif [[ ${ss_method} == "12" ]]; then
		ss_method="aead_chacha20_poly1305"
	else
		ss_method="aead_chacha20_poly1305"
	fi
	echo && echo "========================"
	echo -e "	шифрование : ${Red_background_prefix} ${ss_method} ${Font_color_suffix}"
	echo "========================" && echo
}
Set_config_protocol(){
ss_protocol="origin"
}
Set_config_obfs(){
ss_obfs="plain"
}
Set_config_protocol_param(){
	while true
	do
	ss_protocol_param=""
	[[ -z "$ss_protocol_param" ]] && ss_protocol_param="" && break
	echo $((${ss_protocol_param}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ss_protocol_param} -ge 1 ]] && [[ ${ss_protocol_param} -le 9999 ]]; then
			break
		else
			echo -e "${Error} Введите корректный номер(1-9999)"
		fi
	else
		echo -e "${Error} Введите корректный номер(1-9999)"
	fi
	done
}
Set_config_speed_limit_per_con(){
	while true
	do
	ss_speed_limit_per_con=""
	[[ -z "$ss_speed_limit_per_con" ]] && ss_speed_limit_per_con=0 && break
	echo $((${ss_speed_limit_per_con}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ss_speed_limit_per_con} -ge 1 ]] && [[ ${ss_speed_limit_per_con} -le 131072 ]]; then
			break
		else
			echo -e "${Error} Введите корректный номер(1-131072)"
		fi
	else
		echo -e "${Error} Введите корректный номер(1-131072)"
	fi
	done
}
Set_config_speed_limit_per_user(){
	while true
	do
	echo
	ss_speed_limit_per_user=""
	[[ -z "$ss_speed_limit_per_user" ]] && ss_speed_limit_per_user=0 && break
	echo $((${ss_speed_limit_per_user}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ss_speed_limit_per_user} -ge 1 ]] && [[ ${ss_speed_limit_per_user} -le 131072 ]]; then
			break
		else
			echo -e "${Error} Введите корректный номер(1-131072)"
		fi
	else
		echo -e "${Error} Введите корректный номер(1-131072)"
	fi
	done
}
Set_config_transfer(){
	while true
	do
	echo
	ss_transfer=""
	[[ -z "$ss_transfer" ]] && ss_transfer="838868" && break
	echo $((${ss_transfer}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ss_transfer} -ge 1 ]] && [[ ${ss_transfer} -le 838868 ]]; then
			break
		else
			echo -e "${Error} Введите корректный номер(1-838868)"
		fi
	else
		echo -e "${Error} Введите корректный номер(1-838868)"
	fi
	done
}
Set_config_forbid(){
	ss_forbid=""
	[[ -z "${ss_forbid}" ]] && ss_forbid=""
}
Set_config_enable(){
	user_total=$(echo $((${user_total}-1)))
	for((integer = 0; integer <= ${user_total}; integer++))
	do
		echo -e "integer=${integer}"
		port_jq=$(${jq_file} ".[${integer}].port" "${config_user_mudb_file}")
		echo -e "port_jq=${port_jq}"
		if [[ "${ss_port}" == "${port_jq}" ]]; then
			enable=$(${jq_file} ".[${integer}].enable" "${config_user_mudb_file}")
			echo -e "enable=${enable}"
			[[ "${enable}" == "null" ]] && echo -e "${Error} Не удалось получить отключенный статус текущего порта [${ss_port}]!" && exit 1
			ss_port_num=$(cat "${config_user_mudb_file}"|grep -n '"port": '${ss_port}','|awk -F ":" '{print $1}')
			echo -e "ss_port_num=${ss_port_num}"
			[[ "${ssr_port_num}" == "null" ]] && echo -e "${Error} Не удалось получить количество строк текущего порта[${ss_port}]!" && exit 1
			ss_enable_num=$(echo $((${ss_port_num}-5)))
			echo -e "ss_enable_num=${ssr_enable_num}"
			break
		fi
	done
	if [[ "${enable}" == "1" ]]; then
		echo -e "Порт [${ssr_port}] находится в состоянии：${Green_font_prefix}включен${Font_color_suffix} , сменить статус на ${Red_font_prefix}выключен${Font_color_suffix} ?[Y/n]"
		read -e -p "(По умолчанию: Y):" ss_enable_yn
		[[ -z "${ss_enable_yn}" ]] && ss_enable_yn="y"
		if [[ "${ss_enable_yn}" == [Yy] ]]; then
			ss_enable="0"
		else
			echo "Отмена..." && exit 0
		fi
	elif [[ "${enable}" == "0" ]]; then
		echo -e "Порт [${ssr_port}] находится в состоянии：${Green_font_prefix}отключен${Font_color_suffix} , сменить статус на  ${Red_font_prefix}включен${Font_color_suffix} ?[Y/n]"
		read -e -p "(По умолчанию: Y):" ss_enable_yn
		[[ -z "${ss_enable_yn}" ]] && ss_enable_yn = "y"
		if [[ "${ss_enable_yn}" == [Yy] ]]; then
			ss_enable="1"
		else
			echo "Отмена..." && exit 0
		fi
	else
		echo -e "${Error} какая то ошибка с акком, гг[${enable}] !" && exit 1
	fi
}
Set_user_api_server_pub_addr(){
	addr=$1
	if [[ "${addr}" == "Modify" ]]; then
		server_pub_addr=$(cat ${config_user_api_file}|grep "SERVER_PUB_ADDR = "|awk -F "[']" '{print $2}')
		if [[ -z ${server_pub_addr} ]]; then
			echo -e "${Error} Не получилось получить IP сервера！" && exit 1
		else
			echo -e "${Info} Текущий IP： ${Green_font_prefix}${server_pub_addr}${Font_color_suffix}"
		fi
	fi
	echo "Введите IP сервера"
	read -e -p "(Автоматическое определние IP при нажатии Enter):" ss_server_pub_addr
	if [[ -z "${ss_server_pub_addr}" ]]; then
		Get_IP
		if [[ ${ip} == "VPS_IP" ]]; then
			while true
			do
			read -e -p "${Error} Введите IP сервера сами!" ss_server_pub_addr
			if [[ -z "$ss_server_pub_addr" ]]; then
				echo -e "${Error} Не может быть пустым！"
			else
				break
			fi
			done
		else
			ss_server_pub_addr="${ip}"
		fi
	fi
	echo && echo ${Separator_1} && echo -e "	IP сервера : ${Green_font_prefix}${ssr_server_pub_addr}${Font_color_suffix}" && echo ${Separator_1} && echo
}
Set_config_all(){
	lal=$1
	if [[ "${lal}" == "Modify" ]]; then
		Set_config_password
		Set_config_method
		Set_config_protocol
		Set_config_obfs
		Set_config_protocol_param
		Set_config_speed_limit_per_con
		Set_config_speed_limit_per_user
		Set_config_transfer
		Set_config_forbid
	else
		Set_config_user
		Set_config_port
		Set_config_password
		Set_config_method
		Set_config_protocol
		Set_config_obfs
		Set_config_protocol_param
		Set_config_speed_limit_per_con
		Set_config_speed_limit_per_user
		Set_config_transfer
		Set_config_forbid
	fi
}
# Изменить конфигурацию клиента
Modify_config_password(){
	match_edit=$(python mujson_mgr.py -e -p "${ss_port}" -k "${ss_password}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Не удалось изменить пароль пользователя ${Green_font_prefix}[Порт: ${ss_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Пароль пользователя успешно изменен ${Green_font_prefix}[Порт: ${ss_port}]${Font_color_suffix} (Может занять около 10 секунд для обновления конфигурации)"
	fi
}
Modify_config_method(){
	match_edit=$(python mujson_mgr.py -e -p "${ss_port}" -m "${ss_method}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Не удалось изменить шифрование ${Green_font_prefix}[Порт: ${ss_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Шифрование успешно изменено ${Green_font_prefix}[Порт: ${ss_port}]${Font_color_suffix} (Может занять около 10 секунд для обновления конфигурации)"
	fi
}
Modify_config_protocol(){
	match_edit=$(python mujson_mgr.py -e -p "${ss_port}" -O "${ss_protocol}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Не удалось изменить протокол ${Green_font_prefix}[Порт: ${ss_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Протокол успешно изменен ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} (Может занять около 10 секунд для обновления конфигурации)"
	fi
}
Modify_config_obfs(){
	match_edit=$(python mujson_mgr.py -e -p "${ss_port}" -o "${ss_obfs}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Не удалось изменить Obfs plugin ${Green_font_prefix}[Порт: ${ss_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Obfs plugin успешно изменен ${Green_font_prefix}[Порт: ${ss_port}]${Font_color_suffix} (Может занять около 10 секунд для обновления конфигурации)"
	fi
}
Modify_config_protocol_param(){
	match_edit=$(python mujson_mgr.py -e -p "${ss_port}" -G "${ss_protocol_param}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Не удалось изменить лимит устройств ${Green_font_prefix}[Порт: ${ss_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Лимит устройств успешно изменен ${Green_font_prefix}[Порт: ${ss_port}]${Font_color_suffix} (Может занять около 10 секунд для обновления конфигурации)"
	fi
}
Modify_config_speed_limit_per_con(){
	match_edit=$(python mujson_mgr.py -e -p "${ss_port}" -s "${ss_speed_limit_per_con}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Не удалось изменить лимит скорости ключа ${Green_font_prefix}[Порт: ${ss_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Лимит скорости ключа успешно изменен ${Green_font_prefix}[Порт: ${ss_port}]${Font_color_suffix} (Может занять около 10 секунд для обновления конфигурации)"
	fi
}
Modify_config_speed_limit_per_user(){
	match_edit=$(python mujson_mgr.py -e -p "${ss_port}" -S "${ss_speed_limit_per_user}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Не удалось изменить лимит скорости пользователей ${Green_font_prefix}[Порт: ${ss_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Лимит скорости пользователей успешно изменен ${Green_font_prefix}[Порт: ${ss_port}]${Font_color_suffix} (Может занять около 10 секунд для обновления конфигурации)"
	fi
}
Modify_config_speed_limit_per_user(){
	match_edit=$(python mujson_mgr.py -e -p "${ss_port}" -S "${ss_speed_limit_per_user}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Не удалось изменить лимит скорости пользователей ${Green_font_prefix}[Порт: ${ss_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Лимит скорости пользователей успешно изменен ${Green_font_prefix}[Порт: ${ss_port}]${Font_color_suffix} (Может занять около 10 секунд для обновления конфигурации)"
	fi
}
Modify_config_connect_verbose_info(){
	sed -i 's/"connect_verbose_info": '"$(echo ${connect_verbose_info})"',/"connect_verbose_info": '"$(echo ${ss_connect_verbose_info})"',/g' ${config_user_file}
}
Modify_config_transfer(){
	match_edit=$(python mujson_mgr.py -e -p "${ss_port}" -t "${ss_transfer}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Не удалось изменить общий трафик пользователя ${Green_font_prefix}[Порт: ${ss_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Общий трафик пользователя успешно изменен ${Green_font_prefix}[Порт: ${ss_port}]${Font_color_suffix} (Может занять около 10 секунд для обновления конфигурации)"
	fi
}
Modify_config_forbid(){
	match_edit=$(python mujson_mgr.py -e -p "${ss_port}" -f "${ss_forbid}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Не удалось изменить запрещенные порты пользователя ${Green_font_prefix}[Порт: ${ss_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Запрещенные порты пользователя успешно изменены ${Green_font_prefix}[Порт: ${ss_port}]${Font_color_suffix} (Может занять около 10 секунд для обновления конфигурации)"
	fi
}
Modify_config_enable(){
	sed -i "${ss_enable_num}"'s/"enable": '"$(echo ${enable})"',/"enable": '"$(echo ${ss_enable})"',/' ${config_user_mudb_file}
}
Modify_user_api_server_pub_addr(){
	sed -i "s/SERVER_PUB_ADDR = '${server_pub_addr}'/SERVER_PUB_ADDR = '${ss_server_pub_addr}'/" ${config_user_api_file}
}
Modify_config_all(){
	Modify_config_password
	Modify_config_method
	Modify_config_protocol
	Modify_config_obfs
	Modify_config_protocol_param
	Modify_config_speed_limit_per_con
	Modify_config_speed_limit_per_user
	Modify_config_transfer
	Modify_config_forbid
}
Check_python(){
	python_ver=`python -h`
	if [[ -z ${python_ver} ]]; then
		echo -e "${Info} Python не установлен, начинаю установку..."
		if [[ ${release} == "centos" ]]; then
			yum install -y python
		else
			apt-get install -y python
		fi
	fi
}
Centos_yum(){
	yum update
	cat /etc/redhat-release |grep 7\..*|grep -i centos>/dev/null
	if [[ $? = 0 ]]; then
		yum install -y vim unzip crond net-tools
	else
		yum install -y vim unzip crond
	fi
}
Debian_apt(){
	apt-get update
	cat /etc/issue |grep 9\..*>/dev/null
	if [[ $? = 0 ]]; then
		apt-get install -y vim unzip cron net-tools
	else
		apt-get install -y vim unzip cron
	fi
}
# Скачать ShadowsocksR
Download_SS(){
	cd "/usr/local"
	wget -N --no-check-certificate "https://github.com/ToyoDAdoubiBackup/shadowsocksr/archive/manyuser.zip"
	#git config --global http.sslVerify false
	#env GIT_SSL_NO_VERIFY=true git clone -b manyuser https://github.com/ToyoDAdoubiBackup/shadowsocksr.git
	#[[ ! -e ${ssr_folder} ]] && echo -e "${Error} Ошибка загрузки сервера Shadowsocks !" && exit 1
	[[ ! -e "manyuser.zip" ]] && echo -e "${Error} Не удалось скачать архив с Shadowsocks !" && rm -rf manyuser.zip && exit 1
	unzip "manyuser.zip"
	[[ ! -e "/usr/local/shadowsocksr-manyuser/" ]] && echo -e "${Error} Ошибка распаковки ShadowsocksR !" && rm -rf manyuser.zip && exit 1
	mv "/usr/local/shadowsocksr-manyuser/" "/usr/local/shadowsocksr/"
	[[ ! -e "/usr/local/shadowsocksr/" ]] && echo -e "${Error} Переименование ShadowsocksR неуспешно !" && rm -rf manyuser.zip && rm -rf "/usr/local/shadowsocksr-manyuser/" && exit 1
	rm -rf manyuser.zip
	cd "shadowsocksr"
	cp "${ss_folder}/config.json" "${config_user_file}"
	cp "${ss_folder}/mysql.json" "${ssr_folder}/usermysql.json"
	cp "${ss_folder}/apiconfig.py" "${config_user_api_file}"
	[[ ! -e ${config_user_api_file} ]] && echo -e "${Error} Не удалось скопировать apiconfig.py для ShadowsocksR !" && exit 1
	sed -i "s/API_INTERFACE = 'sspanelv2'/API_INTERFACE = 'mudbjson'/" ${config_user_api_file}
	server_pub_addr="127.0.0.1"
	Modify_user_api_server_pub_addr
	#sed -i "s/SERVER_PUB_ADDR = '127.0.0.1'/SERVER_PUB_ADDR = '${ip}'/" ${config_user_api_file}
	sed -i 's/ \/\/ only works under multi-user mode//g' "${config_user_file}"
	echo -e "${Info} Shadowsocks успешно установлен !"
}
Service_SS(){
	if [[ ${release} = "centos" ]]; then
		if ! wget --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubiBackup/doubi/master/service/ssrmu_centos -O /etc/init.d/ssrmu; then
			echo -e "${Error} Не удалось загрузить скрипт для управления Shadowsocks !" && exit 1
		fi
		chmod +x /etc/init.d/ssrmu
		chkconfig --add ssrmu
		chkconfig ssrmu on
	else
		if ! wget --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubiBackup/doubi/master/service/ssrmu_debian -O /etc/init.d/ssrmu; then
			echo -e "${Error} Не удалось загрузить скрипт для управления Shadowsocks !" && exit 1
		fi
		chmod +x /etc/init.d/ssrmu
		update-rc.d -f ssrmu defaults
	fi
	echo -e "${Info} Скрипт для управления Shadowsocks успешно установлен !"
}
# Зависимость от установки
Installation_dependency(){
	if [[ ${release} == "centos" ]]; then
		Centos_yum
	else
		Debian_apt
	fi
	[[ ! -e "/usr/bin/unzip" ]] && echo -e "${Error} Установка unzip неуспешна !" && exit 1
	Check_python
	#echo "nameserver 8.8.8.8" > /etc/resolv.conf
	#echo "nameserver 8.8.4.4" >> /etc/resolv.conf
	\cp -f /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
	if [[ ${release} == "centos" ]]; then
		/etc/init.d/crond restart
	else
		/etc/init.d/cron restart
	fi
}
Install_SS(){
	check_root
	[[ -e ${ss_folder} ]] && echo -e "${Error} Shadowsocks уже установлен !" && exit 1
	echo -e "${Info} типа че то происходит..."
	Set_user_api_server_pub_addr
	Set_config_all
	echo -e "${Info} типа че то происходит..."
	Installation_dependency
	echo -e "${Info} типа че то происходит..."
	Download_SS
	echo -e "${Info} типа че то происходит..."
	Service_SS
	echo -e "${Info} типа че то происходит..."
	Add_port_user "install"
	echo -e "${Info} типа че то происходит..."
	Set_iptables
	echo -e "${Info} типа че то происходит..."
	Add_iptables
	echo -e "${Info} типа че то происходит..."
	Save_iptables
	echo -e "${Info} типа че то происходит..."
	Start_SS
	Get_User_info "${ss_port}"
	View_User_info
}
Update_SS(){
	SS_installation_status
	echo -e "Данная функция отключена."
	#cd ${ss_folder}
	#git pull
	#Restart_SS
}
Uninstall_SS(){
	[[ ! -e ${ss_folder} ]] && echo -e "${Error} Shadowsocks не установлен !" && exit 1
	echo "Удалить Shadowsocks？[y/N]" && echo
	read -e -p "(По умолчанию: n):" unyn
	[[ -z ${unyn} ]] && unyn="n"
	if [[ ${unyn} == [Yy] ]]; then
		check_pid
		[[ ! -z "${PID}" ]] && kill -9 ${PID}
		user_info=$(python mujson_mgr.py -l)
		user_total=$(echo "${user_info}"|wc -l)
		if [[ ! -z ${user_info} ]]; then
			for((integer = 1; integer <= ${user_total}; integer++))
			do
				port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
				Del_iptables
			done
			Save_iptables
		fi
		if [[ ! -z $(crontab -l | grep "ssrmu.sh") ]]; then
			crontab_monitor_ssr_cron_stop
			Clear_transfer_all_cron_stop
		fi
		if [[ ${release} = "centos" ]]; then
			chkconfig --del ssrmu
		else
			update-rc.d -f ssrmu remove
		fi
		rm -rf ${ssr_folder} && rm -rf /etc/init.d/ssrmu
		echo && echo " Shadowsocks
 успешно удален !" && echo
	else
		echo && echo " Отмена..." && echo
	fi
}
Check_Libsodium_ver(){
	echo -e "${Info} Начинаю получение последней версии libsodium..."
	Libsodiumr_ver=$(wget -qO- "https://github.com/jedisct1/libsodium/tags"|grep "/jedisct1/libsodium/releases/tag/"|head -1|sed -r 's/.*tag\/(.+)\">.*/\1/')
	[[ -z ${Libsodiumr_ver} ]] && Libsodiumr_ver=${Libsodiumr_ver_backup}
	echo -e "${Info} Последняя версия libsodium: ${Green_font_prefix}${Libsodiumr_ver}${Font_color_suffix} !"
}
Install_Libsodium(){
	if [[ -e ${Libsodiumr_file} ]]; then
		echo -e "${Error} libsodium уже установлен, желаете перезаписать(обновить)？[y/N]"
		read -e -p "(По умолчанию: n):" yn
		[[ -z ${yn} ]] && yn="n"
		if [[ ${yn} == [Nn] ]]; then
			echo "Отмена..." && exit 1
		fi
	else
		echo -e "${Info} libsodium не установлен, начинаю установку..."
	fi
	Check_Libsodium_ver
	if [[ ${release} == "centos" ]]; then
		yum update
		echo -e "${Info} бла бла бла..."
		yum -y groupinstall "Development Tools"
		echo -e "${Info} скачивание..."
		#https://github.com/jedisct1/libsodium/releases/download/1.0.18-RELEASE/libsodium-1.0.18.tar.gz
		wget  --no-check-certificate -N "https://github.com/jedisct1/libsodium/releases/download/${Libsodiumr_ver}-RELEASE/libsodium-${Libsodiumr_ver}.tar.gz"
		echo -e "${Info} распаковка..."
		tar -xzf libsodium-${Libsodiumr_ver}.tar.gz && cd libsodium-${Libsodiumr_ver}
		echo -e "${Info} установка..."
		./configure --disable-maintainer-mode && make -j2 && make install
		echo /usr/local/lib > /etc/ld.so.conf.d/usr_local_lib.conf
	else
		apt-get update
		echo -e "${Info} бла бла бла..."
		apt-get install -y build-essential
		echo -e "${Info} скачивание..."
		wget  --no-check-certificate -N "https://github.com/jedisct1/libsodium/releases/download/${Libsodiumr_ver}-RELEASE/libsodium-${Libsodiumr_ver}.tar.gz"
		echo -e "${Info} распаковка..."
		tar -xzf libsodium-${Libsodiumr_ver}.tar.gz && cd libsodium-${Libsodiumr_ver}
		echo -e "${Info} установка..."
		./configure --disable-maintainer-mode && make -j2 && make install
	fi
	ldconfig
	cd .. && rm -rf libsodium-${Libsodiumr_ver}.tar.gz && rm -rf libsodium-${Libsodiumr_ver}
	[[ ! -e ${Libsodiumr_file} ]] && echo -e "${Error} Установка libsodium неуспешна !" && exit 1
	echo && echo -e "${Info} libsodium успешно установлен !" && echo
}
# BBR
Configure_BBR(){
	echo && echo -e "  Что будем делать？
	
 ${Green_font_prefix}1.${Font_color_suffix} Установить BBR
————————
 ${Green_font_prefix}2.${Font_color_suffix} Запустить BBR
 ${Green_font_prefix}3.${Font_color_suffix} Остановить BBR
 ${Green_font_prefix}4.${Font_color_suffix} Просмотреть статус BBR" && echo
echo -e "${Green_font_prefix} [ВНИМАТЕЛЬНО ПРОЧИТАЙТЕ ТЕКСТ СНИЗУ!!!] ${Font_color_suffix}
1. Для успешной установки BBR нужно заменить ядро, что может привести к поломке сервера
2. OpenVZ и Docker не поддерживают данную функцию, нужен Debian/Ubuntu!
3. Если у вас система Debian, то при выборе [ При остановке деинсталлирования ядра ] ，то выберите ${Green_font_prefix} NO ${Font_color_suffix}" && echo
	read -e -p "(По умолчанию: отмена):" bbr_num
	[[ -z "${bbr_num}" ]] && echo "Отмена..." && exit 1
	if [[ ${bbr_num} == "1" ]]; then
		Install_BBR
	elif [[ ${bbr_num} == "2" ]]; then
		Start_BBR
	elif [[ ${bbr_num} == "3" ]]; then
		Stop_BBR
	elif [[ ${bbr_num} == "4" ]]; then
		Status_BBR
	else
		echo -e "${Error} Выберите корректный номер(1-4)" && exit 1
	fi
}
Install_BBR(){
	[[ ${release} = "centos" ]] && echo -e "${Error} Скрипт не поддерживает установку BBR на CentOS !" && exit 1
	BBR_installation_status
	bash "${BBR_file}"
}
Start_BBR(){
	BBR_installation_status
	bash "${BBR_file}" start
}
Stop_BBR(){
	BBR_installation_status
	bash "${BBR_file}" stop
}
Status_BBR(){
	BBR_installation_status
	bash "${BBR_file}" status
}
# Прочие функции
Other_functions(){
	echo && echo -e "  Что будем делать？
	
  ${Green_font_prefix}1.${Font_color_suffix} Настроить BBR
  ${Green_font_prefix}2.${Font_color_suffix} Настроить Sharp Speed(ServerSpeeder)
  ${Tip} Rui Su/BBR не поддерживают OpenVZ！
————————————
  ${Green_font_prefix}4.${Font_color_suffix} 一Блокировка BT/PT/SPAM в один клик (iptables)
  ${Green_font_prefix}5.${Font_color_suffix} 一Разблокировка BT/PT/SPAM в один клик (iptables)
————————————
  ${Green_font_prefix}6.${Font_color_suffix} Изменить тип вывода лога Shadowsocks
  —— Подсказка：SS по умолчанию выводит только ошибочные логи. Лог можно изменить на более детализированный。
  ${Green_font_prefix}7.${Font_color_suffix} Монитор текущего статуса Shadowsocks
  —— Подсказка： Эта функция очень полезна если SS часто выключается. Каждую минуту скрипт будеть проверять статус Shadowsocks, и если он выключен, включать его" && echo
	read -e -p "(По умолчанию: отмена):" other_num
	[[ -z "${other_num}" ]] && echo "Отмена..." && exit 1
	if [[ ${other_num} == "1" ]]; then
		Configure_BBR
	elif [[ ${other_num} == "2" ]]; then
		Configure_Server_Speeder
	elif [[ ${other_num} == "3" ]]; then
		BanBTPTSPAM
	elif [[ ${other_num} == "4" ]]; then
		UnBanBTPTSPAM
	elif [[ ${other_num} == "5" ]]; then
		Set_config_connect_verbose_info
	elif [[ ${other_num} == "6" ]]; then
		Set_crontab_monitor_ss
	else
		echo -e "${Error} Введите корректный номер [1-7]" && exit 1
	fi
}
# Запретить BT PT SPAM
BanBTPTSPAM(){
	wget -N --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubiBackup/doubi/master/ban_iptables.sh && chmod +x ban_iptables.sh && bash ban_iptables.sh banall
	rm -rf ban_iptables.sh
}
# Разблокировать BT PT SPAM
UnBanBTPTSPAM(){
	wget -N --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubiBackup/doubi/master/ban_iptables.sh && chmod +x ban_iptables.sh && bash ban_iptables.sh unbanall
	rm -rf ban_iptables.sh
}
Set_config_connect_verbose_info(){
	SS_installation_status
	[[ ! -e ${jq_file} ]] && echo -e "${Error} Отсутствует парсер JQ !" && exit 1
	connect_verbose_info=`${jq_file} '.connect_verbose_info' ${config_user_file}`
	if [[ ${connect_verbose_info} = "0" ]]; then
		echo && echo -e "Текущий режим логирования: ${Green_font_prefix}простой（только ошибки）${Font_color_suffix}" && echo
		echo -e "Вы уверены, что хотите сменить его на  ${Green_font_prefix}детализированный(Детальный лог соединений + ошибки)${Font_color_suffix}？[y/N]"
		read -e -p "(По умолчанию: n):" connect_verbose_info_ny
		[[ -z "${connect_verbose_info_ny}" ]] && connect_verbose_info_ny="n"
		if [[ ${connect_verbose_info_ny} == [Yy] ]]; then
			ss_connect_verbose_info="1"
			Modify_config_connect_verbose_info
			Restart_SS
		else
			echo && echo "	Отмена..." && echo
		fi
	else
		echo && echo -e "Текущий режим логирования: ${Green_font_prefix}детализированный(Детальный лог соединений + ошибки)${Font_color_suffix}" && echo
		echo -e "Вы уверены, что хотите сменить его на  ${Green_font_prefix}простой（только ошибки）${Font_color_suffix}？[y/N]"
		read -e -p "(По умолчанию: n):" connect_verbose_info_ny
		[[ -z "${connect_verbose_info_ny}" ]] && connect_verbose_info_ny="n"
		if [[ ${connect_verbose_info_ny} == [Yy] ]]; then
			ss_connect_verbose_info="0"
			Modify_config_connect_verbose_info
			Restart_SS
		else
			echo && echo "	Отмена..." && echo
		fi
	fi
}
Set_crontab_monitor_ss(){
	SS_installation_status
	crontab_monitor_ss_status=$(crontab -l|grep "ssrmu.sh monitor")
	if [[ -z "${crontab_monitor_ssr_status}" ]]; then
		echo && echo -e "Текущий статус мониторинга: ${Green_font_prefix}выключен${Font_color_suffix}" && echo
		echo -e "Вы уверены что хотите включить ${Green_font_prefix}функцию мониторинга Shadowsocks${Font_color_suffix}？(При отключении SS, он будет запущен автоматически)[Y/n]"
		read -e -p "(По умолчанию: y):" crontab_monitor_ssr_status_ny
		[[ -z "${crontab_monitor_ss_status_ny}" ]] && crontab_monitor_ss_status_ny="y"
		if [[ ${crontab_monitor_ss_status_ny} == [Yy] ]]; then
			crontab_monitor_ss_cron_start
		else
			echo && echo "	Отмена..." && echo
		fi
	else
		echo && echo -e "Текущий статус мониторинга: ${Green_font_prefix}включен${Font_color_suffix}" && echo
		echo -e "Вы уверены что хотите выключить ${Green_font_prefix}функцию мониторинга Shadowsocks${Font_color_suffix}？(При отключении SS, он будет запущен автоматически)[y/N]"
		read -e -p "(По умолчанию: n):" crontab_monitor_ssr_status_ny
		[[ -z "${crontab_monitor_ssr_status_ny}" ]] && crontab_monitor_ss_status_ny="n"
		if [[ ${crontab_monitor_ssr_status_ny} == [Yy] ]]; then
			crontab_monitor_ssr_cron_stop
		else
			echo && echo "	Отмена..." && echo
		fi
	fi
}
crontab_monitor_ss(){
	SS_installation_status
	check_pid
	if [[ -z ${PID} ]]; then
		echo -e "${Error} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] Замечено что SS не запущен, запускаю..." | tee -a ${ss_log_file}
		/etc/init.d/ssrmu start
		sleep 1s
		check_pid
		if [[ -z ${PID} ]]; then
			echo -e "${Error} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] Shadowsocks не удалось запустить..." | tee -a ${ss_log_file} && exit 1
		else
			echo -e "${Info} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] Shadowsocks успешно установлен..." | tee -a ${ss_log_file} && exit 1
		fi
	else
		echo -e "${Info} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] Shadowsocks успешно работает..." exit 0
	fi
}
crontab_monitor_ss_cron_start(){
	crontab -l > "$file/crontab.bak"
	sed -i "/ssrmu.sh monitor/d" "$file/crontab.bak"
	echo -e "\n* * * * * /bin/bash $file/ssrmu.sh monitor" >> "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ssrmu.sh monitor")
	if [[ -z ${cron_config} ]]; then
		echo -e "${Error} Не удалось запустить функцию мониторинга Shadowsocks  !" && exit 1
	else
		echo -e "${Info} Функция мониторинга Shadowsocks успешно запущена !"
	fi
}
crontab_monitor_ss_cron_stop(){
	crontab -l > "$file/crontab.bak"
	sed -i "/ssrmu.sh monitor/d" "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ssrmu.sh monitor")
	if [[ ! -z ${cron_config} ]]; then
		echo -e "${Error} Не удалось остановить функцию моинторинга сервера Shadowsocks !" && exit 1
	else
		echo -e "${Info} Функция мониторинга сервера Shadowsocks успешно остановлена !"
	fi
}
Update_Shell(){
	sh_new_ver=$(wget --no-check-certificate -qO- -t1 -T3 "https://raw.githubusercontent.com/ToyoDAdoubiBackup/doubi/master/ssrmu.sh"|grep 'sh_ver="'|awk -F "=" '{print $NF}'|sed 's/\"//g'|head -1) && sh_new_type="github"
	[[ -z ${sh_new_ver} ]] && echo -e "${Error} Не удается подключиться к Github !" && exit 0
	if [[ -e "/etc/init.d/ssrmu" ]]; then
		rm -rf /etc/init.d/ssrmu
		Service_SSR
	fi
	cd "${file}"
	wget -N --no-check-certificate "https://raw.githubusercontent.com/ToyoDAdoubiBackup/doubi/master/ssrmu.sh" && chmod +x ssrmu.sh
	echo -e "Скрипт успешно обновлен до версии[ ${sh_new_ver} ] !(Так как обновление - перезапись, то далее могут выйти ошибки, просто инорируйте их)" && exit 0
}
# Отображение статуса меню
menu_status(){
	if [[ -e ${ss_folder} ]]; then
		check_pid
		if [[ ! -z "${PID}" ]]; then
			echo -e " Текущий статус: ${Green_font_prefix}установлен${Font_color_suffix} и ${Green_font_prefix}запущен${Font_color_suffix}"
		else
			echo -e " Текущий статус: ${Green_font_prefix}установлен${Font_color_suffix} но ${Red_font_prefix}не запущен${Font_color_suffix}"
		fi
		cd "${ss_folder}"
	else
		echo -e " Текущий статус: ${Red_font_prefix}не установлен${Font_color_suffix}"
	fi
}
Server_IP_Checker(){
	 echo -e "IP данного сервера = $(curl "ifconfig.me") " && echo
}
check_sys
[[ ${release} != "debian" ]] && [[ ${release} != "ubuntu" ]] && [[ ${release} != "centos" ]] && echo -e "${Error} Этот скрипт не поддерживает текущую систему ${release} !" && exit 1
action=$1
if [[ "${action}" == "clearall" ]]; then
	Clear_transfer_all
elif [[ "${action}" == "monitor" ]]; then
	crontab_monitor_ss
else
        echo -e " Скрипт модерации сервера Shadowsocks ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
	---- LEGENDA VPN USER CONTROL ----
"
echo -e "Салам алейкум, администратор сервера!
  ${Green_font_prefix}1.${Font_color_suffix} Установить ShadowsocksR
  ${Green_font_prefix}2.${Font_color_suffix} Обновить ShadowsocksR
  ${Green_font_prefix}3.${Font_color_suffix} Удалить ShadowsocksR
  ${Green_font_prefix}4.${Font_color_suffix} Установить libsodium
  ${Green_font_prefix}5.${Font_color_suffix} Посмотреть информацию о пользователях
  ${Green_font_prefix}6.${Font_color_suffix} Показать информацию о соединениях
  ${Green_font_prefix}7.${Font_color_suffix} Настройки конфигурации юзеров
  ${Green_font_prefix}8.${Font_color_suffix} Вручную изменить конфигурацию
  ${Green_font_prefix}9.${Font_color_suffix} Очистка информации о трафике пользователей
————————————
 ${Green_font_prefix}10.${Font_color_suffix} Запустить ShadowsocksR
 ${Green_font_prefix}11.${Font_color_suffix} Остановить ShadowsocksR
 ${Green_font_prefix}12.${Font_color_suffix} Перезапустить ShadowsocksR
 ${Green_font_prefix}13.${Font_color_suffix} Просмотреть лог ShadowsocksR
————————————
 ${Green_font_prefix}14.${Font_color_suffix} Другие функции
 ${Green_font_prefix}15.${Font_color_suffix} Просмотреть IP адрес сервера
 "
        menu_status
	echo && read -e -p "Введите корректный номер [1-15]：" num
case "$num" in
	1)
	Install_SS
	;;
	2)
	Update_SS
	;;
	3)
	Uninstall_SS
	;;
	4)
	Install_Libsodium
	;;
	5)
	View_User
	;;
	6)
	View_user_connection_info
	;;
	7)
	Modify_Config
	;;
	8)
	Manually_Modify_Config
	;;
	9)
	Clear_transfer
	;;
	10)
	Start_SS
	;;
	11)
	Stop_SS
	;;
	12)
	Restart_SS
	;;
	13)
	View_Log
	;;
	14)
	Other_functions
	;;
	15)
	Server_IP_Checker
        ;;
	*)
	echo -e "${Error} Введите корректный номер [1-15]"
	;;
esac
fi
