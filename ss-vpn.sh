#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#=================================================
#	System Required: CentOS/Debian/Ubuntu
#	Description: Shadowsocks VPN
#	Version: 1.0.0
#	Author: Legenda
#=================================================

sh_ver="1.0.0"
filepath=$(cd "$(dirname "$0")"; pwd)
file_1=$(echo -e "${filepath}"|awk -F "$0" '{print $1}')
FOLDER="/usr/local/shadowsocks-go"
FILE="/usr/local/shadowsocks-go/shadowsocks-go"
CONF="/usr/local/shadowsocks-go/shadowsocks-go.conf"
LOG="/usr/local/shadowsocks-go/shadowsocks-go.log"
Now_ver_File="/usr/local/shadowsocks-go/ver.txt"
Crontab_file="/usr/bin/crontab"

Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[Информация]${Font_color_suffix}"
Error="${Red_font_prefix}[Ошибка]${Font_color_suffix}"
Tip="${Green_font_prefix}[Заметка]${Font_color_suffix}"

check_root(){
	[[ $EUID != 0 ]] && echo -e "${Error} Текущая учетная запись без ROOT (или без разрешения ROOT)，невозможно продолжить работу, смените учетную запись ROOT или используйте ${Green_background_prefix}sudo su${Font_color_suffix} команда для получения временного ROOT-разрешения (может быть предложено ввести пароль текущей учетной записи после выполнения)。" && exit 1
}
# Проверить систему
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
check_installed_status(){
	[[ ! -e ${FILE} ]] && echo -e "${Error} Shadowsocks не установлено, проверьте !" && exit 1
}
check_crontab_installed_status(){
	if [[ ! -e ${Crontab_file} ]]; then
		echo -e "${Error} Crontab нет установки, начать установку..."
		if [[ ${release} == "centos" ]]; then
			yum install crond -y
		else
			apt-get install cron -y
		fi
		if [[ ! -e ${Crontab_file} ]]; then
			echo -e "${Error} Crontab установка не удалась, проверьте！" && exit 1
		else
			echo -e "${Info} Crontab успешная установка！"
		fi
	fi
}
check_pid(){
	PID=$(ps -ef| grep "./shadowsocks-go "| grep -v "grep" | grep -v "init.d" |grep -v "service" |awk '{print $2}')
}
check_new_ver(){
	new_ver=$(wget -qO- https://api.github.com/repos/shadowsocks/go-shadowsocks2/releases| grep "tag_name"| head -n 1| awk -F ":" '{print $2}'| sed 's/\"//g;s/,//g;s/ //g')
	[[ -z ${new_ver} ]] && echo -e "${Error} Shadowsocks не удалось получить последнюю версию！" && exit 1
	echo -e "${Info} Обнаружена последняя версия Shadowsocks [ ${new_ver} ]"
}
check_ver_comparison(){
	now_ver=$(cat ${Now_ver_File})
	if [[ "${now_ver}" != "${new_ver}" ]]; then
		echo -e "${Info} Нашла новую версию Shadowsocks [ ${new_ver} ]，старая версия [ ${now_ver} ]"
		read -e -p "Обновить ? [Y/n] :" yn
		[[ -z "${yn}" ]] && yn="y"
		if [[ $yn == [Yy] ]]; then
			check_pid
			[[ ! -z $PID ]] && kill -9 ${PID}
			\cp "${CONF}" "/tmp/shadowsocks-go.conf"
			rm -rf ${FOLDER}
			Download
			mv "/tmp/shadowsocks-go.conf" "${CONF}"
			Start
		fi
	else
		echo -e "${Info} На данный момент Shadowsocks - последняя версия [ ${new_ver} ]" && exit 1
	fi
}
Download(){
	if [[ ! -e "${FOLDER}" ]]; then
		mkdir "${FOLDER}"
	else
		[[ -e "${FILE}" ]] && rm -rf "${FILE}"
	fi
	cd "${FOLDER}"
	if [[ ${bit} == "x86_64" ]]; then
		wget --no-check-certificate -N "https://github.com/shadowsocks/go-shadowsocks2/releases/download/${new_ver}/shadowsocks2-linux.gz"
	else
		echo -e "${Error} Shadowsocks-Go версия в настоящее время не поддерживает установку сервера с не 64-битной архитектурой, пожалуйста, измените систему !" && rm -rf "${FOLDER}" && exit 1
	fi
	[[ ! -e "shadowsocks2-linux.gz" ]] && echo -e "${Error} Shadowsocks не удалось загрузить сжатый пакет !" && rm -rf "${FOLDER}" && exit 1
	gzip -d "shadowsocks2-linux.gz"
	[[ ! -e "shadowsocks2-linux" ]] && echo -e "${Error} Shadowsocks не удалось распаковать сжатый пакет !" && rm -rf "${FOLDER}" && exit 1
	mv "shadowsocks2-linux" "shadowsocks-go"
	[[ ! -e "shadowsocks-go" ]] && echo -e "${Error} Shadowsocks не удалось переименовать !" && rm -rf "${FOLDER}" && exit 1
	chmod +x shadowsocks-go
	echo "${new_ver}" > ${Now_ver_File}
}
Service(){
	if [[ ${release} = "centos" ]]; then
		if ! wget --no-check-certificate "https://raw.githubusercontent.com/heweiye/ToyoDAdoubiBackup/master/service/ss_go_centos" -O /etc/init.d/ss-go; then
			echo -e "${Error} Shadowsocks ошибка загрузки сценария управления сервисом !"
			rm -rf "${FOLDER}"
			exit 1
		fi
		chmod +x "/etc/init.d/ss-go"
		chkconfig --add ss-go
		chkconfig ss-go on
	else
		if ! wget --no-check-certificate "https://raw.githubusercontent.com/heweiye/ToyoDAdoubiBackup/master/service/ss_go_debian" -O /etc/init.d/ss-go; then
			echo -e "${Error} Shadowsocks ошибка загрузки сценария управления сервисом !"
			rm -rf "${FOLDER}"
			exit 1
		fi
		chmod +x "/etc/init.d/ss-go"
		update-rc.d -f ss-go defaults
	fi
	echo -e "${Info} Shadowsocks скачивание скрипта управления сервисом завершено !"
}
Installation_dependency(){
	gzip_ver=$(gzip -V)
	if [[ -z ${gzip_ver} ]]; then
		if [[ ${release} == "centos" ]]; then
			yum update
			yum install -y gzip
		else
			apt-get update
			apt-get install -y gzip
		fi
	fi
	\cp -f /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
}
Write_config(){
	cat > ${CONF}<<-EOF
PORT = ${ss_port}
PASSWORD = ${ss_password}
CIPHER = ${ss_cipher}
VERBOSE = ${ss_verbose}
EOF
}
Read_config(){
	[[ ! -e ${CONF} ]] && echo -e "${Error} Shadowsocks файл конфигурации не существует !" && exit 1
	port=$(cat ${CONF}|grep 'ПОРТ = '|awk -F 'PORT = ' '{print $NF}')
	password=$(cat ${CONF}|grep 'ПАРОЛЬ = '|awk -F 'PASSWORD = ' '{print $NF}')
	cipher=$(cat ${CONF}|grep 'ШИФР = '|awk -F 'CIPHER = ' '{print $NF}')
	verbose=$(cat ${CONF}|grep 'ПОДРОБНЫЙ = '|awk -F 'VERBOSE = ' '{print $NF}')
}
Set_port(){
	while true
		do
		echo -e "Пожалуйста, введите в порт Shadowsocks [1-65535]"
		read -e -p "(по умолчанию: 443):" ss_port
		[[ -z "${ss_port}" ]] && ss_port="443"
		echo $((${ss_port}+0)) &>/dev/null
		if [[ $? -eq 0 ]]; then
			if [[ ${ss_port} -ge 1 ]] && [[ ${ss_port} -le 65535 ]]; then
				echo && echo "========================"
				echo -e "	порт : ${Red_background_prefix} ${ss_port} ${Font_color_suffix}"
				echo "========================" && echo
				break
			else
				echo "Ошибка ввода, введите правильный порт。"
			fi
		else
			echo "Ошибка ввода, введите правильный порт。"
		fi
		done
}
Set_password(){
	echo "Пожалуйста, введите пароль Shadowsocks [0-9][a-z][A-Z]"
	read -e -p "(по умолчанию: Сгенерировано случайным образом):" ss_password
	[[ -z "${ss_password}" ]] && ss_password=$(date +%s%N | md5sum | head -c 16)
	echo && echo "========================"
	echo -e "	пароль : ${Red_background_prefix} ${ss_password} ${Font_color_suffix}"
	echo "========================" && echo
}
Set_cipher(){
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
	read -e -p "(默认: 12. chacha20-ietf-poly1305):" ss_cipher
	[[ -z "${ss_cipher}" ]] && ss_cipher="12"
	if [[ ${ss_cipher} == "1" ]]; then
		ss_cipher="aes-128-cfb"
	elif [[ ${ss_cipher} == "2" ]]; then
		ss_cipher="aes-128-ctr"
	elif [[ ${ss_cipher} == "3" ]]; then
		ss_cipher="aes-192-cfb"
	elif [[ ${ss_cipher} == "4" ]]; then
		ss_cipher="aes-192-ctr"
	elif [[ ${ss_cipher} == "5" ]]; then
		ss_cipher="aes-256-cfb"
	elif [[ ${ss_cipher} == "6" ]]; then
		ss_cipher="aes-256-ctr"
	elif [[ ${ss_cipher} == "7" ]]; then
		ss_cipher="chacha20-ietf"
	elif [[ ${ss_cipher} == "8" ]]; then
		ss_cipher="xchacha20"
	elif [[ ${ss_cipher} == "9" ]]; then
		ss_cipher="aead_aes_128_gcm"
	elif [[ ${ss_cipher} == "10" ]]; then
		ss_cipher="aead_aes_192_gcm"
	elif [[ ${ss_cipher} == "11" ]]; then
		ss_cipher="aead_aes_256_gcm"
	elif [[ ${ss_cipher} == "12" ]]; then
		ss_cipher="aead_chacha20_poly1305"
	else
		ss_cipher="aead_chacha20_poly1305"
	fi
	echo && echo "========================"
	echo -e "	шифрование : ${Red_background_prefix} ${ss_cipher} ${Font_color_suffix}"
	echo "========================" && echo
}
Set_verbose(){
	echo -e "Следует ли включать режим подробного журнала？[Y/n]
Включите режим подробного журнала, чтобы просмотреть информацию о компоновщике в журнале (время ссылки, порт прокси-сервера, IP-адрес компоновщика, имя целевого домена или IP-адрес, который посещает компоновщик, не являются конфиденциальной информацией)。"
	read -e -p "(по умолчанию：N Отключить):" ss_verbose
	[[ -z "${ss_verbose}" ]] && ss_verbose="N"
	if [[ "${ss_verbose}" == [Yy] ]]; then
		ss_verbose="YES"
	else
		ss_verbose="NO"
	fi
	echo && echo "========================"
	echo -e "	Подробный режим журнала : ${Red_background_prefix} ${ss_verbose} ${Font_color_suffix}"
	echo "========================" && echo
}
Set(){
	check_installed_status
	echo && echo -e "чем ты планируешь заняться？
 ${Green_font_prefix}1.${Font_color_suffix}  Изменить конфигурацию порта
 ${Green_font_prefix}2.${Font_color_suffix}  Изменить конфигурацию пароля
 ${Green_font_prefix}3.${Font_color_suffix}  Изменить конфигурацию шифрования
 ${Green_font_prefix}4.${Font_color_suffix}  Измените подробную конфигурацию режима журнала
 ${Green_font_prefix}5.${Font_color_suffix}  Измените все конфигурации
————————————————
 ${Green_font_prefix}6.${Font_color_suffix}  Мониторинг рабочего состояния" && echo
	read -e -p "(по умолчанию: отменить):" ss_modify
	[[ -z "${ss_modify}" ]] && echo "Отменено..." && exit 1
	if [[ "${ss_modify}" == "1" ]]; then
		Read_config
		Set_port
		ss_password=${password}
		ss_cipher=${cipher}
		ss_verbose=${verbose}
		Write_config
		Del_iptables
		Add_iptables
		Restart
	elif [[ "${ss_modify}" == "2" ]]; then
		Read_config
		Set_password
		ss_port=${port}
		ss_cipher=${cipher}
		ss_verbose=${verbose}
		Write_config
		Restart
	elif [[ "${ss_modify}" == "3" ]]; then
		Read_config
		Set_cipher
		ss_port=${port}
		ss_password=${password}
		ss_verbose=${verbose}
		Write_config
		Restart
	elif [[ "${ss_modify}" == "4" ]]; then
		Read_config
		Set_verbose
		ss_port=${port}
		ss_password=${password}
		ss_cipher=${cipher}
		Write_config
		Restart
	elif [[ "${ss_modify}" == "5" ]]; then
		Read_config
		Set_port
		Set_password
		Set_cipher
		Set_verbose
		Write_config
		Restart
	elif [[ "${ss_modify}" == "6" ]]; then
		Set_crontab_monitor
	else
		echo -e "${Error} Пожалуйста, введите правильный номер(1-6)" && exit 1
	fi
}
Install(){
	check_root
	[[ -e ${FILE} ]] && echo -e "${Error} Shadowsocks обнаружен для установки !" && exit 1
	echo -e "${Info} Начать настройку конфигурация пользователя..."
	Set_port
	Set_password
	Set_cipher
	Set_verbose
	echo -e "${Info} Начать установку / настройку..."
	Installation_dependency
	echo -e "${Info} Начать скачивание / установку..."
	check_new_ver
	Download
	echo -e "${Info} Начать загрузку / установку служебного скрипта(init)..."
	Service
	echo -e "${Info} Начать писать файл конфигурации..."
	Write_config
	echo -e "${Info} Начните настройку брандмауэра iptables..."
	Set_iptables
	echo -e "${Info} Начните добавлять правила брандмауэра iptables..."
	Add_iptables
	echo -e "${Info} Начните сохранять правила брандмауэра iptables..."
	Save_iptables
	echo -e "${Info} Все ступени установлены, приступаем к запуску..."
	Start
}
Start(){
	check_installed_status
	check_pid
	[[ ! -z ${PID} ]] && echo -e "${Error} Shadowsocks работает, проверьте !" && exit 1
	/etc/init.d/ss-go start
	#sleep 1s
	check_pid
	[[ ! -z ${PID} ]] && View
}
Stop(){
	check_installed_status
	check_pid
	[[ -z ${PID} ]] && echo -e "${Error} Shadowsocks не работает, проверьте !" && exit 1
	/etc/init.d/ss-go stop
}
Restart(){
	check_installed_status
	check_pid
	[[ ! -z ${PID} ]] && /etc/init.d/ss-go stop
	/etc/init.d/ss-go start
	#sleep 1s
	check_pid
	[[ ! -z ${PID} ]] && View
}
Update(){
	check_installed_status
	check_new_ver
	check_ver_comparison
}
Uninstall(){
	check_installed_status
	echo "Убедитесь, что вы хотите удалить Shadowsocks ? (Y/n)"
	echo
	read -e -p "(по умолчанию: n):" unyn
	[[ -z ${unyn} ]] && unyn="n"
	if [[ ${unyn} == [Yy] ]]; then
		check_pid
		[[ ! -z $PID ]] && kill -9 ${PID}
		if [[ -e ${CONF} ]]; then
			port=$(cat ${CONF}|grep 'PORT = '|awk -F 'PORT = ' '{print $NF}')
			Del_iptables
			Save_iptables
		fi
		if [[ ! -z $(crontab -l | grep "ss-go.sh monitor") ]]; then
			crontab_monitor_cron_stop
		fi
		rm -rf "${FOLDER}"
		if [[ ${release} = "centos" ]]; then
			chkconfig --del ss-go
		else
			update-rc.d -f ss-go remove
		fi
		rm -rf "/etc/init.d/ss-go"
		echo && echo "Удаление Shadowsocks завершено !" && echo
	else
		echo && echo "Удаление отменено..." && echo
	fi
}
getipv4(){
	ipv4=$(wget -qO- -4 -t1 -T2 ipinfo.io/ip)
	if [[ -z "${ipv4}" ]]; then
		ipv4=$(wget -qO- -4 -t1 -T2 api.ip.sb/ip)
		if [[ -z "${ipv4}" ]]; then
			ipv4=$(wget -qO- -4 -t1 -T2 members.3322.org/dyndns/getip)
			if [[ -z "${ipv4}" ]]; then
				ipv4="IPv4_Error"
			fi
		fi
	fi
}
getipv6(){
	ipv6=$(wget -qO- -6 -t1 -T2 ifconfig.co)
	if [[ -z "${ipv6}" ]]; then
		ipv6="IPv6_Error"
	fi
}
urlsafe_base64(){
	date=$(echo -n "$1"|base64|sed ':a;N;s/\n/ /g;ta'|sed 's/ //g;s/=//g;s/+/-/g;s/\//_/g')
	echo -e "${date}"
}
ss_link_qr(){
	if [[ "${ipv4}" != "IPv4_Error" ]]; then
		if [[ "${cipher}" == "aead_chacha20_poly1305" ]]; then
			cipher_1="chacha20-ietf-poly1305"
		else
			cipher_1=$(echo "${cipher}"|sed 's/aead_//g;s/_/-/g')
		fi
		SSbase64=$(urlsafe_base64 "${cipher_1}:${password}@${ipv4}:${port}")
		SSurl="ss://${SSbase64}"
		SSQRcode="http://doub.pw/qr/qr.php?text=${SSurl}"
		ss_link_ipv4=" ссылка  [ipv4] : ${Red_font_prefix}${SSurl}${Font_color_suffix} \n QR код[ipv4] : ${Red_font_prefix}${SSQRcode}${Font_color_suffix}"
	fi
	if [[ "${ipv6}" != "IPv6_Error" ]]; then
		if [[ "${cipher}" == "aead_chacha20_poly1305" ]]; then
			cipher_1="chacha20-ietf-poly1305"
		else
			cipher_1=$(echo "${cipher}"|sed 's/aead_//g;s/_/-/g')
		fi
		SSbase64=$(urlsafe_base64 "${cipher_1}:${password}@${ipv6}:${port}")
		SSurl="ss://${SSbase64}"
		SSQRcode="http://doub.pw/qr/qr.php?text=${SSurl}"
		ss_link_ipv6=" ссылка  [ipv6] : ${Red_font_prefix}${SSurl}${Font_color_suffix} \n QR код[ipv6] : ${Red_font_prefix}${SSQRcode}${Font_color_suffix}"
	fi
}
View(){
	check_installed_status
	Read_config
	getipv4
	getipv6
	ss_link_qr
	if [[ "${cipher}" == "aead_chacha20_poly1305" ]]; then
		cipher_2="chacha20-ietf-poly1305"
	else
		cipher_2=$(echo "${cipher}"|sed 's/aead_//g;s/_/-/g')
	fi
	clear && echo
	echo -e "Конфигурация пользователя Shadowsocks："
	echo -e "————————————————"
	[[ "${ipv4}" != "IPv4_Error" ]] && echo -e " адрес\t: ${Green_font_prefix}${ipv4}${Font_color_suffix}"
	[[ "${ipv6}" != "IPv6_Error" ]] && echo -e " адрес\t: ${Green_font_prefix}${ipv6}${Font_color_suffix}"
	echo -e " порт\t: ${Green_font_prefix}${port}${Font_color_suffix}"
	echo -e " пароль\t: ${Green_font_prefix}${password}${Font_color_suffix}"
	echo -e " шифрование\t: ${Green_font_prefix}${cipher_2}${Font_color_suffix}"
	[[ ! -z "${ss_link_ipv4}" ]] && echo -e "${ss_link_ipv4}"
	[[ ! -z "${ss_link_ipv6}" ]] && echo -e "${ss_link_ipv6}"
	echo
	echo -e " Подробный режим журнала\t: ${Green_font_prefix}${verbose}${Font_color_suffix}"
	echo
}
View_Log(){
	check_installed_status
	[[ ! -e ${LOG} ]] && echo -e "${Error} Файл журнала Shadowsocks не существует !" && exit 1
	echo && echo -e "${Tip} Нажмите ${Red_font_prefix}Ctrl+C${Font_color_suffix} Прекратить просмотр журналов"
	echo -e "Если вам нужно просмотреть полное содержимое журнала, используйте ${Red_font_prefix}cat ${LOG}${Font_color_suffix} команда。"
	echo -e "Если вы хотите просмотреть подробные журналы, посетите [7.Настройки конфигурация учетной записи - 4.Измените подробную конфигурацию режима журнала] Включить。" && echo
	tail -f ${LOG}
}
# Отображение информации о подключении
View_user_connection_info_1(){
	format_1=$1
	Read_config
	user_IP=$(ss state connected sport = :${port} -tn|sed '1d'|awk '{print $NF}'|awk -F ':' '{print $(NF-1)}'|sort -u)
	if [[ -z ${user_IP} ]]; then
		user_IP_total="0"
		echo -e "порт: ${Green_font_prefix}"${port}"${Font_color_suffix}\t Общий IP-адрес ссылки: ${Green_font_prefix}"${user_IP_total}"${Font_color_suffix}\t Текущий IP-адрес ссылки: "
	else
		user_IP_total=$(echo -e "${user_IP}"|wc -l)
		if [[ ${format_1} == "IP_address" ]]; then
			echo -e "порт: ${Green_font_prefix}"${port}"${Font_color_suffix}\t Общий IP-адрес ссылки: ${Green_font_prefix}"${user_IP_total}"${Font_color_suffix}\t Текущий IP-адрес ссылки: "
			get_IP_address
			echo
		else
			user_IP=$(echo -e "\n${user_IP}")
			echo -e "порт: ${Green_font_prefix}"${user_port}"${Font_color_suffix}\t Общий IP-адрес ссылки: ${Green_font_prefix}"${user_IP_total}"${Font_color_suffix}\t Текущий IP-адрес ссылки: ${Green_font_prefix}${user_IP}${Font_color_suffix}\n"
		fi
	fi
	user_IP=""
}
View_user_connection_info(){
	check_installed_status
	echo && echo -e "Выберите формат для отображения：
 ${Green_font_prefix}1.${Font_color_suffix} Формат отображения IP
 ${Green_font_prefix}2.${Font_color_suffix} Отображение формата IP + IP-атрибуции" && echo
	read -e -p "(по умолчанию: 1):" connection_info
	[[ -z "${connection_info}" ]] && connection_info="1"
	if [[ "${connection_info}" == "1" ]]; then
		View_user_connection_info_1
	elif [[ "${connection_info}" == "2" ]]; then
		echo -e "${Tip} Определить IP-атрибуцию(ipip.net)，Если IP-адресов больше, время может быть больше..."
		View_user_connection_info_1 "IP_address"
	else
		echo -e "${Error} Пожалуйста, введите правильный номер(1-2)" && exit 1
	fi
}
get_IP_address(){
	if [[ ! -z ${user_IP} ]]; then
		for((integer_1 = ${user_IP_total}; integer_1 >= 1; integer_1--))
		do
			IP=$(echo "${user_IP}" |sed -n "$integer_1"p)
			IP_address=$(wget -qO- -t1 -T2 http://freeapi.ipip.net/${IP}|sed 's/\"//g;s/,//g;s/\[//g;s/\]//g')
			echo -e "${Green_font_prefix}${IP}${Font_color_suffix} (${IP_address})"
			sleep 1s
		done
	fi
}
Set_crontab_monitor(){
	check_crontab_installed_status
	crontab_monitor_status=$(crontab -l|grep "ss-go.sh monitor")
	if [[ -z "${crontab_monitor_status}" ]]; then
		echo && echo -e "Текущий режим мониторинга: ${Red_font_prefix}Неоткрытый${Font_color_suffix}" && echo
		echo -e "Обязательно включить ${Green_font_prefix}Сервер Shadowsocks запускает мониторинг состояния${Font_color_suffix} Функция?  (Когда процесс будет закрыт, сервер Shadowsocks будет запущен автоматически)[Y/n]"
		read -e -p "(по умолчанию: y):" crontab_monitor
		[[ -z "${crontab_monitor_status_ny}" ]] && crontab_monitor_status_ny="y"
		if [[ ${crontab_monitor_status_ny} == [Yy] ]]; then
			crontab_monitor_cron_start
		else
			echo && echo "	Отменено..." && echo
		fi
	else
		echo && echo -e "Текущий режим мониторинга: ${Green_font_prefix}Включенный${Font_color_suffix}" && echo
		echo -e "Обязательно закрыть ${Red_font_prefix}Сервер Shadowsocks запускает мониторинг состояния${Font_color_suffix} Функция?  (Когда процесс будет закрыт, сервер Shadowsocks будет запущен автоматически)[Y/n]"
		read -e -p "(по умолчанию: n):" crontab_monitor_status_ny
		[[ -z "${crontab_monitor_status_ny}" ]] && crontab_monitor_status_ny="n"
		if [[ ${crontab_monitor_status_ny} == [Yy] ]]; then
			crontab_monitor_cron_stop
		else
			echo && echo " Отменено..." && echo
		fi
	fi
}
crontab_monitor_cron_start(){
	crontab -l > "$file_1/crontab.bak"
	sed -i "/ss-go.sh monitor/d" "$file_1/crontab.bak"
	echo -e "\n* * * * * /bin/bash $file_1/ss-go.sh monitor" >> "$file_1/crontab.bak"
	crontab "$file_1/crontab.bak"
	rm -r "$file_1/crontab.bak"
	cron_config=$(crontab -l | grep "ss-go.sh monitor")
	if [[ -z ${cron_config} ]]; then
		echo -e "${Error} Не удалось запустить функцию мониторинга состояния сервера Shadowsocks !" && exit 1
	else
		echo -e "${Info} Сервер Shadowsocks, на котором запущена функция мониторинга состояния, успешно запущен !"
	fi
}
crontab_monitor_cron_stop(){
	crontab -l > "$file_1/crontab.bak"
	sed -i "/ss-go.sh monitor/d" "$file_1/crontab.bak"
	crontab "$file_1/crontab.bak"
	rm -r "$file_1/crontab.bak"
	cron_config=$(crontab -l | grep "ss-go.sh monitor")
	if [[ ! -z ${cron_config} ]]; then
		echo -e "${Error} Сбой остановки функции мониторинга состояния сервера Shadowsocks !" && exit 1
	else
		echo -e "${Info} Сервер Shadowsocks, на котором запущена функция мониторинга состояния, успешно остановлен !"
	fi
}
crontab_monitor(){
	check_installed_status
	check_pid
	#echo "${PID}"
	if [[ -z ${PID} ]]; then
		echo -e "${Error} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] Обнаружить, что сервер Shadowsocks не запущен, начать запуск..." | tee -a ${LOG}
		/etc/init.d/ss-go start
		sleep 1s
		check_pid
		if [[ -z ${PID} ]]; then
			echo -e "${Error} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] Сервер Shadowsocks не запустился..." | tee -a ${LOG}
		else
			echo -e "${Info} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] Сервер Shadowsocks успешно запущен..." | tee -a ${LOG}
		fi
	else
		echo -e "${Info} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] Серверный процесс Shadowsocks работает нормально..." | tee -a ${LOG}
	fi
}
Add_iptables(){
	iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ss_port} -j ACCEPT
	iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${ss_port} -j ACCEPT
	ip6tables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ss_port} -j ACCEPT
	ip6tables -I INPUT -m state --state NEW -m udp -p udp --dport ${ss_port} -j ACCEPT
}
Del_iptables(){
	iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
	iptables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
	ip6tables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
	ip6tables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
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
Update_Shell(){
	sh_new_ver=$(wget --no-check-certificate -qO- -t1 -T3 "https://raw.githubusercontent.com/heweiye/ToyoDAdoubiBackup/master/ss-go.sh"|grep 'sh_ver="'|awk -F "=" '{print $NF}'|sed 's/\"//g'|head -1) && sh_new_type="github"
	[[ -z ${sh_new_ver} ]] && echo -e "${Error} Невозможно связать с Github !" && exit 0
	if [[ -e "/etc/init.d/ss-go" ]]; then
		rm -rf /etc/init.d/ss-go
		Service
	fi
	wget -N --no-check-certificate "https://raw.githubusercontent.com/heweiye/ToyoDAdoubiBackup/master/ss-go.sh" && chmod +x ss-go.sh
	echo -e "Скрипт обновлен до последней версии[ ${sh_new_ver} ] !(Примечание: поскольку метод обновления заключается в непосредственной перезаписи текущего выполняемого скрипта, некоторые ошибки могут появиться ниже, просто игнорируйте их.)" && exit 0
}
check_sys
action=$1
if [[ "${action}" == "monitor" ]]; then
	crontab_monitor
else
        echo && echo -e "  Сценарий управления одним щелчком Shadowsocks-Go ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
  ---- LEGENDA VPN USER CONTROL ----
  
 ${Green_font_prefix} 0.${Font_color_suffix} Сценарий обновления
————————————
 ${Green_font_prefix} 1.${Font_color_suffix} Установить Shadowsocks
 ${Green_font_prefix} 2.${Font_color_suffix} Обновить Shadowsocks
 ${Green_font_prefix} 3.${Font_color_suffix} Удалить Shadowsocks
———————————
 ${Green_font_prefix} 4.${Font_color_suffix} Запустить Shadowsocks
 ${Green_font_prefix} 5.${Font_color_suffix} Остановить Shadowsocks
 ${Green_font_prefix} 6.${Font_color_suffix} Перезапустить Shadowsocks
————————————
 ${Green_font_prefix} 7.${Font_color_suffix} Настройки конфигурация учетной записи
 ${Green_font_prefix} 8.${Font_color_suffix} Просмотр информации об учетной записи
 ${Green_font_prefix} 9.${Font_color_suffix} Просмотр информации журнала
 ${Green_font_prefix}10.${Font_color_suffix} Просмотр информации о ссылке
————————————" && echo
	if [[ -e ${FILE} ]]; then
		check_pid
		if [[ ! -z "${PID}" ]]; then
			echo -e " Текущее состояние: ${Green_font_prefix}установлены${Font_color_suffix} и ${Green_font_prefix}активирован${Font_color_suffix}"
		else
			echo -e " Текущее состояние: ${Green_font_prefix}установлены${Font_color_suffix} но ${Red_font_prefix}не инициирован${Font_color_suffix}"
		fi
	else
		echo -e " Текущее состояние: ${Red_font_prefix}не установлено${Font_color_suffix}"
	fi
	echo
	read -e -p " Пожалуйста, введите номер [0-10]:" num
	case "$num" in
		0)
		Update_Shell
		;;
		1)
		Install
		;;
		2)
		Update
		;;
		3)
		Uninstall
		;;
		4)
		Start
		;;
		5)
		Stop
		;;
		6)
		Restart
		;;
		7)
		Set
		;;
		8)
		View
		;;
		9)
		View_Log
		;;
		10)
		View_user_connection_info
		;;
		*)
		echo "Пожалуйста, введите правильный номер [0-10]"
		;;
	esac
fi
