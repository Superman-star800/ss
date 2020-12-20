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
