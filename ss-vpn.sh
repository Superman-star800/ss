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
	echo "请输入 Shadowsocks 密码 [0-9][a-z][A-Z]"
	read -e -p "(默认: 随机生成):" ss_password
	[[ -z "${ss_password}" ]] && ss_password=$(date +%s%N | md5sum | head -c 16)
	echo && echo "========================"
	echo -e "	密码 : ${Red_background_prefix} ${ss_password} ${Font_color_suffix}"
	echo "========================" && echo
}
Set_cipher(){
	echo -e "请选择 Shadowsocks 加密方式
	
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

${Tip} chacha20 系列加密方式无需额外安装 libsodium，Shadowsocks Go版默认集成 !" && echo
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
	echo -e "	加密 : ${Red_background_prefix} ${ss_cipher} ${Font_color_suffix}"
	echo "========================" && echo
}
Set_verbose(){
	echo -e "是否启用详细日志模式？[Y/n]
启用详细日志模式就可以在日志中看到链接者信息(链接时间、链接代理端口、链接者IP、链接者访问的目标域名或IP这些非敏感类信息)。"
	read -e -p "(默认：N 禁用):" ss_verbose
	[[ -z "${ss_verbose}" ]] && ss_verbose="N"
	if [[ "${ss_verbose}" == [Yy] ]]; then
		ss_verbose="YES"
	else
		ss_verbose="NO"
	fi
	echo && echo "========================"
	echo -e "	详细日志模式 : ${Red_background_prefix} ${ss_verbose} ${Font_color_suffix}"
	echo "========================" && echo
}
Set(){
	check_installed_status
	echo && echo -e "你要做什么？
 ${Green_font_prefix}1.${Font_color_suffix}  修改 端口配置
 ${Green_font_prefix}2.${Font_color_suffix}  修改 密码配置
 ${Green_font_prefix}3.${Font_color_suffix}  修改 加密配置
 ${Green_font_prefix}4.${Font_color_suffix}  修改 详细日志模式 配置
 ${Green_font_prefix}5.${Font_color_suffix}  修改 全部配置
————————————————
 ${Green_font_prefix}6.${Font_color_suffix}  监控 运行状态" && echo
	read -e -p "(默认: 取消):" ss_modify
	[[ -z "${ss_modify}" ]] && echo "已取消..." && exit 1
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
		echo -e "${Error} 请输入正确的数字(1-6)" && exit 1
	fi
}
Install(){
	check_root
	[[ -e ${FILE} ]] && echo -e "${Error} 检测到 Shadowsocks 已安装 !" && exit 1
	echo -e "${Info} 开始设置 用户配置..."
	Set_port
	Set_password
	Set_cipher
	Set_verbose
	echo -e "${Info} 开始安装/配置 依赖..."
	Installation_dependency
	echo -e "${Info} 开始下载/安装..."
	check_new_ver
	Download
	echo -e "${Info} 开始下载/安装 服务脚本(init)..."
	Service
	echo -e "${Info} 开始写入 配置文件..."
	Write_config
	echo -e "${Info} 开始设置 iptables防火墙..."
	Set_iptables
	echo -e "${Info} 开始添加 iptables防火墙规则..."
	Add_iptables
	echo -e "${Info} 开始保存 iptables防火墙规则..."
	Save_iptables
	echo -e "${Info} 所有步骤 安装完毕，开始启动..."
	Start
}
Start(){
	check_installed_status
	check_pid
	[[ ! -z ${PID} ]] && echo -e "${Error} Shadowsocks 正在运行，请检查 !" && exit 1
	/etc/init.d/ss-go start
	#sleep 1s
	check_pid
	[[ ! -z ${PID} ]] && View
}
Stop(){
	check_installed_status
	check_pid
	[[ -z ${PID} ]] && echo -e "${Error} Shadowsocks 没有运行，请检查 !" && exit 1
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
	echo "确定要卸载 Shadowsocks ? (y/N)"
	echo
	read -e -p "(默认: n):" unyn
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
		echo && echo "Shadowsocks 卸载完成 !" && echo
	else
		echo && echo "卸载已取消..." && echo
	fi
}
