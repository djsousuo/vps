#! /bin/bash

#error and force-exit
function die(){
    echo -e "\033[33mERROR: $1 \033[0m" > /dev/null 1>&2
    exit 1
}

#info echo
function print_info(){
    echo -n -e '\e[1;36m'
    echo -n $1
    echo -e '\e[0m'
}

##### echo
function print_xxxx(){
    xXxX="#############################"
    echo
    echo "$xXxX$xXxX$xXxX$xXxX"
    echo
}

#warn echo
function print_warn(){
    echo -n -e '\033[41;37m'
    echo -n $1
    echo -e '\033[0m'
}

#color line
color_line(){
    echo
    while read line
    do
        echo -e "\e[1;33m$line"
        echo
    done
    echo -en "\e[0m"
}

#Default_Ask "Question?" "default_value" "var_to_save_answer"
function Default_Ask(){
    echo
    Temp_question=$1
    Temp_default_var=$2
    Temp_var_name=$3
#if yes or no 
    echo -e -n "\e[1;36m$Temp_question\e[0m""\033[31m(Default:$Temp_default_var)\033[0m"
    echo
    read Temp_var
    if [ "$Temp_default_var" = "y" ] || [ "$Temp_default_var" = "n" ]; then
        Temp_var=$(echo $Temp_var | sed 'y/YESNO0/yesnoo/')
        case $Temp_var in
            y|ye|yes)
                Temp_var=y
                ;;
            n|no)
                Temp_var=n
                ;;
            *)
                Temp_var=$Temp_default_var
                ;;
        esac
    else
        Temp_var=${Temp_var:-$Temp_default_var}        
    fi
    Temp_cmd="$Temp_var_name='$Temp_var'"
    eval $Temp_cmd
    print_info "Your answer is : ${Temp_var}"
    echo
    print_xxxx
}

function log_Start(){
    echo "SYS INFO" > ${Log_File}
    echo "" >> ${Log_File}
    sed '/^$/d' /etc/issue >> ${Log_File}
    uname -r >> ${Log_File}
    echo "" >> ${Log_File}
    echo "SETUP INFO" >> ${Log_File}
    echo "" >> ${Log_File}
}

function config_network(){
    IPADDR=$(LC_ALL=C ifconfig  | grep 'inet addr:'| grep -v '127.0.0.1' | grep -v inet6 | cut -d: -f2 | awk '{print $1}')
    GATEWAY="${IPADDR%\.[0-9]*}.1"
}

function show_help(){
    print_xxxx
    print_info "######################## Parameter Description ####################################"
    echo
    print_info " 1: Install ocserv for CentOS 6"
    echo
    print_info " 2: Add a user using password method"
    echo
    print_info " 3: Delete a user using password method"
    echo
    print_info " 4: Generate a new client certificate"
    echo
    print_info " 5: Revoke a client certificate"
    echo
    print_info " 6: Force to reinstall your ocserv(Destroy All Data)"
    echo
    print_info " 7: Uninstall your ocserv(Destroy All Data)"
    print_xxxx
    Default_Ask "Please select one option." "1" "action"
}

function install_OpenConnect_VPN_server(){
    print_info "Install Open Connect Server."
    wget https://github.com/zhuangzhemin/vps/raw/master/epel-release-6-8.noarch.rpm -O /etc/yum.repos.d/epel-release-6-8.noarch.rpm
    rpm -ivh  /etc/yum.repos.d/epel-release-6-8.noarch.rpm 
    yum install -y ocserv
    clear && print_xxxx
    Default_Ask "Your VPN username?" "ocvpn" "VpnUser"
    Default_Ask "Your VPN password?" "ocvpn" "VpnPasswd"
    Default_Ask "Your VPN port?" "443" "VpnPort"
    make_ocserv_ca
    ca_login_clientcert
    set_ocserv_conf
    service ocserv status
}

function make_ocserv_ca(){
    IPADDR=$(LC_ALL=C ifconfig  | grep 'inet addr:'| grep -v '127.0.0.1' | grep -v inet6 | cut -d: -f2 | awk '{print $1}')
    print_info "Generating Self-signed CA..."
#generating the CA
    openssl genrsa -out /etc/ocserv/ca-key.pem 4096
    cat << _EOF_ > /etc/ocserv/ca.tmpl
cn = "${VpnUser}"
organization = "${VpnUser}"
serial = 1
expiration_days = 7777
ca
signing_key
cert_signing_key
crl_signing_key
# An URL that has CRLs (certificate revocation lists)
# available. Needed in CA certificates.
#crl_dist_points = "http://www.getcrl.crl/getcrl/"
_EOF_
    certtool --generate-self-signed --hash SHA256 --load-privkey /etc/ocserv/ca-key.pem --template /etc/ocserv/ca.tmpl --outfile /etc/ocserv/ca-cert.pem
#generating a local server key-certificate pair
    openssl genrsa -out /etc/ocserv/server-key.pem 2048
    cat << _EOF_ > /etc/ocserv/server.tmpl
cn = "${IPADDR}"
organization = "${VpnUser}"
serial = 2
expiration_days = 7777
signing_key
encryption_key
tls_www_server
_EOF_
    certtool --generate-certificate --hash SHA256 --load-privkey /etc/ocserv/server-key.pem --load-ca-certificate /etc/ocserv/ca-cert.pem --load-ca-privkey /etc/ocserv/ca-key.pem --template /etc/ocserv/server.tmpl --outfile /etc/ocserv/server-cert.pem
    [ ! -f /etc/ocserv/server-cert.pem ] && die "/etc/ocserv/server-cert.pem NOT Found , make failure!"
    [ ! -f /etc/ocserv/server-key.pem ] && die "/etc/ocserv/server-key.pem NOT Found , make failure!"
    cat /etc/ocserv/ca-cert.pem >> /etc/ocserv/server-cert.pem
    print_info "Self-signed CA for ocserv ok"
}

function ca_login_clientcert(){
#generate a client cert
    print_info "Generating a client cert..."
    caname=$(openssl x509 -noout -subject -in /etc/ocserv/ca-cert.pem|sed -n 's/.*CN=\([^=]*\)\/.*/\1/p')
    cat << _EOF_ > /etc/ocserv/user-${VpnUser}.tmpl
cn = "${VpnUser}"
unit = "Route"
#unit = "All"
uid ="${VpnUser}"
expiration_days = 7777
signing_key
tls_www_client
_EOF_
#user key
    openssl genrsa -out /etc/ocserv/user-${VpnUser}-key.pem 2048
#user cert
    certtool --generate-certificate --hash SHA256 --load-privkey /etc/ocserv/user-${VpnUser}-key.pem --load-ca-certificate /etc/ocserv/ca-cert.pem --load-ca-privkey /etc/ocserv/ca-key.pem --template /etc/ocserv/user-${VpnUser}.tmpl --outfile /etc/ocserv/user-${VpnUser}-cert.pem
#p12
    openssl pkcs12 -export -inkey /etc/ocserv/user-${VpnUser}-key.pem -in /etc/ocserv/user-${VpnUser}-cert.pem -name "${VpnUser}" -certfile /etc/ocserv/ca-cert.pem -caname "$caname" -out /etc/ocserv/user-${VpnUser}.p12 -passout pass:${VpnPasswd}
#cp to ${Script_Dir}
    cp /etc/ocserv/user-${VpnUser}.p12 /root/
    cat << _EOF_ > /etc/ocserv/crl.tmpl
crl_next_update = 7777 
crl_number = 1 
_EOF_
    certtool --generate-crl --load-ca-privkey /etc/ocserv/ca-key.pem --load-ca-certificate /etc/ocserv/ca-cert.pem --template /etc/ocserv/crl.tmpl --outfile /etc/ocserv/crl.pem
    print_info "Generate client cert ok"
}

function set_ocserv_conf(){
    print_info "Setup Open Connect Server."
    cat << _EOF_ > /etc/ocserv/profile.xml
<?xml version="1.0" encoding="UTF-8"?>
<AnyConnectProfile xmlns="http://schemas.xmlsoap.org/encoding/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://schemas.xmlsoap.org/encoding/ AnyConnectProfile.xsd">
	<ClientInitialization>
		<UseStartBeforeLogon UserControllable="false">false</UseStartBeforeLogon>
		<StrictCertificateTrust>false</StrictCertificateTrust>
		<RestrictPreferenceCaching>false</RestrictPreferenceCaching>
		<RestrictTunnelProtocols>IPSec</RestrictTunnelProtocols>
		<BypassDownloader>true</BypassDownloader>
		<WindowsVPNEstablishment>AllowRemoteUsers</WindowsVPNEstablishment>
		<CertEnrollmentPin>pinAllowed</CertEnrollmentPin>
		<CertificateMatch>
			<KeyUsage>
				<MatchKey>Digital_Signature</MatchKey>
			</KeyUsage>
			<ExtendedKeyUsage>
				<ExtendedMatchKey>ClientAuth</ExtendedMatchKey>
			</ExtendedKeyUsage>
		</CertificateMatch>
		<BackupServerList>
	            <HostAddress>${IPADDR}</HostAddress>
		</BackupServerList>
	</ClientInitialization>
	<ServerList>
		<HostEntry>
	            <HostName>VPN Server</HostName>
	            <HostAddress>${IPADDR}</HostAddress>
		</HostEntry>
	</ServerList>
</AnyConnectProfile>
_EOF_
    print_info "Copying ocserv.conf file from github.com"
    wget https://raw.githubusercontent.com/zhuangzhemin/vps/master/ocserv.conf -O /etc/ocserv/ocserv.conf
    print_info "Perhaps generate DH parameters will take some time , please wait..."
    certtool --generate-dh-params --outfile /etc/ocserv/dh.pem
    (echo "${VpnPasswd}"; sleep 1; echo "${VpnPasswd}") | ocpasswd -c /etc/ocserv/ocpasswd ${VpnUser}
#set port
    sed -i "s|\(tcp-port = \).*|\1${VpnPort}|" ${OCSERV_CONF}
    sed -i "s|^[ \t]*\(udp-port = \).*|\1${VpnPort}|" ${OCSERV_CONF}
#default domain compression dh.pem
    sed -i "s|^[# \t]*\(default-domain = \).*|\1${IPADDR}|" ${OCSERV_CONF}
    sed -i "s|^[# \t]*\(compression = \).*|\1true|" ${OCSERV_CONF}
    sed -i 's|^[# \t]*\(dh-params = \).*|\1/etc/ocserv/dh.pem|' ${OCSERV_CONF}
#setup the cert login
    sed -i '/sample.passwd/d' /etc/ocserv/ocserv.conf
    sed -i 's|^[# \t]*\(auth = "plain\)|\1|' ${OCSERV_CONF}
    sed -i 's|^[# \t]*\(auth = "certificate"\)|#\1|' ${OCSERV_CONF}
    sed -i 's|^[# \t]*\(enable-auth = "certificate"\)|\1|' ${OCSERV_CONF}
    sed -i 's|^[# \t]*\(ca-cert = \).*|\1/etc/ocserv/ca-cert.pem|' ${OCSERV_CONF}
    sed -i 's|^[# \t]*\(crl = \).*|\1/etc/ocserv/crl.pem|' ${OCSERV_CONF}
    sed -i 's|^[# \t]*\(cert-user-oid = \).*|\12\.5\.4\.3|' ${OCSERV_CONF}
#    sed -i 's|^[# \t]*\(cert-user-oid = \).*|\10\.9\.2342\.19200300\.100\.1\.1|' ${OCSERV_CONF}
    #wget https://raw.githubusercontent.com/zhuangzhemin/vps/master/ocserv_setup.sh ~/ocserv_setup.sh
    print_info "Set ocserv ok"
    service ocserv restart
    chkconfig ocserv on
    sed -i "/-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT/a-A INPUT -p tcp -m tcp --dport ${VpnPort} -j ACCEPT" /etc/sysconfig/iptables
    sed -i "/-A OUTPUT -p udp -m udp --dport 53 -j ACCEPT/a-A OUTPUT -p udp -m udp --dport ${VpnPort} -j ACCEPT" /etc/sysconfig/iptables
    service iptables restart
}

function check_ca_cert(){
    [ ! -f /usr/sbin/ocserv ] && die "Ocserv NOT Found !!!"
    [ ! -f /etc/ocserv/ca-key.pem ] && die "ca-key.pem NOT Found !!!"
    [ ! -f /etc/ocserv/ca-cert.pem ] && die "ca-cert.pem NOT Found !!!"
}

function add_plain_login_user(){
    check_ca_cert
    Default_Ask "Your VPN username?" "ocvpn" "VpnUser"
    Default_Ask "Your VPN password?" "ocvpn" "VpnPasswd"
    (echo "${VpnPasswd}"; sleep 1; echo "${VpnPasswd}") | ocpasswd -c /etc/ocserv/ocpasswd ${VpnUser}
    echo
}

function del_plain_login_user(){
    check_ca_cert
    clear
    print_xxxx
    print_info "The following is the user list..."
    echo
    cat /etc/ocserv/ocpasswd |cut -d: -f1|color_line
    print_xxxx
    print_info "Which user do you want to delete?"
    echo
    read del_user
    cat /etc/ocserv/ocpasswd | grep "^${del_user}:" > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        die "${del_user} NOT Found !!!"
    fi
    echo
    print_warn "Okay,${del_user} will be deleted."
    print_xxxx
    sed -i "/^${del_user}:/d" /etc/ocserv/ocpasswd
    service ocserv restart
    echo
}

function  get_new_userca(){
    check_ca_cert
    Default_Ask "Your VPN username?" "ocvpn" "VpnUser"
    Default_Ask "Your VPN password?" "ocvpn" "VpnPasswd"
    ca_login_clientcert
    clear
    echo
}

function Outdate_Autoclean(){
    My_All_Ca=$(ls -F /etc/ocserv|grep user|grep cert|cut -d- -f2|sed ':a;N;s/\n/ /;ba;')
    Today_Date=$(date +%s)
    for My_One_Ca in ${My_All_Ca}
    do
        Client_EX_Date=$(openssl x509 -noout -enddate -in /etc/ocserv/user-${My_One_Ca}-cert.pem | cut -d= -f2)
        Client_EX_Date=$(date -d "${Client_EX_Date}" +%s)
        [ ${Client_EX_Date} -lt ${Today_Date} ] && {
            mv  /etc/ocserv/user-${revoke_ca}* /etc/ocserv/revoke/
        }
    done
}

function revoke_userca(){
    check_ca_cert
    if [ ! -d /etc/ocserv/revoke ]; then
        mkdir -p /etc/ocserv/revoke > /dev/null 2>&1
    fi
#input info
    Outdate_Autoclean
    clear
    print_xxxx
    print_info "The following is the user list..."
    echo
    ls -F /etc/ocserv | grep user | grep cert | cut -d- -f2 | color_line
    print_xxxx
    print_info "Which user do you want to revoke?"
    echo
    read revoke_ca
    if [ ! -f /etc/ocserv/user-$revoke_ca-cert.pem ]; then
        die "$revoke_ca NOT Found !!!"
    fi
    echo
    print_warn "Okay,${revoke_ca} will be revoked."
    print_xxxx
    press_any_key
#revoke   
    cat /etc/ocserv/user-${revoke_ca}-cert.pem >> /etc/ocserv/revoked.pem
    certtool --generate-crl --load-ca-privkey /etc/ocserv/ca-key.pem --load-ca-certificate /etc/ocserv/ca-cert.pem --load-certificate /etc/ocserv/revoked.pem --template /etc/ocserv/crl.tmpl --outfile /etc/ocserv/crl.pem
    mv  /etc/ocserv/user-${revoke_ca}* /etc/ocserv/revoke/
    print_info "${revoke_ca} was revoked."
    service ocserv restart
    echo    
}

function reinstall_ocserv(){
    uninstall_ocserv
    install_OpenConnect_VPN_server
}

function uninstall_ocserv(){
    VpnPort=$(cat ${OCSERV_CONF} | grep tcp-port | awk '{print $3}')
    print_info "Stop ocserv service ..."
    service ocserv stop
    print_info "Remove ocserv ..."
    yum remove -y ocserv
    rm -rf /etc/ocserv/
    sed -i "/-A INPUT -p tcp -m tcp --dport ${VpnPort} -j ACCEPT/d" /etc/sysconfig/iptables
    sed -i "/-A OUTPUT -p udp -m udp --dport ${VpnPort} -j ACCEPT/d" /etc/sysconfig/iptables
    service iptables restart
    print_info "Open Connect VPN server removed ..."
}

#######################################################
#main                                                                                                            #
#######################################################
Script_Dir="$(cd "$(dirname $0)"; pwd)"
Log_File="${Script_Dir}/ocserv_setup.log"
OCSERV_CONF="/etc/ocserv/ocserv.conf"

log_Start

show_help

#Initialization step
case "$action" in
1)
    install_OpenConnect_VPN_server | tee -a ${Log_File}
    ;;
2)
    add_plain_login_user | tee -a ${Log_File}
    ;;
3)
    del_plain_login_user | tee -a ${Log_File}
    ;;
4)
    get_new_userca | tee -a ${Log_File}
    ;;
5)
    revoke_userca | tee -a ${Log_File}
    ;;
6)
    reinstall_ocserv | tee -a ${Log_File}
    ;;
7)
    uninstall_ocserv | tee -a ${Log_File}
    ;;
*)
    clear
    print_warn "Arguments error! [ ${action} ]"
    ;;
esac

exit 0
