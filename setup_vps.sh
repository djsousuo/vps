#! /bin/bash

RootPasswd="ROOTPASSWD"
UserName="vpn_user"
UserPasswd="USERPASSWD"
VncPasswd="VNCPASSWD"
VncPort="61"
SsPasswd="SSPASSWD"
SsPort="8443"
VpnUser="vpn_user"
VpnPasswd="VPNPASSWD" 
VpnPort="443"
InstallGUI="n"

#error and force-exit
function die(){
    echo -e "\033[33m[$(date +'%Y-%m-%dT%H:%M:%S%z')]ERROR: $@ \033[0m" > /dev/null 1>&2
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

function log_start(){
    echo "SYS INFO" >${Log_File}
    echo "" >>${Log_File}
    sed '/^$/d' /etc/issue >>${Log_File}
    uname -r >>${Log_File}
    echo "" >>${Log_File}
    echo "SETUP INFO" >>${Log_File}
    echo "" >>${Log_File}
}

function yum_update(){
    print_info "yum update."
    yum update -y
}

function update_kernel(){
    print_info "Update kernel from elrepo."
    rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org
    rpm -Uvh http://www.elrepo.org/elrepo-release-6-6.el6.elrepo.noarch.rpm
    yum --enablerepo=elrepo-kernel install kernel-ml -y
    sed -i 's:default=.*:default=0:g' /boot/grub/grub.conf
}

function install_GUI_system(){
    print_info "Install GUI system."
    yum groupinstall -y "X Window System"
    yum groupinstall -y "Desktop"
    yum groupinstall -y "General Purpose Desktop"
    yum groupinstall -y "Internet Browser"
    sed -i "s/id:.*:initdefault:/id:5:initdefault:/" /etc/inittab
}

function install_basic_tools(){
    print_info "Install basic tools."
    yum install -y vim gvim zsh git tmux
    git clone https://github.com/zhuangzhemin/home.git
    cp -rf home/. ~
    rm -rf home
    chsh -s /bin/zsh
}

function update_root_passwd(){
    print_info "Update password for root."
    echo "root:${RootPasswd}" | chpasswd
}

function add_user(){
    print_info "Add user: $1."
    useradd $1
    echo $1:$2 | chpasswd
    sed -i "/^root[ \t]\+ALL=(ALL)[ \t]\+ALL/a$1\tALL=(ALL)\tALL" /etc/sudoers
    sed -i "s/^[# \t]*\(%wheel[ \t]\+ALL=(ALL)[ \t]\+NOPASSWD:[ \t]*ALL\)/\1/" /etc/sudoers
    usermod -G wheel $1
    su - $1 -c "cd;git https://github.com/zhuangzhemin/home;cp -rf home/. .;rm -rf home"
    chsh -s /bin/zsh $1
}

function config_network(){
    print_info "Config network."
    IPADDR=$(LC_ALL=C ifconfig  | grep 'inet addr:'| grep -v '127.0.0.1' | grep -v inet6 | cut -d: -f2 | awk '{print $1}')
    GATEWAY="${IPADDR%\.[0-9]*}.1"
    cat << _EOF_ > /etc/resolv.conf
nameserver 8.8.8.8
nameserver 8.8.4.4
_EOF_
    cat << _EOF_ > /etc/sysconfig/network-scripts/ifcfg-eth0
DEVICE=eth0
BOOTPROTO=static
ONBOOT=yes
IPADDR=${IPADDR}
GATEWAY=${GATEWAY}
NETMASK=255.255.254.0
DNS1=8.8.8.8
DNS2=8.8.4.4
_EOF_
    echo "*               soft    nofile            51200" >> /etc/security/limits.conf
    echo "*               hard    nofile            51200" >> /etc/security/limits.conf
    ulimit -n 51200
    /sbin/modprobe tcp_bbr
    cat << _EOF_ > /etc/sysctl.conf
# Kernel sysctl configuration file for Red Hat Linux
#
# For binary values, 0 is disabled, 1 is enabled.  See sysctl(8) and
# sysctl.conf(5) for more details.
#
# Use '/sbin/sysctl -a' to list all possible parameters.
#
# Controls IP packet forwarding
net.ipv4.ip_forward = 1
#
# Controls source route verification
net.ipv4.conf.default.rp_filter = 1
#
# Do not accept source routing
net.ipv4.conf.default.accept_source_route = 0
#
# Controls the System Request debugging functionality of the kernel
kernel.sysrq = 0
#
# Controls whether core dumps will append the PID to the core filename.
# Useful for debugging multi-threaded applications.
kernel.core_uses_pid = 1
#
# Controls the use of TCP syncookies
net.ipv4.tcp_syncookies = 1
#
# Controls the default maxmimum size of a mesage queue
kernel.msgmnb = 65536
#
# Controls the maximum size of a message, in bytes
kernel.msgmax = 65536
#
# Controls the maximum shared segment size, in bytes
kernel.shmmax = 68719476736
#
# Controls the maximum number of shared memory segments, in pages
kernel.shmall = 4294967296
#
# Accept IPv6 advertisements when forwarding is enabled
net.ipv6.conf.all.accept_ra = 2
net.ipv6.conf.eth0.accept_ra = 2
#
# Optimization for shadowsocks
fs.file-max = 51200
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 4096
# configuration for TCP
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mem = 25600 51200 102400
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
_EOF_
    sysctl -p
    echo "/sbin/modprobe tcp_bbr" >> /etc/rc.local
    cat << _EOF_ > /etc/sysconfig/iptables
# Generated by iptables-save v1.4.7
*nat
:PREROUTING ACCEPT [5:284]
:POSTROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [1:72]
-A POSTROUTING -j MASQUERADE 
COMMIT
*filter
:INPUT DROP [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT 
-A INPUT -p tcp -m state --state NEW -m tcp --dport 21 -j ACCEPT 
-A INPUT -p icmp -m icmp --icmp-type any -j ACCEPT 
-A INPUT -s 127.0.0.1/32 -d 127.0.0.1/32 -j ACCEPT 
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT 
-A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 
-A OUTPUT -p icmp -m icmp --icmp-type any -j ACCEPT 
-A OUTPUT -s 127.0.0.1/32 -d 127.0.0.1/32 -j ACCEPT 
-A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT 
-A OUTPUT -p udp -m udp --dport 53 -j ACCEPT 
-A OUTPUT -p tcp -m state --state NEW -m tcp --dport 80 -j ACCEPT 
COMMIT
_EOF_
    service iptables restart
}

function setup_VNC_server(){
    print_info "Install VNC server."
    yum install -y tigervnc-server tigervnc
    print_info "Setup VNC server."
    VncUser=${UserName:-root}
    sed -i "s/^[# ]*\(VNCSERVERS[ \t]*=\).*/\1\"${VncPort}:${VncUser}\"/" /etc/sysconfig/vncservers
    sed -i "s/^[# ]*\(VNCSERVERARGS\).*/\1[${VncPort}]=\"-geometry 1440x900\"/" /etc/sysconfig/vncservers
    if [ -n ${UserName} ]; then
        VncDir="/home/${UserName}/.vnc"
    else
        VncDir="/root/.vnc"
    fi
    mkdir ${VncDir}
    echo "${VncPasswd}" | vncpasswd -f > ${VncDir}/passwd
    cat << _EOF_ > ${VncDir}/xstart
#!/bin/sh
[ -r /etc/sysconfig/i18n ] && . /etc/sysconfig/i18n
export LANG
export SYSFONT
vncconfig -iconic &
unset SESSION_MANAGER
unset DBUS_SESSION_BUS_ADDRESS
OS=\`uname -s\`
if [ \$OS = 'Linux' ]; then
  case "\$WINDOWMANAGER" in
    *gnome*)
      if [ -e /etc/SuSE-release ]; then
        PATH=\$PATH:/opt/gnome/bin
        export PATH
      fi
      ;;
  esac
fi
if [ -x /etc/X11/xinit/xinitrc ]; then
  exec /etc/X11/xinit/xinitrc
fi
if [ -f /etc/X11/xinit/xinitrc ]; then
  exec sh /etc/X11/xinit/xinitrc
fi
[ -r \$HOME/.Xresources ] && xrdb \$HOME/.Xresources
xsetroot -solid grey
xterm -geometry 80x24+10+10 -ls -title "\$VNCDESKTOP Desktop" &
twm &
_EOF_
    chown -R ${VncUser}:${VncUser} ${VncDir}
    chmod 600 ${VncDir}/passwd
    chmod 755 ${VncDir}/xstartup
    service vncserver restart
    chkconfig vncserver on
    VncRealPort=$(expr $VncPort + 5900)
    sed -i "/-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT/a-A INPUT -p tcp -m tcp --dport ${VncRealPort} -j ACCEPT" /etc/sysconfig/iptables
    service iptables restart
}

function setup_Shadowsocks(){
    print_info "Install Shadowsocks server."
    cat << _EOF_ > /etc/yum.repos.d/librehat-shadowsocks-epel-6.repo
[librehat-shadowsocks]
name=Copr repo for shadowsocks owned by librehat
baseurl=https://copr-be.cloud.fedoraproject.org/results/librehat/shadowsocks/epel-6-\$basearch/
skip_if_unavailable=True
gpgcheck=1
gpgkey=https://copr-be.cloud.fedoraproject.org/results/librehat/shadowsocks/pubkey.gpg
enabled=1
enabled_metadata=1
_EOF_
    yum install -y shadowsocks-libev
    print_info "Setup Shadowsocks server."
    IPADDR=$(LC_ALL=C ifconfig  | grep 'inet addr:'| grep -v '127.0.0.1' | grep -v inet6 | cut -d: -f2 | awk '{print $1}')
    cat << _EOF_ > /etc/shadowsocks-libev/config.json
{
    "server":"${IPADDR}",
    "server_port":${SsPort},
    "local_port":1080,
    "password":"${SsPasswd}",
    "timeout":600,
    "method":"aes-256-cfb"
}
_EOF_
    service shadowsocks-libev restart
    chkconfig shadowsocks-libev on
    sed -i "/-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT/a-A INPUT -p tcp -m tcp --dport ${SsPort} -j ACCEPT" /etc/sysconfig/iptables
    service iptables restart
}

function setup_ocserv(){
    print_info "Install Open Connect Server."
    wget https://github.com/zhuangzhemin/vps/raw/master/epel-release-6-8.noarch.rpm -O /etc/yum.repos.d/
    rpm -ivh  /etc/yum.repos.d/epel-release-6-8.noarch.rpm 
    yum install -y ocserv
    print_info "Setup Open Connect Server."
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
#generate a client cert
    print_info "Generating a client cert..."
    caname=`openssl x509 -noout -subject -in /etc/ocserv/ca-cert.pem|sed -n 's/.*CN=\([^=]*\)\/.*/\1/p'`
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
    OCSERV_CONF="/etc/ocserv/ocserv.conf"
    print_info "Copying ocserv.conf file from github.com"
    wget https://raw.githubusercontent.com/zhuangzhemin/vps/master/ocserv.conf -O ${OCSERV_CONF}
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
    print_info "Set ocserv ok"
    service ocserv restart
    chkconfig ocserv on
    wget https://raw.githubusercontent.com/zhuangzhemin/vps/master/setup_ocserv.sh /root/
    sed -i "/-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT/a-A INPUT -p tcp -m tcp --dport ${VpnPort} -j ACCEPT" /etc/sysconfig/iptables
    sed -i "/-A OUTPUT -p udp -m udp --dport 53 -j ACCEPT/a-A OUTPUT -p udp -m udp --dport ${VpnPort} -j ACCEPT" /etc/sysconfig/iptables
    service iptables restart
}

#######################################################
#main                                                                                                            #
#######################################################
Script_Dir="$(cd "$(dirname $0)"; pwd)"
Log_File="${Script_Dir}/vps_setup.log"

log_start

if [ -n ${RootPasswd} ]; then
    update_root_passwd | tee -a ${Log_File}
fi

if [ -n ${UserName} ]; then
    UserPasswd=${UserPasswd:-$UserName}
    add_user ${UserName} ${UserPasswd} | tee -a ${Log_File}
fi

yum_update | tee -a ${Log_File}

update_kernel | tee -a ${Log_File}

install_basic_tools | tee -a ${Log_File}

config_network | tee -a ${Log_File}

if [ ${InstallGUI} == "y" ]; then
    install_GUI_system | tee -a ${Log_File}
    if [ -n ${VncPasswd} ]; then
        VncPort=${VncPort:-61}
        setup_VNC_server | tee -a ${Log_File}
    fi
fi

if [ -n ${SsPasswd} ]; then
    SsPort=${SsPort:-8443}
    setup_Shadowsocks | tee -a ${Log_File}
fi

if [ -n ${VpnUser} ]; then
    VpnPasswd=${VpnPasswd:-$VpnUser}
    VpnPort=${VpnPort:-443}
    setup_ocserv | tee -a ${Log_File}
fi

shutdown -r now
