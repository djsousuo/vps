unalias cp
cp -f vps/limits.conf /etc/security/limits.conf
ulimit -n 51200
/sbin/modprobe tcp_hybla
rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org
yum --enablerepo=elrepo-kernel install kernel-ml -y
sed -i 's:default=.*:default=0:g' /etc/grub.conf
/sbin/modprobe tcp_bbr
cp -f vps/sysctl.conf /etc/sysctl.conf
sysctl -p
cp -f vps/rc.local /etc/rc.local
service shadowsocks-libev restart
reboot
