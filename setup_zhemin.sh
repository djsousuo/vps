yum update -y
yum groupinstall -y "X Window System"
yum groupinstall -y "Desktop"
yum groupinstall -y "General Purpose Desktop"
yum groupinstall -y "Internet Browser"
yum install -y vim gvim
echo root:ROOTPASSWD | chpasswd
yum install -y git
git clone https://github.com/zhuangzhemin/vps
unalias cp
unalias rm
cp -f vps/inittab /etc/
useradd zhemin
echo zhemin:USERPASSWD | chpasswd
cp -f vps/sudoers /etc/
usermod -G wheel zhemin
cp -f vps/resolv.conf /etc/resolv.conf
LC_ALL=C ifconfig  | grep 'inet addr:'| grep -v '127.0.0.1' | grep -v inet6 | cut -d: -f2 | awk '{print "s/my_ip/"$1"/g"}' > sed_command.txt
cp ifcfg-eth0 ifcfg-eth0_temp
sed -f sed_command.txt ifcfg-eth0_temp > ifcfg-eth0_new
LC_ALL=C ifconfig  | grep 'inet addr:'| grep -v '127.0.0.1' | grep -v inet6 | cut -d: -f2 | awk '{print $1}' | awk -F . '{print "s/my_gateway/"$1"."$2"."$3".1/g"}' > sed_command.txt
cp ifcfg-eth0_new ifcfg-eth0_temp
sed -f sed_command.txt ifcfg-eth0_temp > ifcfg-eth0_new
cp -f vps/ifcfg-eth0_new /etc/sysconfig/network-scripts/ifcfg-eth0
rm -f vps/ifcfg-eth0_new ifcfg-eth0_temp
rm -f sed_command.txt
yum install -y tigervnc-server tigervnc
cp -f vps/iptables /etc/sysconfig/iptables
service iptables restart
cp -f vps/vncservers /etc/sysconfig/vncservers
mkdir /home/zhemin/.vnc
echo VNCPASSWD | vncpasswd -f > /home/zhemin/.vnc/passwd
cp -f vps/xstartup /home/zhemin/.vnc
chown -R zhemin:zhemin /home/zhemin/.vnc
chmod 600 /home/zhemin/.vnc/passwd
chmod 755 /home/zhemin/.vnc/xstartup
service vncserver restart
chkconfig vncserver on
cp -f vps/librehat-shadowsocks-epel-6.repo /etc/yum.repos.d/librehat-shadowsocks-epel-6.repo
yum install -y shadowsocks-libev
LC_ALL=C ifconfig  | grep 'inet addr:'| grep -v '127.0.0.1' | grep -v inet6 | cut -d: -f2 | awk '{print "s/server_ip/"$1"/g"}' > sed_command.txt
cp vps/config.json vps/config_temp.json
sed -f sed_command.txt vps/config_temp.json > vps/config_new.json
sed -i "s/ss_password/SSPASSWD/g" vps/config_new.json
cp -f vps/config_new.json /etc/shadowsocks-libev/config.json
rm -f vps/config_new.json vps/config_temp.json 
rm -f sed_command.txt
service shadowsocks-libev restart
chkconfig shadowsocks-libev on

vps/tcp_optimization.sh

git clone https://github.com/zhuangzhemin/vim
cp -rf vim/. ~

shutdown -r now

