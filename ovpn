#!/bin/bash
# Main script to deploy OpenVPN and Unbound
# This will configure and harden the server :)

# Test if tun/tap is enabled
if test ! -e "/dev/net/tun"; then
        echo "TUN/TAP is not enabled. Please enable for this to work."
		exit
fi

# Check if running as root
if [ "$(id -u)" != "0" ]; then
  exec sudo "$0" "$@"
fi

# Install Required Packages
function packages {
	echo "Updating the server and installing required packages..."
	# Update the server
	yum -y update > /dev/null 2>&1
	echo "Package update complete..."
	yum -y upgrade > /dev/null 2>&1
	echo "Server upgrade complete..."
	# Install required packages
	echo "Installing required packages..."
	yum -y install epel-release.noarch > /dev/null 2>&1
	yum -y install wget rng-tools firewalld ntp openvpn easy-rsa yum-utils gpg unbound net-tools bind-utils > /dev/null 2>&1
}

# Secure Server
# Secures the server by hardening ssh, sets up primary ssh user, configures firewall, starts ntpd and rngd, and configures selinux
function secure {
	# Secure ssh
	sed -i -e "s/#ServerKeyBits 1024/ServerKeyBits 2048/" /etc/ssh/sshd_config
	sed -i -e "s/#PermitRootLogin yes/PermitRootLogin no/" /etc/ssh/sshd_config
	systemctl restart sshd

	# Setup User
	adduser $superUser
	echo -e "$password" | passwd --stdin $superUser > /dev/null 2>&1
	gpasswd -a $superUser wheel > /dev/null 2>&1

	# Setup firewalld
	systemctl start firewalld > /dev/null 2>&1
	systemctl enable firewalld > /dev/null 2>&1
	firewall-cmd --add-service openvpn > /dev/null 2>&1
	firewall-cmd --permanent --add-service openvpn > /dev/null 2>&1
	firewall-cmd --permanent --add-service=dns > /dev/null 2>&1
	firewall-cmd --add-masquerade > /dev/null 2>&1
	firewall-cmd --permanent --add-masquerade > /dev/null 2>&1
	firewall-cmd --permanent --zone=public --add-port=443/tcp > /dev/null 2>&1
	firewall-cmd --permanent --zone=public --add-port=443/udp > /dev/null 2>&1
	## Add alternative ssh port
	firewall-cmd --permanent --zone=public --add-port=22/tcp > /dev/null 2>&1
	firewall-cmd --reload > /dev/null 2>&1
	
	# Start and enable ntpd
	sudo systemctl start ntpd > /dev/null 2>&1
	sudo systemctl enable ntpd > /dev/null 2>&1
	# Start and enable rng-tools for increasing entropy
	sudo systemctl start rngd > /dev/null 2>&1
	sudo systemctl enable rngd > /dev/null 2>&1

	# SELinux test and rules
	if [[ $(getenforce) = Enforcing ]] || [[ $(getenforce) = Permissive ]]; then
  		yum install policycoreutils-python -y  > /dev/null 2>&1
  		semanage port -a -t ssh_port_t -p tcp 22
  		semanage port -m -t openvpn_port_t -p tcp 443
  		semanage port -a -t openvpn_port_t -p udp 443
	fi
}

# Configure Cron Jobs
# Updates the server, clears the cache every 24 hours, and updates blacklisted domains
function cronjob {
	crontab -l > /tmp/cronjob | grep -v "no crontab for root"
	echo "0 0 * * * yum -y update" >> /tmp/cronjob
	echo "0 0 * * * unbound-control reload; systemctl restart unbound" >> /tmp/cronjob
	echo "0 0 * * * /bin/bash /opt/adblock.sh > /dev/null 2>&1" >> /tmp/cronjob
	crontab /tmp/cronjob
	rm -f /tmp/cronjob
}


# Configure Unbound
# Configures unbound recursive caching DNS server with root hint validation
function unbound {
	# Grab Configuration File
	rm -f /etc/unbound/unbound.conf
	cd ~
	cp ~/OpenVPN/unbound.conf /etc/unbound/unbound.conf
	unbound-control-setup  > /dev/null 2>&1
	chown unbound:root /etc/unbound/unbound_*
	chmod 440 /etc/unbound/unbound_*

	# Retrieve primary root DNS servers for root hint validation
	wget https://www.internic.net/domain/named.cache -O /etc/unbound/named.cache  > /dev/null 2>&1
	unbound-anchor -r /etc/unbound/named.cache  > /dev/null 2>&1
	
	# DNSSEC
	# Fix broken stuff
	rm -f /etc/unbound/root.key
	unbound-anchor -a /etc/unbound/root.key

	# Restart unbound and enable the service
	systemctl restart unbound.service  > /dev/null 2>&1
	systemctl start unbound > /dev/null 2>&1
	systemctl -f enable unbound.service  > /dev/null 2>&1
}

# Configure OpenVPN
function openvpnconfig {
	# Install and configure OpenVPN
	\cp -f /usr/share/doc/openvpn-*/sample/sample-config-files/server.conf /etc/openvpn
	sed -i -e "s/;local a.b.c.d/local 0.0.0.0/" /etc/openvpn/server.conf
	sed -i -e "s/local/local 0.0.0.0/" /etc/openvpn/server.conf
	sed -i -e "s/port 1194/port $port/" /etc/openvpn/server.conf
	sed -i -e "s/proto udp/proto tcp/" /etc/openvpn/server.conf
	sed -i -e "s/;push \"redirect-gateway def1 bypass-dhcp\"/push \"redirect-gateway def1 bypass-dhcp\"/" /etc/openvpn/server.conf
	#Implement OpenDNS
	#sed -i -e '/;push \"dhcp-option DNS 208.67.220.220\"/d' /etc/openvpn/server.conf
	#sed -i -e '/;push \"dhcp-option DNS 208.67.222.222\"/d' /etc/openvpn/server.conf
	sed -i -e '200ipush "dhcp-option DNS 10.8.0.1"' /etc/openvpn/server.conf
	sed -i -e "s/;group nobody/group nobody/" /etc/openvpn/server.conf
	sed -i -e "s/;user nobody/user nobody/" /etc/openvpn/server.conf
	sed -i 's/dh dh.*/dh dh4096.pem/g' /etc/openvpn/server.conf
	sed -i -e "s/server.crt/$commonName.crt/g" /etc/openvpn/server.conf
	sed -i -e "s/server.key/$commonName.key/g" /etc/openvpn/server.conf
	echo "" >> /etc/openvpn/server.conf
	echo "# Custom hardening" >> /etc/openvpn/server.conf 
	echo "cipher AES-256-CBC" >> /etc/openvpn/server.conf 
	echo "auth SHA512" >> /etc/openvpn/server.conf 
	echo "tls-cipher TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256:TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256:TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384:TLS-DHE-RSA-WITH-AES-256-CBC-SHA256" >> /etc/openvpn/server.conf 
	echo "tls-version-min 1.2" >> /etc/openvpn/server.conf 
	echo "tls-auth /etc/openvpn/easy-rsa/keys/ta.key 0" >> /etc/openvpn/server.conf 
	echo "remote-cert-eku \"TLS Web Client Authentication\"" >> /etc/openvpn/server.conf 

	# Copy Key Files
	mkdir -p /etc/openvpn/easy-rsa/keys
	\cp -rf /usr/share/easy-rsa/2.0/* /etc/openvpn/easy-rsa

	# Configure vars
	sed -i "s/KEY_SIZE=.*/KEY_SIZE=4096/g" /etc/openvpn/easy-rsa/vars
	sed -i 's/export CA_EXPIRE=3650/export CA_EXPIRE=365/' /etc/openvpn/easy-rsa/vars
	sed -i 's/export KEY_EXPIRE=3650/export KEY_EXPIRE=365/' /etc/openvpn/easy-rsa/vars
	sed -i "s/export KEY_COUNTRY=\"US\"/export KEY_COUNTRY=\"$country\"/" /etc/openvpn/easy-rsa/vars
	sed -i "s/export KEY_PROVINCE=\"CA\"/export KEY_PROVINCE=\"$province\"/" /etc/openvpn/easy-rsa/vars
	sed -i "s/export KEY_CITY=\"SanFrancisco\"/export KEY_CITY=\"$city\"/" /etc/openvpn/easy-rsa/vars
	sed -i "s/export KEY_ORG=\"Fort-Funston\"/export KEY_ORG=\"$organization\"/" /etc/openvpn/easy-rsa/vars
	sed -i "s/export KEY_EMAIL=\"me@myhost.mydomain\"/export KEY_EMAIL=\"$email\"/" /etc/openvpn/easy-rsa/vars
	sed -i "s/export KEY_OU=\"MyOrganizationalUnit\"/export KEY_OU=\"$organizationUnit\"/" /etc/openvpn/easy-rsa/vars
	sed -i "s/export KEY_NAME=\"EasyRSA\"/export KEY_NAME=\"$commonName\"/" /etc/openvpn/easy-rsa/vars
	sed -i "s/export KEY_CN=openvpn.example.com/export KEY_CN=\"$commonName\"/" /etc/openvpn/easy-rsa/vars

	# Copy OpenSSL configuration
	\cp -f /etc/openvpn/easy-rsa/openssl-1.0.0.cnf /etc/openvpn/easy-rsa/openssl.cnf

	# Start generating keys and certificates
	cd /etc/openvpn/easy-rsa
	source ./vars > /dev/null 2>&1
	./clean-all  > /dev/null 2>&1
	./build-ca --batch  > /dev/null 2>&1
	./build-key-server --batch $commonName  > /dev/null 2>&1
	echo "Generating DH parameters, this will take a while(~45 minutes)."
	./build-dh > /dev/null 2>&1
	cd /etc/openvpn/easy-rsa/keys
	cp dh4096.pem ca.crt $commonName.crt $commonName.key /etc/openvpn
	openvpn --genkey --secret ta.key > /dev/null 2>&1

	# Setup routing
	echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
	sysctl -p /etc/sysctl.conf > /dev/null 2>&1

	# Manage service
	systemctl -f enable openvpn@server.service > /dev/null 2>&1
	systemctl start openvpn@server.service > /dev/null 2>&1
}

# User Input
# Get user input for required variables
function input {
	# Notes	
	echo "Please enter the following values required for setup:"
	echo "You can leave the default values if you so choose."

	# Get IP address
	default=$(curl -s https://4.ifcfg.me/)
	read -p "Enter IP address [$default]: " IP
	IP=${IP:-$default}

	# Get username
	default="johnny"
	read -p "Enter username [$default]: " superUser
	superUser=${superUser:-$default}

	# Get password and generate secure random password
	default=$(strings /dev/urandom | grep -o '[[:alnum:]]' | head -n 30 | tr -d '\n')
	read -p "Enter password [$default]: " password
	password=${password:-$default}

	# Get port
	default="443"
	read -p "Enter port for OpenVPN [$default]: " port
	port=${port:-$default}

	# Get common name
	default="none.dontknow.com"
	read -p "Enter server hostname [$default]: " commonName
	commonName=${commonName:-$default}

	# Get country
	default="US"
	read -p "Enter country abbreviation [$default]: " country
	country=${country:-$default}

	# Get providence/state
	default="Califonia"
	read -p "Enter providence/state [$default]: " province
	province=${province:-$default}

	# Get providence/state
	default="Sacramento"
	read -p "Enter city [$default]: " city
	city=${city:-$default}

	# Get organization
	default="None"
	read -p "Enter organization [$default]: " organization
	organization=${organization:-$default}

	# Get organization unit
	default="None"
	read -p "Enter organization unit [$default]: " organizationUnit
	organizationUnit=${organizationUnit:-$default}

	# Get email
	default="none@ofyourbusiness.com"
	read -p "Enter email [$default]: " email
	email=${email:-$default}
	
	# Clear the screen
	clear
}

input
packages
secure
openvpnconfig
unbound
cronjob
