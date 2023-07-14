# ESXI-Project
Failover+DMZ+Apache2-Site-Hosting+Thunderbird



# Topology

![image7](https://github.com/AF-Github1/ESXI-Project/assets/133685290/261c4820-9b5d-461b-b056-fccfadd9c114)


Windows INSIDE: 192.168.31.129( DHCP) - 192.168.31.1 Linux RTR
Linux DMZ: 172.31.0.2 - 172.31.0.1 Linux RTR
Linux Failover: 192.168.31.1

Credentials used for every linux machine:

**username: debian**

**password: Passw0rd**

# Port groups and switches


![image5](https://github.com/AF-Github1/ESXI-Project/assets/133685290/2687f8d1-c4be-4b10-bd5a-168ae0b75d2a)

![image3](https://github.com/AF-Github1/ESXI-Project/assets/133685290/706ebcee-92ee-409b-803a-7c91b9202284)

Settings left on default

# LINUX RTR INSTALLATION

hostname: antonioRTRv2

Primary Interface chosen as ens192

IP: 192.168.15.174


Configuration

![image2](https://github.com/AF-Github1/ESXI-Project/assets/133685290/57fae05d-b7a0-4ad0-9d34-19be5c0537b2)


# LINUX FAILOVER INSTALLATION

hostname: antonioFAILOVERv2


IP: 192.168.31.2


Configuration

![image6](https://github.com/AF-Github1/ESXI-Project/assets/133685290/b75c00c5-a050-411b-822c-472dbc9118c4)


# LINUX DMZ INSTALLATION

hostname: antonioDMZv2

IP: 172.31.0.2, later changed to 172.31.0.100 through DHCP

Configuration

![image10](https://github.com/AF-Github1/ESXI-Project/assets/133685290/a26544a5-d81b-4a71-a515-49836fa9b8f8)


# WINDOWS INSIDE INSTALLATION

username: antonio
password: Passw0rd

IP: 192.168.31.129 (DHCP provided)

Configuration


![image12](https://github.com/AF-Github1/ESXI-Project/assets/133685290/acd011f5-731e-4b45-a7a5-c61e952036fe)

While Windows is booting up there will be a screen prompting a random key press in order to load the OS from disk. If this is not done on time the boot will fail and you will need to restart and try it again.

OS used during installation: Windows 10 Pro

After the machines are fully installed check their settings to make sure the CD drive is connected. If not, check the box

![image9](https://github.com/AF-Github1/ESXI-Project/assets/133685290/811331d7-733f-46eb-9264-4971fce72b0d)

# LINUX RTR Initial Configuration

Install all necessary software

apt install exim4 dovecot-imapddovecot-pop3d bind9 bind9-dnsutils bind9-doc bind9-utils bind9utils easy-rsa git sasl2-bin resolvconf isc-dhcp-server


/etc/network/interfaces configuration

```
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).


source /etc/network/interfaces.d/*


# The loopback network interface
auto lo
iface lo inet loopback


# The primary network interface
allow-hotplug ens192
iface ens192 inet static
        address 192.168.15.174/24
        gateway 192.168.15.1
        # dns-* options are implemented by the resolvconf package, if installed
        dns-search enta.pt
# Inside network interface
allow-hotplug ens224
iface ens224 inet static
        address 192.168.31.1/24
        # dns-* options are implemented by the resolvconf package, if installed
        dns-search enta.pt
# DMZ network interface
allow-hotplug ens256
iface ens256 inet static
        address 172.31.0.1/24
        # dns-* options are implemented by the resolvconf package, if installed
        dns-search enta.pt
```

# LINUX RTR isc-dhcp-server configuration




Add the necessary interfaces to the last line. In my case, ens192,ens224 and ens256
INTERFACESv4="ens192 ens224 ens256"

```

nano /etc/default/isc-dhcp-server


# Defaults for isc-dhcp-server (sourced by /etc/init.d/isc-dhcp-server)

# Path to dhcpd's config file (default: /etc/dhcp/dhcpd.conf).
#DHCPDv4_CONF=/etc/dhcp/dhcpd.conf
#DHCPDv6_CONF=/etc/dhcp/dhcpd6.conf

# Path to dhcpd's PID file (default: /var/run/dhcpd.pid).
#DHCPDv4_PID=/var/run/dhcpd.pid
#DHCPDv6_PID=/var/run/dhcpd6.pid

# Additional options to start dhcpd with.
#       Don't use options -cf or -pf here; use DHCPD_CONF/ DHCPD_PID instead
#OPTIONS=""

# On what interfaces should the DHCP server (dhcpd) serve DHCP requests?
#       Separate multiple interfaces with spaces, e.g. "eth0 eth1".
INTERFACESv4="ens192 ens224 ens256"

```


# LINUX RTR dhcpd.conf 

nano /etc/dhcp/dhcpd.conf
```
# dhcpd.conf
#
# Sample configuration file for ISC dhcpd
#

# option definitions common to all supported networks…

#Replace domain name and domain-name-server with what you need
option domain-name "enta.pt";
option domain-name-servers 192.168.15.174, 192.168.31.1, 172.31.0.1;


# DHCP FAILOVER

omapi-port 7911;
omapi-key DHCP_FAILOVER;


# If you generate your own key then you will have to change the key in this spot
key "DHCP_FAILOVER" {
        algorithm hmac-sha512;
        secret "bpeWoyJ7sfqcnCbJ4EdrPahz0caCkLlmi61x7BlT7QpkcSAt4XB18PBhmD+OuSB7c1ZpiFumXMMVbSwgu8aMmA==";
};





default-lease-time 600;
max-lease-time 7200;

# The ddns-updates-style parameter controls whether or not the server will
# attempt to do a DNS update when a lease is confirmed. We default to the
# behavior of the version 2 packages ('none', since DHCP v2 didn't
# have support for DDNS.)
ddns-update-style none;

# If this DHCP server is the official DHCP server for the local
# network, the authoritative directive should be uncommented.
#authoritative;

# Use this to send dhcp log messages to a different log file (you also
# have to hack syslog.conf to complete the redirection).
#log-facility local7;

# No service will be given on this subnet, but declaring it helps the 
# DHCP server to understand the network topology.

#subnet 10.152.187.0 netmask 255.255.255.0 {
#}

# This is a very basic subnet declaration.

#subnet 10.254.239.0 netmask 255.255.255.224 {
#  range 10.254.239.10 10.254.239.20;
#  option routers rtr-239-0-1.example.org, rtr-239-0-2.example.org;
#}

# This declaration allows BOOTP clients to get dynamic addresses,
# which we don't really recommend.

#subnet 10.254.239.32 netmask 255.255.255.224 {
#  range dynamic-bootp 10.254.239.40 10.254.239.60;
#  option broadcast-address 10.254.239.31;
#  option routers rtr-239-32-1.example.org;
#}

# A slightly different configuration for an internal subnet.
#subnet 10.5.5.0 netmask 255.255.255.224 {
#  range 10.5.5.26 10.5.5.30;
#  option domain-name-servers ns1.internal.example.org;
#  option domain-name "internal.example.org";
#  option routers 10.5.5.1;
#  option broadcast-address 10.5.5.31;
#  default-lease-time 600;
#  max-lease-time 7200;
#}

# Hosts which require special configuration options can be listed in
# host statements.   If no address is specified, the address will be
# allocated dynamically (if possible), but the host-specific information
# will still come from the host declaration.

#host passacaglia {
#  hardware ethernet 0:0:c0:5d:bd:95;
#  filename "vmunix.passacaglia";
#  server-name "toccata.example.com";
#}



# Fixed IP addresses can also be specified for hosts.   These addresses
# should not also be listed as being available for dynamic assignment.
# Hosts for which fixed IP addresses have been specified can boot using
# BOOTP or DHCP.   Hosts for which no fixed address is specified can only
# be booted with DHCP, unless there is an address range on the subnet
# to which a BOOTP client is connected which has the dynamic-bootp flag
# set.
#host fantasia {
#  hardware ethernet 08:00:07:26:c0:a5;
#  fixed-address fantasia.example.com;
#}

# You can declare a class of clients and then do address allocation
# based on that.   The example below shows a case where all clients
# in a certain class get addresses on the 10.17.224/24 subnet, and all
# other clients get addresses on the 10.0.29/24 subnet.

#class "foo" {
#  match if substring (option vendor-class-identifier, 0, 4) = "SUNW";
#}

# Failover setup, peer address being the address of the other failover dhcp server that you will use. 

failover peer "failover-example" {
        primary;
        address 192.168.31.1;
        port 519;
        peer address 192.168.31.2;
        peer port 520;
        max-response-delay 60;
        max-unacked-updates 10;
        mclt 3600;
        split 256;
        load balance max seconds 3;
}

subnet 192.168.31.0 netmask 255.255.255.0 {
  option routers 192.168.31.1;
  option broadcast-address 192.168.31.255;
  pool {
        failover peer "failover-example";
        range 192.168.31.128 192.168.31.191;
  }
}

# A slightly different configuration for an internal subnet.
#subnet 192.168.31.0 netmask 255.255.255.0 {
#  range 192.168.31.128 192.168.31.191;
#  option routers 192.168.31.1;
#  option broadcast-address 192.168.31.255;
#}
subnet 172.31.0.0 netmask 255.255.255.0 {
  range 172.31.0.64 172.31.0.95;
  option routers 172.31.0.1;
  option broadcast-address 172.31.0.255;
}
#DMZ
host 172.31.0.100 {
  hardware ethernet 00:50:56:86:05:65;
  fixed-address 172.31.0.100;
  option routers 172.31.0.1;
  option broadcast-address 172.31.0.255;
}
#Windows machine
host 192.168.31.129 {
  hardware ethernet 00:0C:29:D3:FA:6D;
  fixed-address 192.168.31.129;
  option routers 192.168.31.1;
  option broadcast-address 192.168.31.255;
}


#Declaring zones
key DHCP_UPDATER {
        algorithm HMAC-MD5.SIG-ALG.REG.INT;
        secret pRP5FapFoJ95JEL06sv4PQ==;
};

zone 31.172.in-addr.arpa. {
        primary 127.0.0.1;
        key DHCP_UPDATER;
}

zone 31.168.192.in-addr.arpa. {
        primary 127.0.0.1;
        key DHCP_UPDATER;
}

zone 15.168.192.in-addr.arpa. {
        primary 127.0.0.1;
        key DHCP_UPDATER;
}

#update-static-leases on;

```
# LINUX FAILOVER CONFIGURATION

Similar configuration but the failover peer section will be changed to the secondary version

nano /etc/dhcp/dhcpd.conf
```
# dhcpd.conf
#
# Sample configuration file for ISC dhcpd
#

# option definitions common to all supported networks...
option domain-name "enta.pt";
option domain-name-servers 192.168.15.174, 192.168.31.1,172.31.0.1;

default-lease-time 600;
max-lease-time 7200;

omapi-port 7911;
omapi-key DHCP_FAILOVER;

key DHCP_FAILOVER {
        algorithm hmac-sha512;
        secret "emo/juNfRfG5gQSGbmoYQ/zinctXoYPaYjlxKnYtoG5iPxofDCshLyS66q32qPpqqe6KpMl4q5HsgN0Q/VVBBw==";
}



# The ddns-updates-style parameter controls whether or not the server will
# attempt to do a DNS update when a lease is confirmed. We default to the
# behavior of the version 2 packages ('none', since DHCP v2 didn't
# have support for DDNS.)
ddns-update-style none;

# If this DHCP server is the official DHCP server for the local
# network, the authoritative directive should be uncommented.
#authoritative;

# Use this to send dhcp log messages to a different log file (you also
# have to hack syslog.conf to complete the redirection).
#log-facility local7;

# No service will be given on this subnet, but declaring it helps the 
# DHCP server to understand the network topology.

#subnet 10.152.187.0 netmask 255.255.255.0 {
#}

# This is a very basic subnet declaration.

#subnet 10.254.239.0 netmask 255.255.255.224 {
#  range 10.254.239.10 10.254.239.20;
#  option routers rtr-239-0-1.example.org, rtr-239-0-2.example.org;
#}

# This declaration allows BOOTP clients to get dynamic addresses,
# which we don't really recommend.

#subnet 10.254.239.32 netmask 255.255.255.224 {
#  range dynamic-bootp 10.254.239.40 10.254.239.60;
#  option broadcast-address 10.254.239.31;
#  option routers rtr-239-32-1.example.org;
#}

# A slightly different configuration for an internal subnet.
#subnet 10.5.5.0 netmask 255.255.255.224 {
#  range 10.5.5.26 10.5.5.30;
#  option domain-name-servers ns1.internal.example.org;
#  option domain-name "internal.example.org";
#  option routers 10.5.5.1;
#  option broadcast-address 10.5.5.31;
#  default-lease-time 600;
#  max-lease-time 7200;
#}

# Hosts which require special configuration options can be listed in
# host statements.   If no address is specified, the address will be
# allocated dynamically (if possible), but the host-specific information
# will still come from the host declaration.

#host passacaglia {
#  hardware ethernet 0:0:c0:5d:bd:95;
#  filename "vmunix.passacaglia";
#  server-name "toccata.example.com";
#}

# Fixed IP addresses can also be specified for hosts.   These addresses
# should not also be listed as being available for dynamic assignment.
# Hosts for which fixed IP addresses have been specified can boot using
# BOOTP or DHCP.   Hosts for which no fixed address is specified can only
# be booted with DHCP, unless there is an address range on the subnet
# to which a BOOTP client is connected which has the dynamic-bootp flag
# set.
#host fantasia {
#  hardware ethernet 08:00:07:26:c0:a5;
#  fixed-address fantasia.example.com;
#}

# You can declare a class of clients and then do address allocation
# based on that.   The example below shows a case where all clients
# in a certain class get addresses on the 10.17.224/24 subnet, and all
# other clients get addresses on the 10.0.29/24 subnet.

#class "foo" {
#  match if substring (option vendor-class-identifier, 0, 4) = "SUNW";
#}

#shared-network 224-29 {
#  subnet 10.17.224.0 netmask 255.255.255.0 {
#    option routers rtr-224.example.org;
#  }
#  subnet 10.0.29.0 netmask 255.255.255.0 {
#    option routers rtr-29.example.org;
#  }
#  pool {
#    allow members of "foo";
#    range 10.17.224.10 10.17.224.250;
#  }
#  pool {
#    deny members of "foo";
#    range 10.0.29.10 10.0.29.230;
#  }
#}


failover peer "failover-example" {
        secondary;
        address 192.168.31.2;
        port 520;
        peer address 192.168.31.1;
        peer port 519;
        max-response-delay 60;
        max-unacked-updates 10;
        load balance max seconds 3;
}


subnet 192.168.31.0 netmask 255.255.255.0 {
    pool {
        failover peer "failover-example";
        range 192.168.31.128 192.168.31.191;
        option routers 192.168.31.1;
        option broadcast-address 192.168.31.255;
    }
}


subnet 172.31.0.0 netmask 255.255.255.0 {
  range 172.31.0.64 172.31.0.95;
  option routers 172.31.0.1;
  option broadcast-address 172.31.0.255;
}
host 172.31.0.100 {
  hardware ethernet 00:50:56:86:05:65;
  fixed-address 172.31.0.100;
  option routers 172.31.0.1;
  option broadcast-address 172.31.0.255;
}

key DHCP_UPDATER {
        algorithm HMAC-MD5.SIG-ALG.REG.INT;
        secret pRP5FapFoJ95JEL06sv4PQ==;
};

zone 31.172.in-addr.arpa. {
        primary 127.0.0.1;
        key DHCP_UPDATER;
}

zone 31.168.192.in-addr.arpa. {
        primary 127.0.0.1;
        key DHCP_UPDATER;
}

zone 15.168.192.in-addr.arpa. {
        primary 127.0.0.1;
        key DHCP_UPDATER;
}
```

# LINUX RTR sysctl configuration

nano /etc/sysctl.conf 

Uncomment

```
net.ipv4.ip_forward = 1
```
This enables forwarding

sysctl -p checks if it is uncommented if it returns **net.ipv4.ip_forward = 1**

# LINUX RTR /var/cache/bind files

For taking care of zones/dns

**cd /var/cache/bind**

**nano db.172.31.enta.pt**
```
;
; BIND reverse data file for local loopback interface
;
$TTL    604800
@       IN      SOA     enta.pt. root.enta.pt. (
                              1         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      NS      enta.pt.
1.0     IN      PTR     enta.pt.
1.0     IN      PTR     ns.enta.pt.
1.0     IN      PTR     antoniortr.enta.pt.
100.0   IN      PTR     smtp.enta.pt.
100.0   IN      PTR     pop.enta.pt.
100.0   IN      PTR     imap.enta.pt.
100.0   IN      PTR     www.enta.pt.
```

**nano db.192.168.15.enta.pt**
```
;
; BIND reverse data file for local loopback interface
;
$TTL    604800
@       IN      SOA     enta.pt. root.enta.pt. (
                              1         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      NS      enta.pt.
174     IN      PTR     enta.pt.
```
**nano db.192.168.31.enta.pt**
```
;
; BIND reverse data file for local loopback interface
;
$TTL    604800
@       IN      SOA     enta.pt. root.enta.pt. (
                              1         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      NS      enta.pt.
174     IN      PTR     enta.pt.
```
**db.192.168.31.enta.pt**
```
; BIND reverse data file for local loopback interface
;
$TTL    604800
@       IN      SOA     enta.pt. root.enta.pt. (
                              1         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      NS      enta.pt.
1       IN      PTR     enta.pt.
```
**nano db.enta.pt**
```
$ORIGIN .
$TTL 604800     ; 1 week
enta.pt                 IN SOA  enta.pt. root.enta.pt. (
                                7          ; serial
                                604800     ; refresh (1 week)
                                86400      ; retry (1 day)
                                2419200    ; expire (4 weeks)
                                604800     ; minimum (1 week)
                                )
                        NS      ns.enta.pt.
                        NS      enta.pt.
                        A       172.31.0.1
                        A       192.168.15.174
                        A       192.168.31.1
                        MX      10 smtp.enta.pt.
$ORIGIN enta.pt.
$TTL 300        ; 5 minutes
Admin                   A       172.31.0.100
                        DHCID   ( AAIBp5hb8ykivvPe6tFBfcSNX3Bnq/5M08YRkZBMJ5bB
                                JE0= ) ; 2 1 32
$TTL 604800     ; 1 week
antoniortr              A       172.31.0.1
                        A       192.168.15.1
                        A       192.168.31.1
$TTL 300        ; 5 minutes
DESKTOP-P1FAKJT         A       192.168.31.128
                        DHCID   ( AAEBfBCUfLF4mcUUiidPTnnTMjzpAz827jgDJ9sqiZY6
                                05Y= ) ; 1 1 32
$TTL 604800     ; 1 week
imap                    A       172.31.0.1
ns                      A       172.31.0.1
pop                     A       172.31.0.1
smtp                    A       172.31.0.1
www                     CNAME   enta.pt.

```
# LINUX RTR resolvconf

nano /etc/resolv.conf

Add this line
```
search enta.pt
```
# LINUX RTR CERTIFICATE GENERATION AND SIGNING THROUGH EASYRSA


```
./easyrsa init-pki
./easyrsa build-ca nopass

./easyrsa --subject-alt-name="DNS:www.enta.pt" gen-req www.enta.pt nopass
./easyrsa --subject-alt-name="DNS:smtp.enta.pt" gen-req smtp.enta.pt nopass
./easyrsa --subject-alt-name="DNS:pop.enta.pt" gen-req pop.enta.pt nopass

./easyrsa sign-req server www.enta.pt
./easyrsa sign-req server smtp.enta.pt
./easyrsa sign-req server pop.enta.pt

```



# LINUX RTR TO DMZ CERTIFICATE TRANSFERS / APACHE2 SETUP


If you haven’t already take care of installing/enabling apache in the DMZ

apt install apache2
a2ensite default-ssl.conf 
a2enmod ssl
systemctl restart apache2
systemctl status apache2

In the router:
```
scp www.enta.pt.crt debian@172.31.0.100:/home
scp www.enta.pt.key debian@172.31.0.100:/home
scp /etc/easy-rsa/pki/ca.crt debian@172.31.0.100:/home
```

Doesn’t particularly matter where you send it, as long as you have permissions to do so. In my case I just send it directly to /home

In the DMZ:
```
cp /home/www.enta.pt.crt /etc/ssl/certs/
cp /home/www.enta.pt.key /etc/ssl/private/
cp /home/ca.crt /etc/ssl/certs/
```

In the /etc/apache2/sites-available/default-ssl.conf file change the following section to point to the location of your transferred certificate and key.
```
                SSLCertificateFile      /etc/ssl/certs/www.enta.pt.crt
                SSLCertificateKeyFile /etc/ssl/private/www.enta.pt.key
```
restart apache2 after changing the file

**systemctl restart apache2**


Now as long as I am in the same network, outside machines should be able to connect to the site using the IP 192.168.15.174 and the inside windows machine should be able to do so with the IP 172.31.0.100 



# LINUX RTR Email configuration (Dovecot, exim4)

If not installed already, install these now


apt-get install exim4-daemon-heavy sasl2-bin dovecot-pop3d dovecot-imapd


cd /etc
cp -R /usr/share/easy-rsa .
cd easy-rsa
ln -s openssl-1.0.0.cnf openssl.cnf


./easyrsa gen-req mailsrv.enta.pt nopass
./easyrsa sign-req server mailsrv.enta.pt


cp keys/mailsrv.enta.pt.crt /etc/ssl/certs/
cp keys/mailsrv.enta.pt.key /etc/ssl/private/


Giving permissions


addgroup --system ssl-cert
chown -R root:ssl-cert /etc/ssl/private
chmod 710 /etc/ssl/private
chmod 440 /etc/ssl/private/*


Creating users


adduser Debian-exim ssl-cert
adduser Debian-exim sasl
adduser dovecot ssl-cert


dpkg-reconfigure exim4-config
```
Internet site; mail is sent and received directly using SMTP
enta.pt
Clear
enta.pt
Clear
Clear
<No>
Maildir format in home directory
<No>
```



**nano /etc/default/saslauthd**

Change to: START=yes

**nano /etc/dovecot/conf.d/10-ssl.conf**
```
ssl = yes
# These paths will depend on where you put your own certificates and keys, and what you named them
ssl_cert = </etc/ssl/certs/mailsrv.enta.pt.crt
ssl_key = </etc/ssl/private/mailsrv.enta.pt.key
```

**nano /etc/dovecot/conf.d/10-auth.conf**

uncomment and change
```
disable_plaintext_auth = no
```
**nano /etc/dovecot/conf.d/10-mail.conf**

uncomment: 
```
mail_location = maildir:~/Maildir
```
comment: 
```
mail_location = mbox:~/mail:INBOX=/var/mail/%u
```
**nano /etc/exim4/exim4.conf.template**

Add  these lines:
```
MAIN_TLS_ENABLE=yes
MAIN_TLS_CERTIFICATE=/etc/ssl/certs/mailsrv.enta.pt.crt
MAIN_TLS_PRIVATEKEY=/etc/ssl/private/mailsrv.enta.pt.key
```

uncomment section **below** this line: ‘# Authenticate against local passwords using sasl2-bin’


echo "tls_on_connect_ports = 465" > /etc/exim4/exim4.conf.localmacros



**nano /etc/default/exim4**

copy: -oX 25:587:10025 -oP /run/exim4/exim.pid
paste and add 465: 


SMTPLISTENEROPTIONS='-oX 25:465:587:10025 -oP /run/exim4/exim.pid'


/etc/exim4/exim4.conf.localmacros

Add these lines

```
tls_on_connect_ports = 465
REQUIRE_PROTOCOL = smtps
```


cd /etc/skel

**mkdir Maildir && cd Maildir && maildirmake.dovecot .**

**systemctl enable saslauthd exim4 dovecot**

**systemctl restart saslauthd exim4 dovecot**

**systemctl status saslauthd exim4 dovecot**


**WINDOWS INSIDE Thunderbird**

The service used for the Windows Inside machine was Thunderbird

Install thunderbird

https://www.thunderbird.net/en-US/

After the installation you should be presented with this screen. Go to the Home tab.

![image13](https://github.com/AF-Github1/ESXI-Project/assets/133685290/5b69094a-172b-45cc-9032-a46465942970)

Go to account settings

![image8](https://github.com/AF-Github1/ESXI-Project/assets/133685290/747d7a4b-59a5-4217-bd29-4bbb35c3a447)

You will now need to add the information relative to the SMTP Servers

![image15](https://github.com/AF-Github1/ESXI-Project/assets/133685290/7e9522e1-3821-4e74-9c0c-4a6113c89635)

You must add 3 different instances, which will have different ports and usernames


![image14](https://github.com/AF-Github1/ESXI-Project/assets/133685290/782c0583-34a1-4884-8248-113c3d8a2fcc)

![image11](https://github.com/AF-Github1/ESXI-Project/assets/133685290/fcf82cb9-7ec3-4686-ae8c-e3ecfad39527)

![image4](https://github.com/AF-Github1/ESXI-Project/assets/133685290/7f43f840-f8d2-4177-8ee8-5f31cadb8f28)

Go back to the home tab and click the email icon. You will be presented with a new screen. Fill it up with your credentials. It should be able to detect the configuration in your local machine if previous steps were done correctly.
In my case I later accessed this from another location, as such it’s finding a configuration in the public database


![image1](https://github.com/AF-Github1/ESXI-Project/assets/133685290/753a245a-e645-4c20-8f77-ea22d834a09b)

Press done and you should have access to your email. You can test it out by trying to send one to yourself. If it works, it is configured correctly.

You can try with different ports with something like this:

![Screenshot from 2023-07-14 11-48-43](https://github.com/AF-Github1/ESXI-Project/assets/133685290/cb62d3a0-a28d-4ade-941b-97a6dbd31803)


All of these should be able to work properly provided everything is configured correctly. To note that sometimes IMAP might have some conflicts for who knows what reason and not work properly even if your setup is fine. You can tell this is happening when you try to send an email and it takes a extremely long while to actually deliver, without it ever actually saying it can't deliver said email












