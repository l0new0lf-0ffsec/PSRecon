# PSRecon
### **Note: Would not recommend upgrade on issued VM**
###### This PSCore automation tool is built for reconnaissance automation toward the OSCP. 
###### - Currently building through lab..


### Requirements : 
**(needs to be tested more)**

#### PSCore (v6.2 tested)
###### After Nov 2019 Install:
```
apt -y install powershell
```
###### Before Nov 2019 Install:
```
apt -y install curl gnupg apt-transport-https
curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add -
echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-stretch-prod stretch main" &gt; /etc/apt/sources.list.d/powershell.list
apt update
apt -y install powershell
```
#### dnsrecon
###### Install:
```
apt install libavahi-compat-libdnssd1 -y
apt install python-setuptools -y
```

#### masscan
###### Install:

```
apt install gcc make libpcap-dev -y
cd masscan
make -j
```
