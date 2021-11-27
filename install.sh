#!/bin/bash

root() {
user=`whoami`
if [[ $user != 'root' ]]; then
	echo "Please run as root\n"
	exit
fi
}

pakage_check() {

printf "installing pip3...."
pakage=`which pip3`
if [[ $pakage == '' ]]; then
	printf "installing pip3..."
	apt-get install python3-pip
else
	sleep 0.5
	printf "\npip3 installed at '$pakage'"
fi

sleep 0.5

printf "\ninstall random2....\n"
pip3 install random2

check='/etc/init.d/postgresql'
if [[ -f $check ]]; then
	printf "postgresql installed .....\n"
else
	apt insatll postgresql -y
fi
pakage=`which msfconsole`
pakage_name='msfconsole'
if [[ $pakage == '' ]]; then
	printf "pakage $pakage_name not install\n"
	sleep 0.2
	printf "pakage '$pakage_name' installing...\n"
	apt install metasploit-framework
else
	sleep 0.5
	printf "pakage installed at '$pakage'\n"
fi
}

access() {
mkdir /usr/share/OS-Access_IHA >& /dev/null
cp osaccess.py /usr/share/OS-Access_IHA

cat > /usr/local/bin/osaccess <<EOF
#!/bin/bash
python3 /usr/share/OS-Access_IHA/osaccess.py
EOF

chmod +x /usr/local/bin/osaccess

printf "\n\ntype 'osaccess' anywhere on the terminal\n"
}

root
pakage_check
access


