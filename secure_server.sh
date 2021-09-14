#!/bin/bash

# The script consists of a two-step invocation
# 1 (required once): Encrypt a clear-text keyfile, and optionally delete the clear-text keyfile
# 2: Run the calimero server using the encryped keyfile, providing the decrypted content to the server


# Config path and name of encrypted file
keyfile_enc="keyfile.enc"

# Config path of the temporary decrypted keyfile passed to the started server instance
# The same path has to be set in the server configuration file
# TODO /dev/shm won't do it on FreeBSD or MacOS
keyfile_dec="/dev/shm/calimero-server-keyfile"

server_config_path="resources/server-config.xml"
run_server="./build/distributions/calimero-server-2.5-rc1/bin/calimero-server"

# openssl option is not recognized on some platforms
sslOptionPbkdf2="-pbkdf2"
#sslOptionPbkdf2=""

if [ "$1" = "-?" ] || [ "$1" = "-h" ] || [ "$1" = "--help" ];then
	echo "Runs the calimero server using an encrypted keyfile"
	echo Usage $0 "[-e keyfile]"
	echo "      -e    encrypt a cleartext keyfile"
	echo "Note: default settings assume you ran './gradlew build' and"
	echo "      extracted './build/distributions/calimero-server-2.5-rc1.[tar|zip]'"
	exit 0
fi

if [ "$1" = "-e" ]; then
	cleartext="$2"
	
	openssl aes-256-cbc $sslOptionPbkdf2 -in $cleartext -out $keyfile_enc
	ret=$?
	if [ $ret -ne 0 ]; then
		exit 1
	fi
	
	read -p "Done. Remove '$cleartext' [y/N]: " remove
	if [ "$remove" = "y" ] || [ "$remove" = "yes" ]; then
		shred --remove $cleartext
	fi
	exit 0
fi

# shred is not available everywhere
# TODO could also check gshred as alternative
command -v shred >/dev/null 2>&1 || { echo "Command 'shred' not available, don't start keyfile decryption."; exit 1; }

#keyfile_dec=$(mktemp) || exit 1
touch "$keyfile_dec" || exit 1
chmod 600 "$keyfile_dec"

serverPid=-1

cleanup () {
	[ -f "$keyfile_dec" ] && shred --remove $keyfile_dec
	kill $serverPid
}
trap cleanup EXIT

openssl aes-256-cbc $sslOptionPbkdf2 -d -in "$keyfile_enc" -out "$keyfile_dec"
ret=$?
if [ $ret -ne 0 ]; then
	echo "Keyfile decryption failed, server not started. Exit."
	exit 1
fi
"$run_server" --no-stdin "$server_config_path" &
serverPid=$!
echo "Run calimero server, PID" $serverPid

sleep 5
shred --remove ${keyfile_dec}

wait $serverPid
