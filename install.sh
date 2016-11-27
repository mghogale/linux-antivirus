rmmod antivirus.ko
touch /root/dummy

gcc user.c -o user

virus_file="/root/virus.db"
whitelist_file="/root/whitelist.db"
if [ ! -f "$virus_file" -o ! -f "$whitelist_file" ]
then
        cp 'antivirus-update' '/usr/local/bin/'
        cp 'antivirus.properties' '/tmp/'
        antivirus-update
	cp 'antivirus-scan' '/usr/local/bin/'
	cp 'user' '/usr/local/bin/'
fi

pkill popup
gcc -o popup popup.c
./popup &

rm -f /home/.CheckMark.png
cp CheckMark.png /home/.CheckMark.png
notify-send -i /home/.CheckMark.png 'Antivirus Installed Successfully!'

insmod antivirus.ko
