touch /root/dummy

virus_file="/root/virus.db"
whitelist_file="/root/whitelist.db"
if [ ! -f "$virus_file" -o ! -f "$whitelist_file" ]
then
        cp 'antivirus-update' '/usr/local/bin/'
        cp 'antivirus.properties' '/tmp/'
        antivirus-update
fi

pkill popup
gcc -o popup popup.c
./popup &

rmmod antivirus.ko
insmod antivirus.ko
rm -rf /home/.CheckMark.png
cp CheckMark.png /home/.CheckMark.png
notify-send -i /home/.CheckMark.png 'Antivirus Installed Successfully!'
