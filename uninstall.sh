pkill popup
rmmod antivirus.k0
rm -f /root/dummy
rm -f /tmp/antivirus.properties
rm -f /usr/local/bin/antivirus-update
rm -f /usr/local/bin/antivirus-scan
cp /dev/null /root/dummy

rm -f /home/.InformationIcon.png
rm -f /home/.CheckMark.png
cp InformationIcon.png /home/.InformationIcon.png
notify-send -i /home/.InformationIcon.png 'Antivirus Uninstalled!'
rm -f /home/.InformationIcon.png
