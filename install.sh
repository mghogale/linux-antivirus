touch /root/dummy
pkill popup
gcc -o popup popup.c
./popup &

rmmod antivirus.ko
insmod antivirus.ko
