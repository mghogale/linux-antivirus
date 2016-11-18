#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define DUMMY_PATH "/root/dummy"

/* This is a hack used for displaying graphical pop-up.
   It continously checks the status of file size and if changed then 
   it treats it as kernel found a virus and wrote to the file.
   It then displays the pop-up.
   Really hacky fix but it works*/

int
main(int argc, char *argv[])
{
   struct stat sb;
   long long curr_size = 0;
   long long prev_size = 0;

   if (stat(DUMMY_PATH, &sb) == -1) {
        perror("GRAPHICAL POPUP: Could not stat");
	exit(EXIT_FAILURE);
    }

   prev_size = curr_size = sb.st_size;

while(1){

   if (stat(DUMMY_PATH, &sb) == -1) {
        perror("GRAPHICAL POPUP: Could not stat");
	exit(EXIT_SUCCESS);
    }

   curr_size = (long long) sb.st_size;

	if (curr_size != prev_size){
		prev_size = curr_size;
		system("zenity --error &");
	} else {
		/* go back to sleep */
		sleep(1);
	}

 }
   exit(EXIT_SUCCESS);
}
