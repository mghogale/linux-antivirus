#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
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
   FILE *file_pointer = NULL;
   char *buffer = NULL, cmd[4150];
   int ret, length;
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
		file_pointer = fopen(DUMMY_PATH, "r");
		if(file_pointer == NULL){
			printf("\nCannot open dummy file");
			goto out;
		}

		ret = fseek(file_pointer, 0, SEEK_END);
		if(ret != 0){
			printf("\nCannot perform seek operation on file");
			goto out;
		}
		length = ftell(file_pointer);
		if(length == -1){
			printf("\nCannot find length of file");
			goto out;
		}
		buffer = malloc(length + 1);
		if(buffer == NULL){
			printf("\nCan't allocate memory ");
			goto out;
		}
		buffer[length] = '\0';
		rewind (file_pointer);
		fread(buffer,length,1,file_pointer);
		cmd[0] = '\0';
		strcat(cmd,"zenity --error --text ' ");
		strcat(cmd,buffer);
		strcat(cmd," has virus!' &");
		prev_size = curr_size;
		system(cmd);
		free(buffer);
	} else {
		/* go back to sleep */
		sleep(1);
	}

 }
   out:
   if(buffer)
	free(buffer);
   if(file_pointer)
	fclose(file_pointer);
   exit(EXIT_SUCCESS);
}
