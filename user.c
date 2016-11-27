#define _XOPEN_SOURCE 500
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
int counter = 0;

/* scans each file by calling open */
static int trace_files(const char *fpath, const struct stat *sb, int tflag, struct FTW *ftwbuf)
{
	int fd = open(fpath, O_RDONLY);
	printf("\nScanning '%s'...",fpath);
	if(fd==-1)
		return 0;

    	return 0;          
}

/* checks if files have been renamed to .virus */
static int check_virus(const char *fpath, const struct stat *sb, int tflag, struct FTW *ftwbuf)
{
	char *pattern = ".virus";
	char *new_string = NULL;
	
	if(strstr(fpath, pattern) != NULL) 
	{
		new_string = malloc(strlen(fpath)-6);
		memcpy(new_string, fpath, strlen(fpath)-6);
    		new_string[strlen(fpath)-6] = '\0';
		printf("%s\n", new_string);
		++counter;
		free(new_string);	 
	}

    	return 0;          
}

/* main program for scanning files */
int main(int argc, char *argv[])
{
	int flags = 0;

   	if (argc > 2 && strchr(argv[2], 'd') != NULL)
        	flags |= FTW_DEPTH;

    	if (argc > 2 && strchr(argv[2], 'p') != NULL)
        	flags |= FTW_PHYS;   
	printf("\n*********************************************\n");
	printf("\nScanning path %s", argv[1]);

   	if (nftw((argc < 2) ? "." : argv[1], trace_files, 20, flags)== -1) 
	{	        
		perror("nftw");
	}
	
	printf("\n\n*********************************************\n");
	printf("\nAfter antivirus-scan:\n");
	nftw((argc < 2) ? "." : argv[1], check_virus, 20, flags);

	if(counter != 0)
		printf("\nThe above files are malicious so they have been renamed with a .virus extension\n\n");
	else
		printf("\nNo virus found!\n");

    	exit(EXIT_SUCCESS);
}
