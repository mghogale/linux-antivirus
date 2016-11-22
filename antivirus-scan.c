#define _XOPEN_SOURCE 500
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

static int trace_files(const char *fpath, const struct stat *sb, int tflag, struct FTW *ftwbuf)
{
	printf("Scanning file %s ...", fpath);
	int fd = open(fpath, O_RDONLY);
	if(fd==-1)
		printf("Error in opening\n");
	else
		printf("File scanned...\n");

    	return 0;          
}

int main(int argc, char *argv[])
{
	int flags = 0;

   	if (argc > 2 && strchr(argv[2], 'd') != NULL)
        	flags |= FTW_DEPTH;

    	if (argc > 2 && strchr(argv[2], 'p') != NULL)
        	flags |= FTW_PHYS;   

   	if (nftw((argc < 2) ? "." : argv[1], trace_files, 20, flags)== -1) 
	{	        
		perror("nftw");
	        exit(EXIT_FAILURE);
	}

    	exit(EXIT_SUCCESS);
}

