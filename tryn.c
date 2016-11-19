#define _XOPEN_SOURCE 500
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

static int
trace_files(const char *fpath, const struct stat *sb, int tflag, struct FTW *ftwbuf)
{
	//printf("\nin function");
	char pathname[100];
	
	FILE *fp = fopen("op1.txt", "a");
	if (fp == NULL)
	{
    		printf("Error in opening the pathname file!\n");
    		exit(1);
	}

	strcpy(pathname, fpath);
	fgets(pathname, sizeof(pathname), fp);
	fprintf(fp,"%s", pathname);
	fprintf(fp, "\n");
	fclose(fp);

    	return 0;          
}

int main(int argc, char *argv[])
{
	int flags = 0;

	if( access("op1.txt", F_OK ) != -1 ) 
	{
   		remove("op1.txt");
	}

   	if (argc > 2 && strchr(argv[2], 'd') != NULL)
        	flags |= FTW_DEPTH;
    	if (argc > 2 && strchr(argv[2], 'p') != NULL)
        	flags |= FTW_PHYS;   

   	if (nftw((argc < 2) ? "." : argv[1], trace_files, 20, flags)== -1) 
	{
	        perror("nftw");
	        exit(EXIT_FAILURE);
	}

	//printf("Reading from op1");
	
   	FILE* file = fopen("op1.txt", "r");
    	char line[256];

    	while (fgets(line, sizeof(line), file)) 
	{
        	printf("%s", line); 
		//open system call
	}
    
    	fclose(file);

    	exit(EXIT_SUCCESS);
}
