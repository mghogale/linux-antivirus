#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#define DUMMY_PATH "/root/.log"

/* This is a hack used for displaying graphical pop-up.
   It continously checks the status of file size and if changed then 
   it treats it as kernel found a virus and wrote to the file.
   It then displays the pop-up.
   Really hacky fix but it works*/

int
main (int argc, char *argv[])
{
  struct stat sb;
  long long curr_size = 0;
  FILE *file_pointer = NULL;
  char buffer[4096], cmd[4150];
  
if (stat (DUMMY_PATH, &sb) == -1)
    {
      perror ("GRAPHICAL POPUP: Could not stat");
      exit (EXIT_FAILURE);
    }

  while (1)
    {
      if (stat (DUMMY_PATH, &sb) == -1)
	{
	  perror ("GRAPHICAL POPUP: Could not stat");
	  exit (EXIT_SUCCESS);
	}
      curr_size = (long long) sb.st_size;
      if (curr_size > 0)
	{
	  file_pointer = fopen (DUMMY_PATH, "r");
	  if (file_pointer == NULL)
	    {
	      printf ("\nCannot open dummy file");
	      goto out;
	    }

	  while (fgets (buffer, 4096, (FILE *) file_pointer))
	    {
	      cmd[0] = '\0';
	      strcpy (cmd, "notify-send -i \"error\" \"");
	      strcat (cmd, buffer);
	      strcat (cmd, " has virus!\"");
	      system (cmd);
	    }
	  if (file_pointer)
	    fclose (file_pointer);
	  /* cleaning up the file */
	  file_pointer = fopen (DUMMY_PATH, "w");
	  if (file_pointer == NULL)
	    {
	      printf ("\nCannot open dummy file");
	      goto out;
	    }
	  if (file_pointer)
	    fclose (file_pointer);
	}
      else
	{
	  /* go back to sleep */
	  sleep (1);
	}
    }
out:
  if (file_pointer)
    fclose (file_pointer);
  exit (EXIT_SUCCESS);
}
