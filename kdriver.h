#ifndef KDRIVER_H
#define KDRIVER_H

#include <linux/fs.h>      /* filp_open */
#include <linux/module.h>  /* Needed by all kernel modules */
#include <linux/kernel.h>  /* Needed for loglevels (KERN_WARNING, KERN_EMERG, KERN_INFO, etc.) */
#include <linux/init.h>    /* Needed for __init and __exit macros. */
#include <linux/unistd.h>  /* sys_call_table __NR_* system call function indices */
#include <linux/fs.h>      /* filp_open */
#include <linux/slab.h>    /* kmalloc */
#include <asm/paravirt.h>  /* write_cr0 */
#include <asm/uaccess.h>   /* needed for kmalloc and kfree and et.el*/

#define VIRUS_DB_FILE "/root/virus.db"

#define TMP_TEST_PATH "/home/"
#define TMP_SIZE 10
#define BUFFER_SIZE 4096
#define DEF_SIZE 10

/* holds the in-memory file data structure */
struct file_data {
int size;
int offset;
int fsize;
int file_exhausted;
char buff[1];
};

/* stores the virus definitions in-memory, maintained as gloabl ds */
struct virus_def {
int size;
int offset;
char buff[1];
};

/* returns true if path is a directory */
extern int is_this_directory(char *path);
/* loads virus definitions from virus db*/
extern struct virus_def *read_virus_def(void);
/* returns kernel_path_name from user path*/
extern char *get_path_name(const char *user_path);
/*scans the given file */
extern int scan(struct file *filp, struct file_data *fdata, struct virus_def *vir_def);
/* first time creation and loading of in memory data strutures */
extern struct file_data *create_file_data_struct(struct file *filp);
/* reloads the file_data in memory when previous buffer is exhausted*/
extern int get_file_data(struct file_data *fdata, struct file *filp);
/* scans the file-content from offset and checks against each virus definition */
extern int scan_black_list(int src_offset, struct file_data *fdata, struct virus_def *vir_def);

#endif
