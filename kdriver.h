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

#define VIRUS_DB_FILE "/tmp/virus.db"

#define TMP_TEST_PATH "/home/"
#define TMP_SIZE 10
#define BUFFER_SIZE 10

struct file_data {
int size;
int offset;
int fsize;
int file_exhausted;
char buff[1];
};

struct virus_def {
int size;
int offset;
char buff[1];
};

extern struct virus_def *read_virus_def(void);
extern struct file_data *create_file_data_struct(struct file *filp);
extern void get_file_data(struct file_data *fdata, struct file *filp);
extern int is_this_directory(char *path);
extern char *get_path_name(const char *user_path);

#endif
