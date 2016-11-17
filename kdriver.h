#ifndef KDRIVER_H
#define KDRIVER_H

#include <linux/fs.h>      /* filp_open */
#include <linux/module.h>  /* needed by all kernel modules */
#include <linux/kernel.h>  /* needed for loglevels (KERN_WARNING, KERN_EMERG, KERN_INFO, etc.) */
#include <linux/init.h>    /* needed for __init and __exit macros. */
#include <linux/unistd.h>  /* sys_call_table __NR_* system call function indices */
#include <linux/fs.h>      /* filp_open */
#include <linux/slab.h>    /* kmalloc */
#include <asm/paravirt.h>  /* write_cr0 */
#include <asm/uaccess.h>   /* needed for kmalloc and kfree and et.el*/
#include <linux/crypto.h>  /* needed for crypto initialization, allocation and hashing methods*/
#include <linux/scatterlist.h> /* needed for struct scatterlist*/

#define VIRUS_DB_FILE "/root/virus.db"
#define WHITELIST_DB_FILE "/root/whitelist.db"

#define TMP_TEST_PATH "/home/"
#define TMP_SIZE 10
#define BUFFER_SIZE 4096
#define DEF_SIZE 10
#define SHA1_LENGTH 20
#define VIRUS_FILE_EXTENSION ".virus"

extern struct white_list_data *head;

/* holds the in-memory crypto data structure*/
struct crypto_data {
struct scatterlist sg;
struct crypto_hash *tfm;
struct hash_desc desc;
};

/* holds the in-memory file data structure */
struct file_data {
int size;
int offset;
int fsize;
int file_exhausted;
struct crypto_data c_data;
char buff[1];
};

/* stores the virus definitions in-memory, maintained as gloabl ds */
struct virus_def {
int size;
int offset;
char buff[1];
};

struct white_list_data{
	char data[41];
	struct white_list_data *next;
};


/* returns true if path is a directory */
extern int is_this_directory(char *path);
/* loads virus definitions from virus db*/
extern struct virus_def *read_virus_def(void);
/* returns kernel_path_name from user path*/
extern char *get_path_name(const char *user_path);
/* returns length of the next signature */
int get_signature_len(struct virus_def *vir_def);
/* returns cumulative index of end of prefix */
int get_prefix_len(struct virus_def *vir_def);
/*scans the given file */
extern int scan(struct file *filp, struct file_data *fdata, struct virus_def *vir_def);
/* first time creation and loading of in memory data strutures */
extern struct file_data *create_file_data_struct(struct file *filp);
/* reloads the file_data in memory when previous buffer is exhausted*/
extern int get_file_data(struct file_data *fdata, struct file *filp);
/* scans the file-content from offset and checks against each virus definition */
extern int scan_black_list(int src_offset, struct file_data *fdata, struct virus_def *vir_def);
/* computes sha1 of the entire file*/
extern char* compute_hash(struct file_data *);
/* checks if a file is white listed*/
extern bool is_white_listed(struct file *, struct file_data *);
/* renames a file name to file name .virus*/
extern bool rename_malicious_file (char *);
#endif
