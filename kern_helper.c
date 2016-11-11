#include <linux/module.h>  /* Needed by all kernel modules */
#include <linux/kernel.h>  /* Needed for loglevels (KERN_WARNING, KERN_EMERG, KERN_INFO, etc.) */
#include <linux/init.h>    /* Needed for __init and __exit macros. */
#include <linux/unistd.h>  /* sys_call_table __NR_* system call function indices */
#include <linux/fs.h>      /* filp_open */
#include <linux/slab.h>    /* kmalloc */
#include <asm/paravirt.h>  /* write_cr0 */
#include <asm/uaccess.h>   /* get_fs, set_fs */

#include "kdriver.h"

/* returns true if this is a directory  */
int is_this_directory(char *path){
  printk("I got the path\n");
  return 0;
}

/* returns the path name from userland path*/
char * get_path_name(const char *user_path){
  int len = 0;
  char *kpath = NULL;
  int err = 0;
  len =  strlen_user(user_path);
  //printk(KERN_INFO "HELPER: user-path-len is %d\n", len);
 
  kpath =  kzalloc(len, GFP_KERNEL);
  if (kpath == NULL){
    printk(KERN_ERR "unable to allocate memory for user path\n");
    goto out;
  }

 err =  copy_from_user(kpath, user_path, len);
 if (err != 0){
   printk(KERN_ERR "error while copying path from user\n");
   kfree(kpath);
   goto out;
 }

 //  printk(KERN_DEBUG "user path is %s\n", kpath);
 out:
  return kpath;
}

/*  */
struct file_data *create_file_data_struct(struct file *filp){
    struct file_data *fdata;
    int fsize = 0, read_size = 0, err = 0;
    mm_segment_t oldfs;

    fsize = filp->f_inode->i_size;    
    /* file is less than the BUFFER_SIZE*/
    if (fsize <= BUFFER_SIZE){
      /* prepare file_data container */
      fdata = kzalloc(sizeof(struct file_data) + fsize + 1, GFP_KERNEL);
      
      if (fdata == NULL){
	printk(KERN_ERR "can not allocate memory for reading the file structure\n");
	goto out;
      }
      fdata -> size = fsize;
      fdata -> offset = 0;
      fdata -> fsize = fsize;
      fdata -> file_exhausted = 1;
      read_size = fsize;
    } else {
      /* prepare file_data container */
      fdata = kzalloc(sizeof(struct file_data) + BUFFER_SIZE + 1, GFP_KERNEL);
      if (fdata == NULL){
	printk(KERN_ERR "can not allocate memory for reading the file structure\n");
	goto out;
      }
      fdata -> size = BUFFER_SIZE;
      fdata -> fsize = fsize;
      fdata -> offset = 0;
      read_size = BUFFER_SIZE;
    }

    oldfs = get_fs();
    set_fs(KERNEL_DS);
    err = vfs_read(filp, fdata->buff, read_size, &filp->f_pos);
    set_fs(oldfs);

    if (err < 0){
      printk(KERN_ERR "error occured while reading from file\n");
      goto out_free;
    }

    if (err < read_size){
      printk(KERN_INFO "file is exhausted\n");
      fdata->file_exhausted = 1;
    }
    
    printk(KERN_INFO "File data read into structure\n");
    return fdata;

out_free:
    kfree(fdata);
    fdata = NULL;

out:
    return fdata;
}

/* reads the virus definitions from db file into in-memory data structures */
struct virus_def *read_virus_def(void){
  struct file *dbfilp;
  struct virus_def *vdef = NULL;
  mm_segment_t oldfs;
  int fsize = 0, err = 0;

  dbfilp =  filp_open(VIRUS_DB_FILE, O_RDONLY, 0);

  if (dbfilp == NULL || IS_ERR(dbfilp)){
    printk(KERN_ERR "cannot open virus definitions\n");
    goto out;
  }
  
  fsize = dbfilp->f_inode->i_size;
  printk("file size is %d\n", fsize);
  vdef = kmalloc(sizeof(struct virus_def) + fsize, GFP_KERNEL);
  
  if (vdef == NULL){
    printk("could not allocate memory for virus definitions");
    goto out;
  }
  vdef->size = fsize;
  vdef->offset = 0;

  oldfs = get_fs();
  set_fs(KERNEL_DS);
  err = vfs_read(dbfilp, vdef->buff, fsize, &dbfilp->f_pos);
  set_fs(oldfs);

  if (err < 0){
    printk(KERN_ERR "VDEF: error occurred when reading from virus definitions\n");    
    /* freeing the virus definitions buffer*/
    goto out_free;
  }

 return vdef;

 out_free:
  kfree(vdef);
  vdef = NULL;
  filp_close(dbfilp, NULL);

 out:
  return vdef;
}

/* this will only be called when file exceeds pe-defined BUFFER_SIZE */
void get_file_data(struct file_data *fdata, struct file *filp){
  struct file_data *vdef = NULL;
  mm_segment_t oldfs;
  int fsize = 0, read_size = 0, err = 0;

  fsize = filp->f_inode->i_size;
  printk("file size is %d\n", fsize);

  if (fsize <= BUFFER_SIZE){
      /* prepare file_data container */
      
      if (fdata == NULL){
	printk(KERN_ERR "can not allocate memory for reading the file structure\n");
	goto out;
      }
      /* reading next BUFFER_SIZE bytes from file */
      fdata -> size = fsize;
      fdata -> offset = 0;
      fdata -> fsize = fsize;
      fdata -> file_exhausted = 1;
      memset(fdata->buff, BUFFER_SIZE, 0);
      read_size = fsize;
    } else {
      /* file is exhausted here */
      fdata -> size = BUFFER_SIZE;
      fdata -> fsize = fsize;
      fdata -> offset = 0;
      memset(fdata->buff, BUFFER_SIZE, 0);
      read_size = BUFFER_SIZE;
    }

    oldfs = get_fs();
    set_fs(KERNEL_DS);
    err = vfs_read(filp, vdef->buff, read_size, &filp->f_pos);
    set_fs(oldfs);

    if (err < 0){
      printk(KERN_ERR "error occured while reading from file\n");
      goto out_free;
    }

    if (err < read_size){
      printk(KERN_INFO "file is exhausted\n");
      fdata->file_exhausted = 1;
    }
    
    printk(KERN_INFO "File data read into structure\n");
    return;

out_free:
    kfree(fdata);
    fdata = NULL;
out:
    return;
}
