#include <linux/module.h>  /* Needed by all kernel modules */
#include <linux/kernel.h>  /* Needed for loglevels (KERN_WARNING, KERN_EMERG, KERN_INFO, etc.) */
#include <linux/init.h>    /* Needed for __init and __exit macros. */
#include <linux/unistd.h>  /* sys_call_table __NR_* system call function indices */
#include <linux/fs.h>      /* filp_open */
#include <linux/slab.h>    /* kmalloc */
#include <asm/paravirt.h> /* write_cr0 */
#include <asm/uaccess.h>  /* get_fs, set_fs */
#include <linux/errno.h>

#include "kdriver.h"

#define PROC_V    "/proc/version"
#define BOOT_PATH "/boot/System.map-"
#define MAX_VERSION_LEN   256

struct virus_def *vdef;

unsigned long *syscall_table = NULL;
asmlinkage int (*original_write) (unsigned int, const char __user *, size_t);
asmlinkage long (*original_read) (unsigned int, char __user *, size_t);
asmlinkage long (*original_open) (const char __user *, int, umode_t);

/* This method retreives the system-call table address in memory */
static int get_system_call_table(char *kern_ver)
{
	char system_map_entry[MAX_VERSION_LEN];
	int i = 0;
	
	    /*
	     * Holds the /boot/System.map-<version> file name while it's been built
	     */ 
	char *filename;
	
	    /*
	     * Length of the System.map filename, terminating NULL included
	     */ 
	 size_t filename_length = strlen(kern_ver) + strlen(BOOT_PATH) + 1;
	
	    /*
	     * This will points to /boot/System.map-<version> file
	     */ 
	struct file *f = NULL;
	mm_segment_t oldfs;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	printk(KERN_EMERG "Kernel version: %s", kern_ver);
	filename = kmalloc(filename_length, GFP_KERNEL);

	if (filename == NULL) {
		printk(KERN_EMERG
			"kmalloc failed on System.map-<version> filename allocation");
		return -1;
	}
	 
	    /*
	     * Zero out memory to be safe
	     */ 
	    memset(filename, 0, filename_length);
	 
	    /*
	     * Construct our /boot/System.map-<version> file name
	     */ 
	    strncpy(filename, BOOT_PATH, strlen(BOOT_PATH));
	    strncat(filename, kern_ver, strlen(kern_ver));
	 
	    /*
	     * Open the System.map file for reading
	     */ 
	    f = filp_open(filename, O_RDONLY, 0);
	if (IS_ERR(f) || (f == NULL)) {
		printk(KERN_EMERG
			"Error opening System.map-<version> file: %s\n", filename);
		return -1;
	}
	 memset(system_map_entry, 0, MAX_VERSION_LEN);
	 
	    /*
	     * Read one byte at a time from the file until we either max out
	     * out our buffer or read an entire line.
	     */ 
	    while (vfs_read(f, system_map_entry + i, 1, &f->f_pos) == 1) {
		
		    /*
		     * If we've read an entire line or maxed out our buffer,
		     * check to see if we've just read the sys_call_table entry.
		     */ 
		    if (system_map_entry[i] == '\n' || i == MAX_VERSION_LEN) {
			
			    // Reset the "column"/"character" counter for the row
			    i = 0;
			 if (strstr(system_map_entry, "sys_call_table") !=
			       NULL) {
				char *sys_string;
				char *system_map_entry_ptr = system_map_entry;
				 sys_string =
				    kmalloc(MAX_VERSION_LEN, GFP_KERNEL);
				if (sys_string == NULL) {
					filp_close(f, 0);
					set_fs(oldfs);
					kfree(filename);
					 return -1;
				}
				 memset(sys_string, 0, MAX_VERSION_LEN);
				
				    /* copy path upto max_len */ 
				    strncpy(sys_string,
					    strsep(&system_map_entry_ptr, " "),
					    MAX_VERSION_LEN);
				
				    /* value is written in hex format */ 
				    kstrtoul(sys_string, 16, &syscall_table);
				printk(KERN_EMERG "syscall_table retrieved\n");
				 kfree(sys_string);
				break;
			}
			    memset(system_map_entry, 0, MAX_VERSION_LEN);
			continue;
		}
		i++;
	}
	filp_close(f, 0);
	set_fs(oldfs);
	kfree(filename);
	return 0;
}


/*
 * We have to pass in a pointer to a buffer to store the parsed
 * version information in. If we declare a pointer to the
 * parsed version info on the stack of this function, the
 * pointer will disappear when the function ends and the
 * stack frame is removed.
 */
char *acquire_kernel_version(char *buf)
{
	struct file *proc_version;
	char *kernel_version;
	
	    /*
	     * We use this to store the userspace perspective of the filesystem
	     * so we can switch back to it after we are done reading the file
	     * into kernel memory
	     */ 
	    mm_segment_t oldfs;
	
	    /*
	     * Standard trick for reading a file into kernel space
	     * This is very bad practice. We're only doing it here because
	     * we're malicious and don't give a damn about best practices.
	     */ 
	    oldfs = get_fs();
	set_fs(KERNEL_DS);
	
	    /*
	     * Open the version file in the /proc virtual filesystem
	     */ 
	    proc_version = filp_open(PROC_V, O_RDONLY, 0);
	if (IS_ERR(proc_version) || (proc_version == NULL)) {
	       return NULL;
	}
	    /*
	     * Zero out memory just to be safe
	     */ 
	    memset(buf, 0, MAX_VERSION_LEN);
	    /*
	     * Read version info from /proc virtual filesystem
	     */ 
	    vfs_read(proc_version, buf, MAX_VERSION_LEN,
		     &(proc_version->f_pos));
	
	    /*
	     * Extract the third field from the full version string
	     */ 
	kernel_version = strsep(&buf, " ");
	kernel_version = strsep(&buf, " ");
	kernel_version = strsep(&buf, " ");
	filp_close(proc_version, 0);
	    /*
	     * Switch filesystem context back to user space mode
	     */ 
	    set_fs(oldfs);
	return kernel_version;
}

asmlinkage int new_write(unsigned int x, const char __user * y, size_t size)
{
	printk(KERN_EMERG "[+] write() hooked.\n");
	return original_write(x, y, size);
}

asmlinkage long new_open(const char __user * path, int flags, umode_t mode)
{
	char *kpath;
	struct file *filp;
	struct file_data *fdata;
	long err = 0;
	
	//printk(KERN_INFO "open hooked");
	kpath = get_path_name(path);
	if (kpath == NULL) {
		printk(KERN_ERR "KDRIVER: could not get path from user\n");
		err = -ENOMEM;
		goto out;
	}
	
	    /* lower two checks are for test purpose only */ 
	
	if (strncmp(kpath, "/home", 5) != 0)
		goto out;
	
	filp = filp_open(kpath, O_RDONLY, 0);
	if (filp == NULL || IS_ERR(filp)) {
		printk(KERN_ERR "cannot open virus definitions\n");
		goto out;
	}
	if (vdef == NULL) {
	       vdef = read_virus_def();
	       if (vdef == NULL)
	       goto out_close;
	}

	//printk(KERN_INFO "VDEF: data read is %s\n", vdef->buff);
	fdata = create_file_data_struct(filp);
	if (fdata == NULL) {
		printk(KERN_ERR
			"error occured while reading from file to scan\n");
		goto out_vdef;
	}
	printk("FDATA: file exhausted %d\n", fdata->file_exhausted);
	err = scan(filp, fdata, vdef);
	if (err > 0){
	  printk("file contains virus pattern %ld\n", err);
	}
	
	kfree(fdata);
	fdata = NULL;
 out_vdef:
	kfree(vdef);
	vdef = NULL;
 out_close:
	filp_close(filp, NULL);
 out:	
	kfree(kpath);
	kpath = NULL;
	return original_open(path, flags, mode);
}

asmlinkage long new_read(unsigned int fd, char __user * path_name,
			    size_t size)
{
	printk(KERN_EMERG "[+] read() hooked\n");
	return original_read(fd, path_name, size);
}

static int __init on_init(void)
{
	char *kernel_version = kmalloc(MAX_VERSION_LEN, GFP_KERNEL);
	printk(KERN_WARNING "Loading anti-virus!\n");
	get_system_call_table(acquire_kernel_version(kernel_version));
	printk(KERN_EMERG "syscall table address: %p\n", syscall_table);
	printk(KERN_EMERG "sizeof(unsigned long *): %zx\n", sizeof(unsigned long *));
	printk(KERN_EMERG "sizeof(sys_call_table) : %zx\n", sizeof(syscall_table));
	if (syscall_table != NULL) {
		write_cr0(read_cr0() & (~0x10000));
		original_write = (void *)syscall_table[__NR_write];
		original_read = (void *)syscall_table[__NR_read];
		original_open = (void *)syscall_table[__NR_open];
	         //syscall_table[__NR_write] = (unsigned long)&new_write;
                 //syscall_table[__NR_read] = (unsigned long)&new_read;
		syscall_table[__NR_open] = (unsigned long) &new_open;
		write_cr0(read_cr0() | 0x10000);
		printk(KERN_EMERG "[+] onload: sys_call_table hooked\n");
		vdef = read_virus_def();
	} else {
		printk(KERN_EMERG "[-] onload: syscall_table is NULL\n");
	}
	kfree(kernel_version);
	
	    /*
	     * A non 0 return means init_module failed; module can't be loaded.
	     */ 
	    return 0;
}

static void __exit on_exit(void)
{
	if (syscall_table != NULL) {
		
		    /* we are setting the 16th bit of the control register, this lets us write memory area */
		    write_cr0(read_cr0() & (~0x10000));
	       
		    /* un-hook the system calls that were hooked earlier */ 
		    //syscall_table[__NR_write] = (unsigned long)original_write;
		    //syscall_table[__NR_read] = (unsigned long)original_read;
		    syscall_table[__NR_open] = (unsigned long)original_open;
		
		    /* mark the area again as read only */
		    write_cr0(read_cr0() | 0x10000);
		printk(KERN_EMERG "[+] on_exit: sys_call_table unhooked\n");
		kfree(vdef);
	} else {
		printk(KERN_EMERG "[-] on_exit: syscall_table is NULL\n");
	 }
	 printk(KERN_INFO "oops! you are no longer secured!\n");
 }

MODULE_LICENSE("GPL");
module_init(on_init);
module_exit(on_exit);
