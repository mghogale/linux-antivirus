#include <linux/module.h>	/* Needed by all kernel modules */
#include <linux/kernel.h>	/* Needed for loglevels (KERN_WARNING, KERN_EMERG, KERN_INFO, etc.) */
#include <linux/init.h>		/* Needed for __init and __exit macros. */
#include <linux/unistd.h>	/* sys_call_table __NR_* system call function indices */
#include <linux/fs.h>		/* filp_open */
#include <linux/slab.h>		/* kmalloc */
#include <asm/paravirt.h>	/* write_cr0 */
#include <asm/uaccess.h>	/* get_fs, set_fs */
#include "kdriver.h"

/* initializes data needed for crytpo API*/
void initialize_crypto_data(struct file_data *fdata)
{
	fdata->c_data.tfm = crypto_alloc_hash("sha1", 0, CRYPTO_ALG_ASYNC);
	fdata->c_data.desc.tfm = fdata->c_data.tfm;
	fdata->c_data.desc.flags = 0;
	crypto_hash_init(&(fdata->c_data.desc));
}

/* computes sha1 of the entire file*/
char *compute_hash(struct file_data *fdata)
{
	char output[SHA1_LENGTH];
	int i, len;
	char *sha1 = NULL;
	char *sha1_byte = NULL;

	if (fdata->buff) {
		len = fdata->bytes_read;

		memset(output, 0x00, SHA1_LENGTH);
		sg_init_one(&(fdata->c_data.sg), fdata->buff, len);

		crypto_hash_update(&(fdata->c_data.desc), &(fdata->c_data.sg),
				   len);
		if (fdata->file_exhausted) {
			crypto_hash_final(&(fdata->c_data.desc), output);
			sha1 = (char *)kzalloc(sizeof(char) * 41, GFP_KERNEL);
			if (sha1 == NULL) {
				printk(KERN_ERR
				       "\nCould not allocate memory for reading the file structure");
				goto out;
			}
			sha1_byte =
			    (char *)kzalloc(sizeof(char) * 3, GFP_KERNEL);
			if (sha1_byte == NULL) {
				printk(KERN_ERR
				       "\nCould not allocate memory for reading the file structure");
				goto out;
			} else {
				for (i = 0; i < 20; i++) {
					sprintf(sha1_byte, "%02x",
						output[i] & 0xff);
					sha1_byte[2] = '\0';
					strcat(sha1, sha1_byte);
				}
				sha1[40] = '\0';
				crypto_free_hash(fdata->c_data.tfm);
			}
		}
	} else {
		printk("\nfdata->buff is null");
	}

 out:
	if (sha1_byte)
		kfree(sha1_byte);
	return sha1;
}

bool is_white_listed(struct file * filp, struct file_data * fdata)
{
	char *sha1 = NULL;
	struct white_list_data *iterator = head;
	bool ret = false;
	int err = 0;
	/* white-list logic starts */
	/* computing sha1 of the file */
	initialize_crypto_data(fdata);
	while (fdata->file_exhausted != 1) {
		sha1 = compute_hash(fdata);
		err = get_file_data(fdata, filp);
		if (err < 0) {
			printk
			    ("\nSCAN: error occured while reloading the buffer");
			goto out;
		}
	}
	if (fdata->file_exhausted == 1) {
		sha1 = compute_hash(fdata);
		printk(KERN_INFO "\ncalculating SHA1 for file");
		printk("\nSha1 : %s", sha1);
	}

	if (sha1 == NULL) {
		printk("\nCouldn't compute sha1 of file");
		goto out;
	}

	/* white-list comparison logic to be written here */

	while (iterator != NULL) {
		if (strncmp(sha1, iterator->data, 40) == 0) {
			ret = true;
			break;
		}
		iterator = iterator->next;
	}

 out:
	if (sha1)
		kfree(sha1);
	return ret;
}

/* scan the file */
int scan(struct file *filp, struct file_data *fdata, struct virus_def *vir_def)
{
	int start_offset = 0, end_offset = DEF_SIZE;
	int err = 0;

	/* scan for black-list */
	while (end_offset <= fdata->size || fdata->file_exhausted != 1) {
		if (end_offset > fdata->size) {
			/* reload current buffer */
			err = get_file_data(fdata, filp);
			/* if error while reloading the buffer */
			if (err < 0) {
				printk
				    ("\nSCAN: error occured while reloading the buffer");
				goto out;
			}
			end_offset = DEF_SIZE;
			start_offset = 0;
		}
		/* we have data and everything, lets scan */
		err = scan_black_list(start_offset, fdata, vir_def);
		if (err < 0) {
			printk(KERN_ERR
			       "\nSCAN: error occured while scanning through black-list");
			goto out;
		}
		if (err > 0) {
			printk(KERN_INFO "\nfound a malicious file");
			goto out;
		}
		start_offset++;
		end_offset++;
	}
 out:
	return err;
}

/* returns the path name from userland path*/
char *get_path_name(const char *user_path)
{
	int len = 0;
	char *kpath = NULL;
	int err = 0;
	len = strlen_user(user_path);

	kpath = kzalloc(len, GFP_KERNEL);
	if (kpath == NULL) {
		printk(KERN_ERR "\nUnable to allocate memory for user path");
		goto out;
	}

	err = copy_from_user(kpath, user_path, len);
	if (err != 0) {
		printk(KERN_ERR "\nError while copying path from user");
		kfree(kpath);
		goto out;
	}
 out:
	return kpath;
}

bool rename_malicious_file(char *old_path)
{
	int len = 0, err = 0;
	char *new_path = NULL;
	bool ret = true;
	struct inode *old_path_inode = NULL, *new_path_inode =
	    NULL, *old_file_inode = NULL;
	struct file *old_file = NULL, *new_file = NULL, *dummyfp = NULL;
	mm_segment_t oldfs;

	len = strlen(old_path) + strlen(VIRUS_FILE_EXTENSION) + 1;

	new_path = kzalloc(len, GFP_KERNEL);
	if (new_path == NULL) {
		printk(KERN_ERR "\nSCAN_MALICIOUS:Unable to allocate memory");
		ret = false;
		goto out;
	}

	strcat(new_path, old_path);
	strcat(new_path, VIRUS_FILE_EXTENSION);
	new_path[len] = '\0';

	old_file = filp_open(old_path, O_RDONLY, 0);
	if (!old_file || IS_ERR(old_file)) {
		printk("\nSCAN_MALICIOUS:Can't open file to be scanned");
		ret = false;
		goto out;
	}
	new_file = filp_open(new_path, O_WRONLY | O_CREAT, 0644);
	if (!new_file || IS_ERR(new_file)) {
		printk("\nSCAN_MALICIOUS:Can't open file to be scanned");
		ret = false;
		goto out;
	}

	old_path_inode = d_inode(file_dentry(old_file)->d_parent);
	new_path_inode = d_inode(file_dentry(new_file)->d_parent);
	vfs_rename(old_path_inode, file_dentry(old_file), new_path_inode,
		   file_dentry(new_file), NULL, 0);

	/* Modifying the permissions of malicious file to be 0 */
	old_file_inode = file_inode(old_file);
	old_file_inode->i_mode = old_file_inode->i_mode & 0000;

	/* writing renamed file to dummy file which will be read from user space to display pop up */
	dummyfp = filp_open(DUMMY_FILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
	if (dummyfp == NULL || IS_ERR(dummyfp)) {
		printk(KERN_ERR "\nSCAN_MALICIOUS:cannot open dummy file");
		goto out;
	}

	printk("\nSCAN_MALICIOUS:Dummy file opened");
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = vfs_write(dummyfp, old_path, strlen(old_path), &dummyfp->f_pos);
	set_fs(oldfs);

	if (err < 0) {
		printk("\nSCAN_MALICIOUS:error %d while writing to tmp file",
		       err);
	}

 out:
	if (dummyfp && !IS_ERR(dummyfp))
		filp_close(dummyfp, NULL);
	if (new_path)
		kfree(new_path);
	if (old_file && !IS_ERR(old_file))
		filp_close(old_file, NULL);
	if (new_file && !IS_ERR(new_file))
		filp_close(new_file, NULL);
	return ret;
}

/* scans through the black-list searching for match from src_offser of file_data buffer */
int
scan_black_list(int src_offset, struct file_data *fdata,
		struct virus_def *vir_def)
{

	char *virus_name = NULL;
	int record_end = DEF_SIZE, vir_def_offset = 0;
	/* default virus definition size, compare result */
	int def_size = 0, cmp_res = 0;
	/* cumulative signature size, prefix length size and no of bytes to compare */
	int sig_size = 0, pref_len = 0, cmp_len = 0;
	int err = 0;

	if (src_offset < 0) {
		printk(KERN_ERR "\nSCAN_BLACKLIST:invalid source offset");
		return -1;
	}
	def_size = vir_def->size;

	/* while we do not exceed virus definition size, go through db file record by record */
	while (record_end <= vir_def->size) {
		/*end of file, not enough data, not a virus */
		if (src_offset + DEF_SIZE >= fdata->size)
			return 0;

		sig_size = get_signature_len(vir_def);
		pref_len = get_prefix_len(vir_def);

		/* total actual size of the signature only */
		cmp_len = sig_size - pref_len - 1;

		/* perform the actual comparison */
		cmp_res =
		    strncmp(&fdata->buff[src_offset], &vir_def->buff[pref_len],
			    cmp_len);

		if (cmp_res == 0) {
			printk(KERN_INFO
			       "\nSCAN_BLACKLIST:virus found in file");
			/* should probably return the number associated with the malicious signature */
			err = 100;
			kfree(virus_name);
			goto out;
		}

		/* lets point to start of next record */
		record_end = sig_size + 1;
		vir_def_offset = sig_size + 1;
		vir_def->offset = sig_size;
	}

 out:
	vir_def->offset = 0;
	return err;
}

/* we'll need to do this manually, strsep modifies the content of original buffer */
int get_signature_len(struct virus_def *vir_def)
{
	int offset = vir_def->offset;
	/*till we get end of line or buffer is finished */
	while (offset <= vir_def->size && vir_def->buff[offset++] != '\n') ;
	return offset;
}

/* we'll need to do this manually, strsep modifies the content of original buffer */
int get_prefix_len(struct virus_def *vir_def)
{
	int offset = vir_def->offset;
	/*till we get , or buffer is finished */
	while (offset <= vir_def->size && vir_def->buff[offset++] != ',') ;
	return offset;
}

/* created the file_data structure and reads BUF_SIZE bytes into the buffer  */
struct file_data *create_file_data_struct(struct file *filp)
{
	struct file_data *fdata;
	int fsize = 0, read_size = 0, err = 0;
	mm_segment_t oldfs;

	fsize = filp->f_inode->i_size;
	/* file is less than the BUFFER_SIZE */
	if (fsize <= BUFFER_SIZE) {
		/* prepare file_data container */
		fdata =
		    kzalloc(sizeof(struct file_data) + fsize + 1, GFP_KERNEL);

		if (fdata == NULL) {
			printk(KERN_ERR
			       "\nCannot allocate memory for reading the file structure");
			goto out;
		}
		fdata->size = fsize;
		fdata->offset = 0;
		fdata->fsize = fsize;
		fdata->file_exhausted = 1;
		read_size = fsize;
	} else {
		/* prepare file_data container */
		fdata =
		    kzalloc(sizeof(struct file_data) + BUFFER_SIZE + 1,
			    GFP_KERNEL);
		if (fdata == NULL) {
			printk(KERN_ERR
			       "\nCannot allocate memory for reading the file structure");
			goto out;
		}
		fdata->size = BUFFER_SIZE;
		fdata->fsize = fsize;
		fdata->offset = 0;
		read_size = BUFFER_SIZE;
	}

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = vfs_read(filp, fdata->buff, read_size, &filp->f_pos);
	set_fs(oldfs);

	fdata->bytes_read = err;

	if (err < 0) {
		printk(KERN_ERR "\nError occured while reading from file");
		goto out_free;
	}

	if (err < read_size)
		fdata->file_exhausted = 1;

	return fdata;

 out_free:
	kfree(fdata);
	fdata = NULL;
 out:
	return fdata;
}

/* reads the virus definitions from db file into in-memory data structures */
struct virus_def *read_virus_def(void)
{
	struct file *dbfilp;
	struct virus_def *vir_def = NULL;
	mm_segment_t oldfs;
	int fsize = 0, err = 0;

	dbfilp = filp_open(VIRUS_DB_FILE, O_RDONLY, 0);

	if (dbfilp == NULL || IS_ERR(dbfilp)) {
		printk(KERN_ERR "\nCannot open virus definitions");
		goto out;
	}

	fsize = dbfilp->f_inode->i_size;
	vir_def = kmalloc(sizeof(struct virus_def) + fsize, GFP_KERNEL);

	if (vir_def == NULL) {
		printk
		    ("\nREAD_VIRUSDEF:could not allocate memory for virus definitions");
		goto out;
	}

	vir_def->size = fsize;
	vir_def->offset = 0;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = vfs_read(dbfilp, vir_def->buff, fsize, &dbfilp->f_pos);
	set_fs(oldfs);

	if (err < 0) {
		printk(KERN_ERR
		       "\nREAD_VIRUSDEF: error occurred when reading from virus definitions");
		/* freeing the virus definitions buffer */
		goto out_free;
	}

	printk(KERN_INFO "\nvirus definitions loaded");
	return vir_def;
 out_free:
	kfree(vir_def);
	vir_def = NULL;

	if (dbfilp && !IS_ERR(dbfilp))
		filp_close(dbfilp, NULL);
 out:
	return vir_def;
}

/* this will only be called when file exceeds pre-defined BUFFER_SIZE */
int get_file_data(struct file_data *fdata, struct file *filp)
{
	mm_segment_t oldfs;
	int read_size = 0, err = 0, i = 0;

	if (fdata == NULL) {
		printk(KERN_ERR
		       "\nCannot allocate memory for reading the file structure");
		err = -1;
		goto out;
	}

	/* file is not exhausted here */
	fdata->size = BUFFER_SIZE;
	fdata->offset = 0;

	for (i = 0; i < BUFFER_SIZE; i++)
		fdata->buff[i] = '\0';

	read_size = BUFFER_SIZE;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = vfs_read(filp, fdata->buff, read_size, &filp->f_pos);
	set_fs(oldfs);

	fdata->bytes_read = err;

	if (err < 0) {
		printk(KERN_ERR "\nError occured while reading from file");
		err = -1;
		goto out_free;
	}

	if (err < read_size) {
		/* file exhausted */
		fdata->file_exhausted = 1;
		fdata->size = err;
	}

	return err;

 out_free:
	kfree(fdata);
	fdata = NULL;
 out:
	return err;
}
