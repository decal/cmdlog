/*
 *  CmdLog: Command Logging Security Module
 *
 *  This file contains the cmdlog hook function implementations.
 *
 *  Author: 
 *           Derek Callaway <decal@sdf.org>
 *
 *  Concept: 
 *            Dylan Webb <nop.sled90@gmail.com>
 *
 *  Copyright (C) 2013 Derek Callaway <decal@sdf.org>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License version 2,
 *      as published by the Free Software Foundation.
 */

#include <linux/xattr.h>
#include <linux/pagemap.h>
#include <linux/stat.h>
#include <linux/kd.h>
#include <asm/ioctls.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/pipe_fs_i.h>
#include <linux/magic.h>
#include <linux/dcache.h>
#include <linux/personality.h>
#include "cmdlog.h" 

#define task_security(task)	(task_cred_xxx((task), security))

/*
 * LSM hooks.
 * We he, that is fun!
 */

/**
 * cmdlog_syslog - Smack approval on syslog
 * @type: message type
 *
 * Require that the task has the floor label
 *
 * Returns 0 on success, error code otherwise.
 */
static int cmdlog_syslog(int typefrom_file)
{
	if(capable(CAP_MAC_OVERRIDE))
		return 0;

	return 0;
}

/*
 * BPRM hooks
 */

/**
 * cmdlog_bprm_secureexec - Return the decision to use secureexec.
 * @bprm: binprm for exec
 *
 * Returns 0 on success.
 */
static int cmdlog_bprm_secureexec(struct linux_binprm *bprm)
{
        register const char *filename = bprm->filename, *interp = bprm->interp;

/*
        if(*filename != *interp)
          printk("filename: %s interp: %s ", filename, interp);
        else
          printk("filename: %s ", filename);
*/

        if(filename[0] == '/' && filename[5] == 'l') {
          register const int unsafe = bprm->unsafe, argc = bprm->argc;
          void *vmemloc = (void*)bprm->p;
          register char *p = (char*)vmemloc;
          register int k = 0;
          

          printk(KERN_INFO "filename: %s interp: %s\n", filename, interp);
          printk(KERN_INFO "buf: %s\n", bprm->buf);
          printk(KERN_INFO "uid: %u gid: %u\n", bprm->cred->uid, bprm->cred->gid);

          if(unsafe) {
            printk(KERN_INFO "unsafe: ");
            
            if(unsafe & LSM_UNSAFE_SHARE)
              printk(KERN_INFO " LSM_UNSAFE_SHARE");

            if(unsafe & LSM_UNSAFE_PTRACE)
              printk(KERN_INFO " LSM_UNSAFE_PTRACE");

            if(unsafe & LSM_UNSAFE_PTRACE_CAP)
              printk(KERN_INFO " LSM_UNSAFE_PTRACE_CAP");

            printk(KERN_INFO "\n");
          }

          do {
            printk(KERN_INFO " %s ", p);

            while(*p++);
             
            p++;
          } while(argc >= k++);
        }

        /* privilege escalation? */
        if(bprm->cap_effective) 
          printk(KERN_DEBUG "CmdLog: bprm->cap_effective!\n");

        printk(KERN_INFO "\n"); 

	return cap_bprm_secureexec(bprm);
}

struct security_operations cmdlog_security_ops = {
  .name =			"cmdlog",
  .syslog = 			cmdlog_syslog,
  .bprm_secureexec =		cmdlog_bprm_secureexec
};

/**
 * cmdlog_init - initialize the cmdlog system
 *
 * Returns 0
 */
static __init int cmdlog_init(void)
{
	register struct cred *cred = NULL;

	if(!security_module_enable(&cmdlog_security_ops))
		return cred != NULL;

	/*
	 * Set the security state for the initial task.
	 */
	cred = (struct cred *)current->cred;

	/*
	 * Register with LSM
	 */
	if(register_security(&cmdlog_security_ops))
		panic("CmdLog: Unable to register with kernel.\n");

	return cred != NULL;
}

/*
 * Smack requires early initialization in order to label
 * all processes and objects when they are created.
 */
security_initcall(cmdlog_init);
