// SUSFS adapter for backslashxx/KernelSU (Nanairo edition).
//
// fs/susfs.c and the rest of this kernel tree were written against FinaSU's SUSFS glue
// (KernelSU/kernel/extension/susfs.c in the FinaSU edition), which exposes su-compat and
// init-rc hooks through fs/exec.c, fs/stat.c and fs/read_write.c call sites gated by
// CONFIG_KSU_HOOK_SUSFS_INLINE. backslashxx never built that hook backend: it hooks sucompat,
// faccessat and stat through its own syscall-table / branch-link / LSM machinery in
// KernelSU/kernel/hook/* and KernelSU/kernel/feature/sucompat.c instead. FinaSU's own shipped
// 2.5.5 edition does not enable CONFIG_KSU_HOOK_SUSFS_INLINE either (its default hook backend
// is Tracepoint), so even there those call sites always take the "stub" branch below in
// practice. This file keeps that same stub branch permanently: the inline call sites stay
// linkable (so fs/exec.c etc. compile unmodified) but never redirect anything, since
// backslashxx's own hooks already handle su -> ksud redirection for every process.
//
// What this file does provide for real:
//   - the SID lookups fs/susfs.c and security/selinux/*.c need (susfs_is_current_*_domain)
//   - the SUSFS_MAGIC branch of the sys_reboot supercall used by the ksu_susfs userspace tool
//     (kept separate from backslashxx's own ksu_handle_sys_reboot in supercall/supercall.c,
//     which is used by its syscall-table/branch-link hooks and must keep its own calling
//     convention: see kernel/reboot.c in this tree, edited for this edition only)
//
// selinux_hide: fs/susfs.c and security/selinux/{hooks,selinuxfs}.c also reference
// ksu_selinux_hide_running/susfs_ksu_selinux_hide_enabled/fake_status/initialize_fake_status, which
// FinaSU's own feature/selinux_hide.c implements. backslashxx ships a different, independent
// selinux_hide feature (KernelSU/kernel/feature/selinux_hide.c, toggled via its own supercall
// feature id) that this edition keeps using as its real root-hiding mechanism. The symbols
// below are kept permanently inert (ksu_selinux_hide_running stays false) so those call sites
// link and compile without reimplementing a second, redundant hide mechanism.

#include <linux/cred.h>
#include <linux/err.h>
#include <linux/jump_label.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/workqueue.h>

#include <linux/susfs.h>
#include <linux/susfs_def.h>

#include "selinux/selinux.h"

/***** stub inline-hook surface (see header comment) *****/

// Named differently from backslashxx's own file-scope `ksu_su_compat_enabled` bool in
// feature/sucompat.c (same unity translation unit, would otherwise collide). fs/exec.c and
// fs/stat.c are edited in this tree, for this edition only, to reference this name instead.
DEFINE_STATIC_KEY_TRUE(susfs_su_compat_enabled_key);
DEFINE_STATIC_KEY_FALSE(ksu_is_init_rc_hook_enabled);
DEFINE_STATIC_KEY_FALSE(ksu_is_input_hook_enabled);

int susfs_inl_execveat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags)
{
	return -EINVAL;
}

int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags)
{
	return -EINVAL;
}

int ksu_handle_post_execveat_sucompat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags,
				       int *retval)
{
	return 0;
}

int susfs_inl_faccessat(int *dfd, struct filename **filename, int *mode, int *unused_flags)
{
	return 0;
}

int susfs_inl_stat(int *dfd, struct filename **filename, int *flags)
{
	return 0;
}

// kernel/sys.c calls this from setresuid; backslashxx handles setuid through its own LSM
// task_fix_setuid hook (hook/setuid_hook.c), so nothing to do here
int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	return 0;
}

void ksu_handle_sys_read(unsigned int fd)
{
}

void ksu_handle_vfs_fstat(int fd, loff_t *size)
{
}

__attribute__((cold)) int ksu_handle_input_handle_event(unsigned int *type, unsigned int *code, int *value)
{
	return 0;
}

/***** selinux_hide stub surface (see header comment): permanently inert *****/

bool ksu_selinux_hide_running __read_mostly = false;
bool susfs_ksu_selinux_hide_enabled __read_mostly = false;
struct page *fake_status __read_mostly = NULL;
DEFINE_STATIC_KEY_FALSE(fake_status_initialize_key);

void initialize_fake_status(void)
{
}

/***** real SID lookups for fs/susfs.c, fs/nomount and the selinux sources *****/

#define SUSFS_ZYGOTE_NEXT_CONTEXT "u:r:zygote_next:s0"
#define SUSFS_PRIV_APP_CONTEXT "u:r:priv_app:s0:c512,c768"

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
typedef struct task_security_struct susfs_selinux_cred_t;
#else
typedef struct cred_security_struct susfs_selinux_cred_t;
#endif

u32 susfs_ksu_sid __read_mostly = 0;
static u32 susfs_init_sid __read_mostly = 0;
static u32 susfs_zygote_sid __read_mostly = 0;
static u32 susfs_zygote_next_sid __read_mostly = 0;
u32 susfs_priv_app_sid __read_mostly = 0;

static u32 susfs_current_selinux_sid(void)
{
	const susfs_selinux_cred_t *tsec = selinux_cred(current_cred());

	return tsec ? tsec->sid : 0;
}

static void susfs_cache_one_sid(const char *secctx_name, u32 *out_sid)
{
	u32 sid = 0;

	if (security_secctx_to_secid(secctx_name, strlen(secctx_name), &sid))
		sid = 0;
	*out_sid = sid;
}

void susfs_set_batch_sid(void)
{
	susfs_cache_one_sid(ZYGOTE_CONTEXT, &susfs_zygote_sid);
	susfs_cache_one_sid(SUSFS_ZYGOTE_NEXT_CONTEXT, &susfs_zygote_next_sid);
	susfs_cache_one_sid(KERNEL_SU_CONTEXT, &susfs_ksu_sid);
	susfs_cache_one_sid(INIT_CONTEXT, &susfs_init_sid);
	susfs_cache_one_sid(SUSFS_PRIV_APP_CONTEXT, &susfs_priv_app_sid);
}

bool susfs_is_current_zygote_domain(void)
{
	return susfs_zygote_sid && susfs_current_selinux_sid() == susfs_zygote_sid;
}

bool susfs_is_current_zygote_next_domain(void)
{
	return susfs_zygote_next_sid && susfs_current_selinux_sid() == susfs_zygote_next_sid;
}

bool susfs_is_current_ksu_domain(void)
{
	return susfs_ksu_sid && susfs_current_selinux_sid() == susfs_ksu_sid;
}

bool susfs_is_current_init_domain(void)
{
	return susfs_init_sid && susfs_current_selinux_sid() == susfs_init_sid;
}

bool susfs_is_current_priv_app_domain(void)
{
	return susfs_priv_app_sid && susfs_current_selinux_sid() == susfs_priv_app_sid;
}

// cred-taking variant, used by hook/setuid_hook.c (backslashxx edition) to tell apart a
// plain zygote fork from a zygote_next fork (WebView zygote) for the *old* (pre-setresuid)
// cred, which susfs_is_current_zygote_next_domain() above cannot check (it only reads
// current_cred(), and current's cred has not committed the new uid yet at that call site
// either way, so both forms read the same cred in practice — kept separate for clarity and
// in case a future caller needs to check a cred that is not current's).
bool susfs_is_zygote_next_domain(const struct cred *cred)
{
	const susfs_selinux_cred_t *tsec;

	if (!cred || !susfs_zygote_next_sid)
		return false;
	tsec = selinux_cred(cred);
	return tsec && tsec->sid == susfs_zygote_next_sid;
}

/***** SUSFS_MAGIC supercall branch, used by the ksu_susfs userspace tool *****/
//
// Kept apart from backslashxx's own ksu_handle_sys_reboot (supercall/supercall.c), which is
// called from its syscall-table/branch-link hooks with a different convention (return value
// ignored, real reboot always runs afterward). This one is called from kernel/reboot.c (edited
// for this edition, see the diff there), which instead treats 0 as "handled, do not reboot".
// Any call whose magic1 is not KSU_INSTALL_MAGIC1 is a real reboot() and must fall through.
int susfs_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg)
{
	if (magic1 != KSU_INSTALL_MAGIC1)
		return -EINVAL;

	if (magic2 != SUSFS_MAGIC || current_uid().val != 0)
		return -EINVAL;

	switch (cmd) {
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
	case CMD_SUSFS_ADD_SUS_PATH:
		susfs_add_sus_path(arg);
		return 0;
	case CMD_SUSFS_ADD_SUS_PATH_LOOP:
		susfs_add_sus_path_loop(arg);
		return 0;
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	case CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS:
		susfs_set_hide_sus_mnts_for_non_su_procs(arg);
		return 0;
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
	case CMD_SUSFS_ADD_SUS_KSTAT:
	case CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY:
		susfs_add_sus_kstat(arg);
		return 0;
	case CMD_SUSFS_UPDATE_SUS_KSTAT:
		susfs_update_sus_kstat(arg);
		return 0;
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
	case CMD_SUSFS_SET_UNAME:
		susfs_set_uname(arg);
		return 0;
#endif
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
	case CMD_SUSFS_ENABLE_LOG:
		susfs_enable_log(arg);
		return 0;
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
	case CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG:
		susfs_set_cmdline_or_bootconfig(arg);
		return 0;
#endif
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
	case CMD_SUSFS_ADD_OPEN_REDIRECT:
		susfs_add_open_redirect(arg);
		return 0;
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MAP
	case CMD_SUSFS_ADD_SUS_MAP:
		susfs_add_sus_map(arg);
		return 0;
#endif
#ifdef CONFIG_KSU_SUSFS_PRIORITY_UID_FILTER
	case CMD_SUSFS_SET_PRIORITY_UID_FILTER:
		susfs_set_priority_uid_filter(arg);
		return 0;
#endif
	case CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING:
		susfs_set_avc_log_spoofing(arg);
		return 0;
	case CMD_SUSFS_SHOW_ENABLED_FEATURES:
		susfs_get_enabled_features(arg);
		return 0;
	case CMD_SUSFS_SHOW_VARIANT:
		susfs_show_variant(arg);
		return 0;
	case CMD_SUSFS_SHOW_VERSION:
		susfs_show_version(arg);
		return 0;
	default:
		return -EINVAL;
	}
}
