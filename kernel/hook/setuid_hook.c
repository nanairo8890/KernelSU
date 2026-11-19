#ifdef CONFIG_KSU_SUSFS
#include <linux/susfs_def.h>
extern bool susfs_is_current_zygote_domain(void);
extern bool susfs_is_zygote_next_domain(const struct cred *cred);
extern void susfs_set_current_proc_no_su(void);
extern void susfs_set_current_proc_umounted(void);
extern void susfs_set_current_proc_umounted_for_zygote_next(void);
extern struct work_struct susfs_extra_works;

static void ksu_susfs_mark_umounted(bool zygote_next)
{
	susfs_set_current_proc_no_su();
	susfs_set_current_proc_umounted();
	if (zygote_next)
		susfs_set_current_proc_umounted_for_zygote_next();
}
#endif

static __always_inline void ksu_handle_setresuid_cred(struct cred *new, const struct cred *old)
{
	if (!new || !old)
		return;

	uid_t new_uid = ksu_get_uid_t(new->uid);
	uid_t old_uid = ksu_get_uid_t(old->uid);

	// old process is not root, ignore it.
	if (unlikely(!!old_uid))
		return;

	if (IS_ENABLED(CONFIG_KSU_DEBUG))
		pr_info("handle_setresuid from %d to %d\n", old_uid, new_uid);

	// we dont have those new fancy things upstream has
	// lets just do the original thing where we disable seccomp
	if (unlikely(is_uid_manager(new_uid)))
		goto install_ksu_fd;

	if (ksu_is_allow_uid_for_current(new_uid))
		goto kill_seccomp;

#ifdef CONFIG_KSU_SUSFS
	// Mark the SUSFS/NoMount umounted-process flags for zygote's children (this is the exact
	// same old_uid==0 fork point bsxx's own ksu_handle_umount() below already acts on), so
	// fs/nomount/nomount.c serves the stock filesystem to any process whose modules were
	// umounted, same as it does for FinaSU. Only zygote's own children, not every root->X
	// transition, carry the SUSFS marks; ksu_handle_umount() keeps its own, separate check
	// (is_zygote(old)) for backslashxx's native umount path, which also naturally skips the
	// zygote_next case below (old is zygote_next's SID there, not zygote's).
	bool susfs_marked = false;

	if (susfs_is_current_zygote_domain()) {
		ksu_susfs_mark_umounted(false);
		susfs_marked = true;
	} else if (susfs_is_zygote_next_domain(old)) {
		ksu_susfs_mark_umounted(true);
		susfs_marked = true;
	}
#endif

	// Handle kernel umount
	ksu_handle_umount(new, old);

#ifdef CONFIG_KSU_SUSFS
	if (susfs_marked)
		schedule_work(&susfs_extra_works);
#endif
	return;

install_ksu_fd:
	pr_info("install fd for manager: %d\n", new_uid);
	ksu_install_fd();

kill_seccomp:
	disable_seccomp();
	set_thread_flag(TIF_KSU_MANAGED); // sucompat fast-path
	return;
}
