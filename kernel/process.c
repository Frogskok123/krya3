#include "process.h"
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/tty.h>
#include <linux/mm.h>
#include <linux/version.h>
#include <linux/file.h>
#include <linux/fs.h>

#define ARC_PATH_MAX 256

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
#include <linux/maple_tree.h>
#endif

uintptr_t get_module_base(pid_t pid, char *name)
{
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    uintptr_t base_addr = 0;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
    struct vma_iterator vmi;
#endif

    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return 0;

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task)
        goto out_put_pid;

    mm = get_task_mm(task);
    if (!mm)
        goto out_put_task;

    // ВАЖНО: Захватываем блокировку перед итерацией по VMA
    if (mmap_read_lock_killable(mm)) {
        mmput(mm);
        goto out_put_task;
    }

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
    vma_iter_init(&vmi, mm, 0);
    for_each_vma(vmi, vma)
#else
    for (vma = mm->mmap; vma; vma = vma->vm_next)
#endif
    {
        char buf[ARC_PATH_MAX];
        char *path_nm = "";

        if (vma->vm_file) {
            // Используем d_path вместо file_path, так как он безопаснее внутри ядра для путей
            path_nm = file_path(vma->vm_file, buf, ARC_PATH_MAX - 1);
            
            if (IS_ERR(path_nm))
                continue;

            // Сравнение имени файла
            if (!strcmp(kbasename(path_nm), name)) {
                base_addr = vma->vm_start;
                break;
            }
        }
    }

    // ВАЖНО: Освобождаем блокировку
    mmap_read_unlock(mm);

    mmput(mm);

out_put_task:
    put_task_struct(task);
out_put_pid:
    put_pid(pid_struct);

    return base_addr;
}
