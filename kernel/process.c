#include "process.h"
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/tty.h>
#include <linux/mm.h>
#include <linux/version.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/slab.h> // Для kmalloc/kfree

// Максимальная длина пути в Linux обычно 4096
#define MAX_PATH_LEN 4096

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
    char *buf;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
    struct vma_iterator vmi;
#endif

    // Выделяем память в куче, так как 4096 байт слишком много для стека ядра
    buf = kmalloc(MAX_PATH_LEN, GFP_KERNEL);
    if (!buf) {
        return 0;
    }

    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        kfree(buf);
        return 0;
    }

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        put_pid(pid_struct);
        kfree(buf);
        return 0;
    }

    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        put_pid(pid_struct);
        kfree(buf);
        return 0;
    }

    // [ВАЖНО] Захват блокировки чтения перед итерацией по VMA
    // Если этого не сделать, ядро может запаниковать при изменении карты памяти
    if (mmap_read_lock_killable(mm)) {
        mmput(mm);
        put_task_struct(task);
        put_pid(pid_struct);
        kfree(buf);
        return 0;
    }

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
    // Для ядер 6.1+ (Android 14/15) используем VMA Iterator
    vma_iter_init(&vmi, mm, 0);
    for_each_vma(vmi, vma)
#else
    // Для старых ядер (Android 10-13) используем связный список
    for (vma = mm->mmap; vma; vma = vma->vm_next)
#endif
    {
        char *path_nm = NULL;

        // Проверяем, есть ли у региона памяти связанный файл
        if (vma->vm_file) {
            // Получаем полный путь к файлу
            path_nm = file_path(vma->vm_file, buf, MAX_PATH_LEN - 1);

            if (IS_ERR(path_nm))
                continue;

            // kbasename выделяет имя файла из пути (например /data/.../libil2cpp.so -> libil2cpp.so)
            // Сравниваем с искомым именем
            if (!strcmp(kbasename(path_nm), name)) {
                base_addr = vma->vm_start;
                break; // Нашли базу, выходим из цикла
            }
        }
    }

    // [ВАЖНО] Освобождение блокировки
    mmap_read_unlock(mm);

    mmput(mm);
    put_task_struct(task);
    put_pid(pid_struct);
    kfree(buf);

    return base_addr;
}
