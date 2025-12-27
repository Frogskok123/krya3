#include <linux/module.h>
#include <linux/tty.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h> // Для copy_from_user
#include <linux/slab.h>    // Для kmalloc/kzalloc

#include "comm.h"
#include "memory.h"
#include "process.h"

#define DEVICE_NAME "mtk_tersafe"

static int dispatch_open(struct inode *node, struct file *file)
{
    return 0;
}

static int dispatch_close(struct inode *node, struct file *file)
{
    return 0;
}

static long dispatch_ioctl(struct file *const file, unsigned int const cmd, unsigned long const arg)
{
    // ВАЖНО: Переменные должны быть локальными (на стеке), а не static!
    // static переменные общие для всех процессов -> причина сбоев и паники.
    COPY_MEMORY cm;
    MODULE_BASE mb;
    
    // Буфер для имени модуля. Можно на стеке, 256 байт это нормально.
    char name[256];

    switch (cmd) {
    case OP_READ_MEM:
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)) != 0)
            return -EFAULT;
        
        // Проверка валидности указателей
        if (!cm.buffer || cm.size == 0)
            return -EINVAL;

        if (read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false)
            return -EIO;
        break;

    case OP_WRITE_MEM:
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)) != 0)
            return -EFAULT;
            
        if (!cm.buffer || cm.size == 0)
            return -EINVAL;

        if (write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false)
            return -EIO;
        break;

    case OP_MODULE_BASE: {
        long str_len;

        if (copy_from_user(&mb, (void __user *)arg, sizeof(mb)) != 0)
            return -EFAULT;

        // Очищаем буфер перед копированием
        memset(name, 0, sizeof(name));

        // Копируем строку имени модуля из user space
        // mb.name здесь - это указатель (char*), приходящий из приложения
        str_len = strncpy_from_user(name, (const char __user *)mb.name, sizeof(name) - 1);
        
        if (str_len < 0)
            return -EFAULT;

        // Ищем базу
        mb.base = get_module_base(mb.pid, name);

        // Возвращаем результат (структуру с заполненным base) обратно пользователю
        if (copy_to_user((void __user *)arg, &mb, sizeof(mb)) != 0)
            return -EFAULT;
            
        break;
    }
    
    // Если ключи убраны, OP_INIT_KEY можно убрать или оставить пустым
    // case OP_INIT_KEY: return 0;

    default:
        return -EINVAL;
    }
    return 0;
}

static const struct file_operations dispatch_functions = {
    .owner = THIS_MODULE,
    .open = dispatch_open,
    .release = dispatch_close,
    .unlocked_ioctl = dispatch_ioctl,
};

static struct miscdevice misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = DEVICE_NAME,
    .fops = &dispatch_functions,
};

static int __init driver_entry(void) {
    int ret;
    
    // Инициализация Kprobes (поиск скрытых функций ядра)
    if (!resolve_kernel_symbols()) {
        printk(KERN_ERR "[-] Failed to resolve kernel symbols");
        return -EFAULT;
    }

    printk(KERN_INFO "[+] JiangNight: Fast Kmap Driver Loaded");
    ret = misc_register(&misc);
    return ret;
}

static void __exit driver_unload(void)
{
    printk(KERN_INFO "[+] JiangNight driver unloaded");
    misc_deregister(&misc);
}

module_init(driver_entry);
module_exit(driver_unload);

MODULE_DESCRIPTION("Android GKI Memory Driver");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kryasan");MODULE_AUTHOR("Kryasan");
