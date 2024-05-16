#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/bpf.h>

MODULE_AUTHOR("Davide Collovigh");
MODULE_DESCRIPTION("protobuf_lkm: protobuf kfunc declaration");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");

/* Disables missing prototype warnings */
__bpf_kfunc_start_defs();

__bpf_kfunc message example_bpf_print(const char *text__str)
{
    message example;
    memset(&example, 0, sizeof(message));

    example.size = 8;
    strcpy(example.string, "Custom message");

    return example;
}

__bpf_kfunc_end_defs();

static int __init pbtools_lkm_init(void)
{
    pr_info("Loaded module\n");

    return 0;
}

static void __exit pbtools_lkm_exit(void)
{
    pr_info("Removed module\n");
}

module_init(pbtools_lkm_init);
module_exit(pbtools_lkm_exit);
