/**
 * @file
 * @author Z. Liu <liuzx@knownsec.com>
 *
 * @brief kernel module for packet inspection
 */
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/netfilter_ipv4.h>

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Z. Liu <liuzx@knownsec.com>");
MODULE_DESCRIPTION("demo of packet inspection");

static unsigned int pkt_chk_out(unsigned int hooknum, struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
    struct tcphdr *th;
    struct udphdr *uh;
    uint16_t sport = 0, dport = 0;
    struct iphdr *iph = (struct iphdr *)skb_network_header(skb);

    switch (iph->protocol) {
        case IPPROTO_UDP:
            uh = (struct udphdr *)skb_transport_header(skb);
            sport = (unsigned int)ntohs(uh->source);
            dport = (unsigned int)ntohs(uh->dest);
            break;
        case IPPROTO_TCP:
            th = (struct tcphdr *)skb_transport_header(skb);
            sport = (unsigned int)ntohs(th->source);
            dport = (unsigned int)ntohs(th->dest);
            break;
        default:
            break;
    }

    pr_info("OUT: v%d, %pI4:%u -> %pI4:%u, proto: %u\n",
        iph->version, &iph->saddr, sport, &iph->daddr, dport, iph->protocol);

    return NF_ACCEPT;
}

static unsigned int pkt_chk_in(unsigned int hooknum, struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
    unsigned char *h;
    const char *indev;
    struct tcphdr *th;
    struct udphdr *uh;
    uint16_t sport = 0, dport = 0;
    struct iphdr *iph = (struct iphdr *)skb_network_header(skb);
    static const char nulldevname[IFNAMSIZ] __attribute__((aligned(sizeof(long))));

    indev = in ? in->name : nulldevname;

    // @note when a packet goes in from wire, it travels from physical layer,
    // data link layer, network layer upwards, therefore it might not go
    // through the functions for skb_transport_header to work as expected.
    // so we need a hack: skip the ip header. this is the case of kernel 
    // below 3.9.
    switch (iph->protocol) {
        case IPPROTO_UDP:
        case IPPROTO_TCP:
            // transport header is set correctly for kernel 3.9,
            // may be true for earlier version, no test yet
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0) )
            if (likely(skb_transport_header(skb) == (unsigned char *)iph)) {
                pr_notice_once("transport header is not set for kernel 0x%x\n",
                    LINUX_VERSION_CODE);
#else
            if (!skb_transport_header_was_set(skb)) {
#endif
                h = (unsigned char *)iph + (iph->ihl << 2);
            } else {
                h = skb_transport_header(skb);
            }
            if (iph->protocol == IPPROTO_UDP) {
                uh = (struct udphdr *)h;
                sport = (unsigned int)ntohs(uh->source);
                dport = (unsigned int)ntohs(uh->dest);
            } else {
                th = (struct tcphdr *)h;
                sport = (unsigned int)ntohs(th->source);
                dport = (unsigned int)ntohs(th->dest);
            }
            break;
        default:
            break;
    }

    pr_info("IN: v%d, %pI4:%u -> %pI4:%u, proto: %u, dev: %s\n",
        iph->version, &iph->saddr, sport, &iph->daddr, dport,
        iph->protocol, indev);

    return NF_ACCEPT;
}

static struct nf_hook_ops packet_ops[] __read_mostly = {
    {
        .hook     = pkt_chk_in,
        .owner    = THIS_MODULE,
        .pf       = NFPROTO_IPV4,
        .hooknum  = NF_INET_PRE_ROUTING,
        .priority = NF_IP_PRI_FIRST,
    },
    {
        .hook     = pkt_chk_out,
        .owner    = THIS_MODULE,
        .pf       = NFPROTO_IPV4,
        .hooknum  = NF_INET_LOCAL_OUT,
        .priority = NF_IP_PRI_FIRST,
    },
};

static int __init pkt_chk_init(void)
{
    int ret;

    pr_info("initialize of packet inspection module\n");

    ret = nf_register_hooks(packet_ops, ARRAY_SIZE(packet_ops));
    if (ret < 0) {
        return ret;
    }

    return 0;
}

static void __exit pkt_chk_exit(void)
{
    nf_unregister_hooks(packet_ops, ARRAY_SIZE(packet_ops));

    pr_info("packet inspection module unloaded.\n");
}

module_init(pkt_chk_init);
module_exit(pkt_chk_exit);
