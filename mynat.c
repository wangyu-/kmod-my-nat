#include <linux/inet.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/string.h>

typedef unsigned int u32_t;
typedef unsigned short u16_t;

char my_ip[]="192.168.22.134";
int my_port=8080;
char dst_ip[]="45.76.100.53";
int dst_port=8080;

static unsigned char my_hwaddr[ETH_ALEN]={0x00,0x0c,0x29,0x98,0x3e,0x76};
static unsigned char dst_hwaddr[ETH_ALEN]={0x00,0x50,0x56,0xfd,0x42,0x9e};
static int ok=0;

u32_t my_ip_u32;
u32_t dst_ip_u32;
u16_t my_port_u16;
u16_t dst_port_u16;

u32_t last_ip;

static unsigned int local_out_hook(const struct nf_hook_ops *ops,
                               struct sk_buff *skb,
                               const struct net_device *in,
                               const struct net_device *out,
#ifndef __GENKSYMS__
                               const struct nf_hook_state *state
#else
                               int (*okfn)(struct sk_buff *)
#endif
                               )
{
	struct iphdr *iph;
	unsigned int hdroff;
	struct tcphdr *hdr;
	int iphdroff=0;
	int hdrsize= sizeof(struct tcphdr);
	int err;
	u16_t old_port;
	iph = (void *)skb->data + iphdroff;
	hdroff = iphdroff + iph->ihl * 4;	
/*
	if(ok==0&&iph->daddr==dst_ip_u32)
	{
		ok=1;
		memcpy(dst_hwaddr, (eth_hdr(skb)->h_dest), ETH_ALEN);
		printk("okay!! %pM\n",dst_hwaddr);
	}*/
	
	

	
	return NF_ACCEPT;
	
}
static unsigned int pre_routing_hook(const struct nf_hook_ops *ops,
                               struct sk_buff *skb,
                               const struct net_device *in,
                               const struct net_device *out,
#ifndef __GENKSYMS__
                               const struct nf_hook_state *state
#else
                               int (*okfn)(struct sk_buff *)
#endif
                               )
{
	struct iphdr *iph;
	unsigned int hdroff;
	struct tcphdr *hdr;
	int iphdroff=0;
	int hdrsize= sizeof(struct tcphdr);
	int ret,err;
	u16_t old_port;
	iph = (void *)skb->data + iphdroff;
	hdroff = iphdroff + iph->ihl * 4;	
	if(iph->protocol!=6) return NF_ACCEPT;
	if(skb->len < hdroff + sizeof(struct tcphdr)) return NF_ACCEPT;
	hdr = (struct tcphdr *)(skb->data + hdroff);
	
	
	if(iph->daddr==my_ip_u32&&hdr->dest==my_port_u16)
	{
		/*if (!skb_make_writable(skb, iphdroff + sizeof(*iph)))
		{	
			printk("fail1i\n");
			return NF_ACCEPT;
		}*/
		printk("before,%pM %pM\n",eth_hdr(skb)->h_source,eth_hdr(skb)->h_dest);


		//last_ip=iph->saddr;
		//old_port=hdr->dest;
		//hdr->dest=dst_port_u16;
		//inet_proto_csum_replace2(&hdr->check, skb, old_port , dst_port_u16, 0);

		csum_replace4(&iph->check, iph->daddr, dst_ip_u32);
		iph->daddr = dst_ip_u32;

		csum_replace4(&iph->check, iph->saddr, my_ip_u32);
		iph->saddr = my_ip_u32;

		skb->pkt_type = PACKET_OTHERHOST;
		struct net_device * dev = dev_get_by_name(&init_net, "ens33"); 
		skb->dev=dev;

		
		skb->data = (unsigned char *)eth_hdr(skb);
		skb->len += ETH_HLEN; //sizeof(sb->mac.ethernet);
		memcpy((eth_hdr(skb)->h_dest), dst_hwaddr,
			ETH_ALEN);
		memcpy((eth_hdr(skb)->h_source), my_hwaddr,
			ETH_ALEN);

		printk("after, %pM %pM\n",eth_hdr(skb)->h_source,eth_hdr(skb)->h_dest);

		ret=dev_queue_xmit(skb);

		/*
		err=ip_route_me_harder(skb, RTN_UNSPEC);
		if(err<0)
		{
			printk("fail2");
		}
		skb_dst_drop(skb);*/
		printk("got a packet,%d,%d\n",ret,dev);
		return NF_STOLEN;
	}

	
	return NF_ACCEPT;
	
}
static unsigned int post_routing_hook(const struct nf_hook_ops *ops,
                               struct sk_buff *skb,
                               const struct net_device *in,
                               const struct net_device *out,
#ifndef __GENKSYMS__
                               const struct nf_hook_state *state
#else
                               int (*okfn)(struct sk_buff *)
#endif
                               )
{
	struct iphdr *iph;
	unsigned int hdroff;
	struct tcphdr *hdr;
	int iphdroff=0;
	int hdrsize= sizeof(struct tcphdr);
	int err;
	u16_t old_port;
	iph = (void *)skb->data + iphdroff;
	hdroff = iphdroff + iph->ihl * 4;	
	if(iph->protocol!=6) return NF_ACCEPT;
	if(skb->len < hdroff + sizeof(struct tcphdr)) return NF_ACCEPT;
	hdr = (struct tcphdr *)(skb->data + hdroff);

/*	
	if(iph->daddr==my_ip_u32&&hdr->dest==my_port_u16)
	{
		if (!skb_make_writable(skb, iphdroff + sizeof(*iph)))
		{	
			printk("fail1");
			return NF_ACCEPT;
		}
		csum_replace4(&iph->check, iph->daddr, dst_ip_u32);
		iph->daddr = dst_ip_u32;
	}*/
	return NF_ACCEPT;	
}

static struct nf_hook_ops nf_my_nat_ops[] = {
        {
                .hook           = pre_routing_hook,
                .owner          = THIS_MODULE,
                .pf             = NFPROTO_IPV4,
                .hooknum        = NF_INET_PRE_ROUTING,
                .priority       = NF_IP_PRI_FIRST,
        },
        {
                .hook           = post_routing_hook,
                .owner          = THIS_MODULE,
                .pf             = NFPROTO_IPV4,
                .hooknum        = NF_INET_POST_ROUTING,
                .priority       = NF_IP_PRI_FIRST,
        },
        {
                .hook           = local_out_hook,
                .owner          = THIS_MODULE,
                .pf             = NFPROTO_IPV4,
                .hooknum        = NF_INET_LOCAL_OUT,
                .priority       = NF_IP_PRI_FIRST,
        },
};


int init_module()
{
	ok=0;
	int ret=nf_register_hooks(nf_my_nat_ops, ARRAY_SIZE(nf_my_nat_ops));
	my_ip_u32=in_aton(my_ip);
	dst_ip_u32=in_aton(dst_ip);
	my_port_u16=htons(my_port);
	dst_port_u16=htons(dst_port);
	if(ret==0)
		printk("load ok\n");
	else
		printk("load fail\n");
	
	return 0;
}


void cleanup_module()
{
	nf_unregister_hooks(nf_my_nat_ops, ARRAY_SIZE(nf_my_nat_ops));
	printk("unloaded\n");
}
