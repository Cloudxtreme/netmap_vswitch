/*
 * Copyright (C) 2013-2014 Universita` di Pisa. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "bsd_glue.h"
#include <linux/file.h>   /* fget(int fd) */

#include <linux/rtnetlink.h>
#include <linux/nsproxy.h>
#include <net/pkt_sched.h>
#include <net/sch_generic.h>

#include <netmap.h>
#include "netmap_kern.h"
#include "netmap_mem2.h"

#include "netmap_linux_config.h"

void
nm_os_ifnet_lock(void)
{
	rtnl_lock();
}

void
nm_os_ifnet_unlock(void)
{
	rtnl_unlock();
}

/* Register for a notification on device removal */
static int
linux_netmap_notifier_cb(struct notifier_block *b,
		unsigned long val, void *v)
{
	struct ifnet *ifp = netdev_notifier_info_to_dev(v);

	/* linux calls us while holding rtnl_lock() */
	switch (val) {
	case NETDEV_UNREGISTER:
		netmap_make_zombie(ifp);
		break;
	case NETDEV_GOING_DOWN:
		netmap_disable_all_rings(ifp);
		break;
	case NETDEV_UP:
		netmap_enable_all_rings(ifp);
		break;
	default:
		/* we don't care */
		break;
	}
	return NOTIFY_OK;
}

static struct notifier_block linux_netmap_netdev_notifier = {
	.notifier_call = linux_netmap_notifier_cb,
};

static int nm_os_ifnet_registered;

int
nm_os_ifnet_init(void)
{
	int error = register_netdevice_notifier(&linux_netmap_netdev_notifier);
	if (!error)
		nm_os_ifnet_registered = 1;
	return error;
}

void
nm_os_ifnet_fini(void)
{
	if (nm_os_ifnet_registered) {
		unregister_netdevice_notifier(&linux_netmap_netdev_notifier);
		nm_os_ifnet_registered = 0;
	}
}

#ifdef NETMAP_LINUX_HAVE_IOMMU
#include <linux/iommu.h>

/* #################### IOMMU ################## */
/*
 * Returns the IOMMU domain id that the device belongs to.
 */
int nm_iommu_group_id(struct device *dev)
{
	struct iommu_group *grp;
	int id;

	if (!dev)
		return 0;

	grp = iommu_group_get(dev);
	if (!grp)
		return 0;

	id = iommu_group_id(grp);
	return id;
}
#else /* ! HAVE_IOMMU */
int nm_iommu_group_id(struct device *dev)
{
	return 0;
}
#endif /* HAVE_IOMMU */

/* #################### VALE OFFLOADINGS SUPPORT ################## */

/* Compute and return a raw checksum over (data, len), using 'cur_sum'
 * as initial value. Both 'cur_sum' and the return value are in host
 * byte order.
 */
rawsum_t
nm_os_csum_raw(uint8_t *data, size_t len, rawsum_t cur_sum)
{
	return csum_partial(data, len, cur_sum);
}

/* Compute an IPv4 header checksum, where 'data' points to the IPv4 header,
 * and 'len' is the IPv4 header length. Return value is in network byte
 * order.
 */
uint16_t
nm_os_csum_ipv4(struct nm_iphdr *iph)
{
	return ip_compute_csum((void*)iph, sizeof(struct nm_iphdr));
}

/* Compute and insert a TCP/UDP checksum over IPv4: 'iph' points to the IPv4
 * header, 'data' points to the TCP/UDP header, 'datalen' is the lenght of
 * TCP/UDP header + payload.
 */
void
nm_os_csum_tcpudp_ipv4(struct nm_iphdr *iph, void *data,
		      size_t datalen, uint16_t *check)
{
	*check = csum_tcpudp_magic(iph->saddr, iph->daddr,
				datalen, iph->protocol,
				csum_partial(data, datalen, 0));
}

/* Compute and insert a TCP/UDP checksum over IPv6: 'ip6h' points to the IPv6
 * header, 'data' points to the TCP/UDP header, 'datalen' is the lenght of
 * TCP/UDP header + payload.
 */
void
nm_os_csum_tcpudp_ipv6(struct nm_ipv6hdr *ip6h, void *data,
		      size_t datalen, uint16_t *check)
{
	*check = csum_ipv6_magic((void *)&ip6h->saddr, (void*)&ip6h->daddr,
				datalen, ip6h->nexthdr,
				csum_partial(data, datalen, 0));
}

uint16_t
nm_os_csum_fold(rawsum_t cur_sum)
{
	return csum_fold(cur_sum);
}

/* on linux we send up one packet at a time */
void *
nm_os_send_up(struct ifnet *ifp, struct mbuf *m, struct mbuf *prev)
{
	(void)ifp;
	(void)prev;
	m->priority = NM_MAGIC_PRIORITY_RX; /* do not reinject to netmap */
	netif_rx(m);
	return NULL;
}

/* Use ethtool to find the current NIC rings lengths, so that the netmap
   rings can have the same lengths. */
int
nm_os_generic_find_num_desc(struct ifnet *ifp, unsigned int *tx, unsigned int *rx)
{
    int error = EOPNOTSUPP;
#ifdef NETMAP_LINUX_HAVE_GET_RINGPARAM
    struct ethtool_ringparam rp;

    if (ifp->ethtool_ops && ifp->ethtool_ops->get_ringparam) {
        ifp->ethtool_ops->get_ringparam(ifp, &rp);
        *tx = rp.tx_pending ? rp.tx_pending : rp.tx_max_pending;
        *rx = rp.rx_pending ? rp.rx_pending : rp.rx_max_pending;
	if (*tx && *rx)
		error = 0;
    }
#endif /* HAVE_GET_RINGPARAM */
    return error;
}

/* Fills in the output arguments with the number of hardware TX/RX queues. */
void
nm_os_generic_find_num_queues(struct ifnet *ifp, u_int *txq, u_int *rxq)
{
#ifdef NETMAP_LINUX_HAVE_SET_CHANNELS
    struct ethtool_channels ch;
    memset(&ch, 0, sizeof(ch));
    if (ifp->ethtool_ops && ifp->ethtool_ops->get_channels) {
	    ifp->ethtool_ops->get_channels(ifp, &ch);
	    *txq = ch.tx_count ? ch.tx_count : ch.combined_count;
	    *rxq = ch.rx_count ? ch.rx_count : ch.combined_count;
    } else
#endif /* HAVE_SET_CHANNELS */
    {
#if defined(NETMAP_LINUX_HAVE_NUM_QUEUES)
    	*txq = ifp->real_num_tx_queues;
    	*rxq = ifp->real_num_rx_queues;
#else
    	*txq = 1;
    	*rxq = 1; /* TODO ifp->real_num_rx_queues */
#endif /* HAVE_NUM_QUEUES */
    }
}

int
netmap_linux_config(struct netmap_adapter *na,
		u_int *txr, u_int *txd, u_int *rxr, u_int *rxd)
{
	struct ifnet *ifp = na->ifp;
	int error = 0;

	rtnl_lock();

	if (ifp == NULL) {
		D("zombie adapter");
		error = ENXIO;
		goto out;
	}
	error = nm_os_generic_find_num_desc(ifp, txd, rxd);
	if (error)
		goto out;
	nm_os_generic_find_num_queues(ifp, txr, rxr);

out:
	rtnl_unlock();

	return error;
}


/* ######################## FILE OPERATIONS ####################### */

struct net_device *
ifunit_ref(const char *name)
{
#ifndef NETMAP_LINUX_HAVE_INIT_NET
	return dev_get_by_name(name);
#else
	void *ns = &init_net;
#ifdef CONFIG_NET_NS
	ns = current->nsproxy->net_ns;
#endif
	return dev_get_by_name(ns, name);
#endif
}

void if_rele(struct net_device *ifp)
{
	dev_put(ifp);
}

struct nm_linux_selrecord_t {
	struct file *file;
	struct poll_table_struct *pwait;
};

/*
 * Remap linux arguments into the FreeBSD call.
 * - pwait is the poll table, passed as 'dev';
 *   If pwait == NULL someone else already woke up before. We can report
 *   events but they are filtered upstream.
 *   If pwait != NULL, then pwait->key contains the list of events.
 * - events is computed from pwait as above.
 * - file is passed as 'td';
 */
static u_int
linux_netmap_poll(struct file * file, struct poll_table_struct *pwait)
{
#ifdef NETMAP_LINUX_PWAIT_KEY
	int events = pwait ? pwait->NETMAP_LINUX_PWAIT_KEY : \
		     POLLIN | POLLOUT | POLLERR;
#else
	int events = POLLIN | POLLOUT; /* XXX maybe... */
#endif /* PWAIT_KEY */
	struct nm_linux_selrecord_t sr = {
		.file = file,
		.pwait = pwait
	};
	struct netmap_priv_d *priv = file->private_data;
	return netmap_poll(priv, events, &sr);
}

static int
linux_netmap_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct netmap_priv_d *priv = vma->vm_private_data;
	struct netmap_adapter *na = priv->np_na;
	struct page *page;
	unsigned long off = (vma->vm_pgoff + vmf->pgoff) << PAGE_SHIFT;
	unsigned long pa, pfn;

	pa = netmap_mem_ofstophys(na->nm_mem, off);
	ND("fault off %lx -> phys addr %lx", off, pa);
	if (pa == 0)
		return VM_FAULT_SIGBUS;
	pfn = pa >> PAGE_SHIFT;
	if (!pfn_valid(pfn))
		return VM_FAULT_SIGBUS;
	page = pfn_to_page(pfn);
	get_page(page);
	vmf->page = page;
	return 0;
}

static struct vm_operations_struct linux_netmap_mmap_ops = {
	.fault = linux_netmap_fault,
};

static int
linux_netmap_mmap(struct file *f, struct vm_area_struct *vma)
{
	int error = 0;
	unsigned long off;
	u_int memsize, memflags;
	struct netmap_priv_d *priv = f->private_data;
	struct netmap_adapter *na = priv->np_na;
	/*
	 * vma->vm_start: start of mapping user address space
	 * vma->vm_end: end of the mapping user address space
	 * vma->vm_pfoff: offset of first page in the device
	 */

	if (priv->np_nifp == NULL) {
		return -EINVAL;
	}
	mb();

	/* check that [off, off + vsize) is within our memory */
	error = netmap_mem_get_info(na->nm_mem, &memsize, &memflags, NULL);
	ND("get_info returned %d", error);
	if (error)
		return -error;
	off = vma->vm_pgoff << PAGE_SHIFT;
	ND("off %lx size %lx memsize %x", off,
			(vma->vm_end - vma->vm_start), memsize);
	if (off + (vma->vm_end - vma->vm_start) > memsize)
		return -EINVAL;
	if (memflags & NETMAP_MEM_IO) {
		vm_ooffset_t pa;

		/* the underlying memory is contiguous */
		pa = netmap_mem_ofstophys(na->nm_mem, 0);
		if (pa == 0)
			return -EINVAL;
		return remap_pfn_range(vma, vma->vm_start, 
				pa >> PAGE_SHIFT,
				vma->vm_end - vma->vm_start,
				vma->vm_page_prot);
	} else {
		/* non contiguous memory, we serve 
		 * page faults as they come
		 */
		vma->vm_private_data = priv;
		vma->vm_ops = &linux_netmap_mmap_ops;
	}
	return 0;
}


/*
 * This one is probably already protected by the netif lock XXX
 */
netdev_tx_t
linux_netmap_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	netmap_transmit(dev, skb);
	return (NETDEV_TX_OK);
}

/* while in netmap mode, we cannot tolerate any change in the
 * number of rx/tx rings and descriptors
 */
int
linux_netmap_set_ringparam(struct net_device *dev,
	struct ethtool_ringparam *e)
{
	return -EBUSY;
}

#ifdef NETMAP_LINUX_HAVE_SET_CHANNELS
int
linux_netmap_set_channels(struct net_device *dev,
	struct ethtool_channels *e)
{
	return -EBUSY;
}
#endif


#ifndef NETMAP_LINUX_HAVE_UNLOCKED_IOCTL
#define LIN_IOCTL_NAME	.ioctl
static int
linux_netmap_ioctl(struct inode *inode, struct file *file, u_int cmd, u_long data /* arg */)
#else
#define LIN_IOCTL_NAME	.unlocked_ioctl
static long
linux_netmap_ioctl(struct file *file, u_int cmd, u_long data /* arg */)
#endif
{
	struct netmap_priv_d *priv = file->private_data;
	int ret = 0;
	union {
		struct nm_ifreq ifr;
		struct nmreq nmr;
	} arg;
	size_t argsize = 0;

	switch (cmd) {
	case NIOCTXSYNC:
	case NIOCRXSYNC:
		break;
	case NIOCCONFIG:
		argsize = sizeof(arg.ifr);
		break;
	default:
		argsize = sizeof(arg.nmr);
		break;
	}
	if (argsize) {
		if (!data)
			return -EINVAL;
		bzero(&arg, argsize);
		if (copy_from_user(&arg, (void *)data, argsize) != 0)
			return -EFAULT;
	}
	ret = netmap_ioctl(priv, cmd, (caddr_t)&arg, NULL);
	if (data && copy_to_user((void*)data, &arg, argsize) != 0)
		return -EFAULT;
	return -ret;
}


static int
linux_netmap_release(struct inode *inode, struct file *file)
{
	(void)inode;	/* UNUSED */
	if (file->private_data)
		netmap_dtor(file->private_data);
	return (0);
}


static int
linux_netmap_open(struct inode *inode, struct file *file)
{
	struct netmap_priv_d *priv;
	int error;
	(void)inode;	/* UNUSED */

	NMG_LOCK();
	priv = netmap_priv_new();
	if (priv == NULL) {
		error = -ENOMEM;
		goto out;
	}
	file->private_data = priv;
out:
	NMG_UNLOCK();

	return (0);
}


static struct file_operations netmap_fops = {
    .owner = THIS_MODULE,
    .open = linux_netmap_open,
    .mmap = linux_netmap_mmap,
    LIN_IOCTL_NAME = linux_netmap_ioctl,
    .poll = linux_netmap_poll,
    .release = linux_netmap_release,
};

#ifdef WITH_VALE
#ifdef CONFIG_NET_NS
#include <net/netns/generic.h>

int netmap_bns_id;

struct netmap_bns {
	struct net *net;
	struct nm_bridge *bridges;
	u_int num_bridges;
};

#ifdef NETMAP_LINUX_HAVE_PERNET_OPS_ID
static int
nm_bns_create(struct net *net, struct netmap_bns **ns)
{
	*ns = net_generic(net, netmap_bns_id);
	return 0;
}
#define nm_bns_destroy(_1, _2)
#else
static int
nm_bns_create(struct net *net, struct netmap_bns **ns)
{
	int error = 0;

	*ns = kmalloc(sizeof(*ns), GFP_KERNEL);
	if (!*ns)
		return -ENOMEM;

	error = net_assign_generic(net, netmap_bns_id, *ns);
	if (error) {
		kfree(*ns);
		*ns = NULL;
	}
	return error;
}

void
nm_bns_destroy(struct net *net, struct netmap_bns *ns)
{
	kfree(ns);
	net_assign_generic(net, netmap_bns_id, NULL);
}
#endif

struct net*
netmap_bns_get(void)
{
	return get_net(current->nsproxy->net_ns);
}

void
netmap_bns_put(struct net *net_ns)
{
	put_net(net_ns);
}

void
netmap_bns_getbridges(struct nm_bridge **b, u_int *n)
{
	struct net *net_ns = current->nsproxy->net_ns;
	struct netmap_bns *ns = net_generic(net_ns, netmap_bns_id);

	*b = ns->bridges;
	*n = ns->num_bridges;
}

static int __net_init
netmap_pernet_init(struct net *net)
{
	struct netmap_bns *ns;
	int error = 0;

	error = nm_bns_create(net, &ns);
	if (error)
		return error;

	ns->net = net;
	ns->num_bridges = 8;
	ns->bridges = netmap_init_bridges2(ns->num_bridges);
	if (ns->bridges == NULL) {
		nm_bns_destroy(net, ns);
		return -ENOMEM;
	}

	return 0;
}

static void __net_init
netmap_pernet_exit(struct net *net)
{
	struct netmap_bns *ns = net_generic(net, netmap_bns_id);

	netmap_uninit_bridges2(ns->bridges, ns->num_bridges);
	ns->bridges = NULL;

	nm_bns_destroy(net, ns);
}

static struct pernet_operations netmap_pernet_ops = {
	.init = netmap_pernet_init,
	.exit = netmap_pernet_exit,
#ifdef NETMAP_LINUX_HAVE_PERNET_OPS_ID
	.id = &netmap_bns_id,
	.size = sizeof(struct netmap_bns),
#endif
};

int
netmap_bns_register(void)
{
#ifdef NETMAP_LINUX_HAVE_PERNET_OPS_ID
	return -register_pernet_subsys(&netmap_pernet_ops);
#else
	return -register_pernet_gen_subsys(&netmap_bns_id,
			&netmap_pernet_ops);
#endif
}

void
netmap_bns_unregister(void)
{
#ifdef NETMAP_LINUX_HAVE_PERNET_OPS_ID
	unregister_pernet_subsys(&netmap_pernet_ops);
#else
	unregister_pernet_gen_subsys(netmap_bns_id,
			&netmap_pernet_ops);
#endif
}
#endif /* CONFIG_NET_NS */
#endif /* WITH_VALE */

/* ##################### kthread wrapper ##################### */
#include <linux/eventfd.h>
#include <linux/mm.h>
#include <linux/mmu_context.h>
#include <linux/poll.h>
#include <linux/kthread.h>
#include <linux/cpumask.h> /* nr_cpu_ids */

u_int
nm_os_ncpus(void)
{
	return nr_cpu_ids;
}

/* kthread context */
struct nm_kthread_ctx {
    /* files to exchange notifications */
    struct file *ioevent_file;          /* notification from guest */
    struct file *irq_file;              /* notification to guest (interrupt) */
    struct eventfd_ctx  *irq_ctx;

    /* poll ioeventfd to receive notification from the guest */
    poll_table poll_table;
    wait_queue_head_t *waitq_head;
    wait_queue_t waitq;

    /* worker function and parameter */
    nm_kthread_worker_fn_t worker_fn;
    void *worker_private;

    struct nm_kthread *nmk;

    /* integer to manage multiple worker contexts (e.g., RX or TX in ptnetmap) */
    long type;
};

struct nm_kthread {
    struct mm_struct *mm;
    struct task_struct *worker;

    atomic_t scheduled;         /* pending wake_up request */
    int attach_user;            /* kthread attached to user_process */

    struct nm_kthread_ctx worker_ctx;
    int affinity;
};

void inline
nm_os_kthread_wakeup_worker(struct nm_kthread *nmk)
{
    /*
     * There may be a race between FE and BE,
     * which call both this function, and worker kthread,
     * that reads ptk->scheduled.
     *
     * For us it is not important the counter value,
     * but simply that it has changed since the last
     * time the kthread saw it.
     */
    atomic_inc(&nmk->scheduled);
    wake_up_process(nmk->worker);
}


static void
nm_kthread_poll_fn(struct file *file, wait_queue_head_t *wq_head, poll_table *pt)
{
    struct nm_kthread_ctx *ctx;

    ctx = container_of(pt, struct nm_kthread_ctx, poll_table);
    ctx->waitq_head = wq_head;
    add_wait_queue(wq_head, &ctx->waitq);
}

static int
nm_kthread_poll_wakeup(wait_queue_t *wq, unsigned mode, int sync, void *key)
{
    struct nm_kthread_ctx *ctx;

    ctx = container_of(wq, struct nm_kthread_ctx, waitq);
    nm_os_kthread_wakeup_worker(ctx->nmk);
    return 0;
}

static void inline
nm_kthread_worker_fn(struct nm_kthread_ctx *ctx)
{
    __set_current_state(TASK_RUNNING);
    ctx->worker_fn(ctx->worker_private); /* worker body */
    if (need_resched())
        schedule();
}

static int
nm_kthread_worker(void *data)
{
    struct nm_kthread *nmk = data;
    struct nm_kthread_ctx *ctx = &nmk->worker_ctx;
    int old_scheduled = atomic_read(&nmk->scheduled);
    int new_scheduled = old_scheduled;
    mm_segment_t oldfs = get_fs();

    if (nmk->mm) {
        set_fs(USER_DS);
        use_mm(nmk->mm);
    }

    while (!kthread_should_stop()) {
        /*
         * if ioevent_file is not defined, we don't have notification
         * mechanism and we continually execute worker_fn()
         */
        if (!ctx->ioevent_file) {
            nm_kthread_worker_fn(ctx);
        } else {
            /*
             * Set INTERRUPTIBLE state before to check if there is work.
             * if wake_up() is called, although we have not seen the new
             * counter value, the kthread state is set to RUNNING and
             * after schedule() it is not moved off run queue.
             */
            set_current_state(TASK_INTERRUPTIBLE);

            new_scheduled = atomic_read(&nmk->scheduled);

            /* checks if there is a pending notification */
            if (likely(new_scheduled != old_scheduled)) {
                old_scheduled = new_scheduled;
                nm_kthread_worker_fn(ctx);
            } else {
                schedule();
            }
        }
    }

    __set_current_state(TASK_RUNNING);

    if (nmk->mm) {
        unuse_mm(nmk->mm);
    }

    set_fs(oldfs);
    return 0;
}

void inline
nm_os_kthread_send_irq(struct nm_kthread *nmk)
{
    if (nmk->worker_ctx.irq_ctx)
        eventfd_signal(nmk->worker_ctx.irq_ctx, 1);
}

static int
nm_kthread_open_files(struct nm_kthread *nmk, struct nm_kth_event_cfg *ring_cfg)
{
    struct file *file;
    struct nm_kthread_ctx *wctx = &nmk->worker_ctx;

    if (ring_cfg->ioeventfd) {
	file = eventfd_fget(ring_cfg->ioeventfd);
	if (IS_ERR(file))
	    return -PTR_ERR(file);
	wctx->ioevent_file = file;
    }

    if (ring_cfg->irqfd) {
	file = eventfd_fget(ring_cfg->irqfd);
	if (IS_ERR(file))
            goto err;
	wctx->irq_file = file;
	wctx->irq_ctx = eventfd_ctx_fileget(file);
    }

    return 0;
err:
    if (wctx->ioevent_file) {
        fput(wctx->ioevent_file);
        wctx->ioevent_file = NULL;
    }

    return -PTR_ERR(file);
}

static void
nm_kthread_close_files(struct nm_kthread *nmk)
{
    struct nm_kthread_ctx *wctx = &nmk->worker_ctx;

    if (wctx->ioevent_file) {
        fput(wctx->ioevent_file);
        wctx->ioevent_file = NULL;
    }

    if (wctx->irq_file) {
        fput(wctx->irq_file);
        wctx->irq_file = NULL;
        eventfd_ctx_put(wctx->irq_ctx);
        wctx->irq_ctx = NULL;
    }
}

static void
nm_kthread_init_poll(struct nm_kthread *nmk, struct nm_kthread_ctx *ctx)
{
    init_waitqueue_func_entry(&ctx->waitq, nm_kthread_poll_wakeup);
    init_poll_funcptr(&ctx->poll_table, nm_kthread_poll_fn);
    ctx->nmk = nmk;
}

static int
nm_kthread_start_poll(struct nm_kthread_ctx *ctx, struct file *file)
{
    unsigned long mask;
    int ret = 0;

    if (ctx->waitq_head)
        return 0;
    mask = file->f_op->poll(file, &ctx->poll_table);
    if (mask)
        nm_kthread_poll_wakeup(&ctx->waitq, 0, 0, (void *)mask);
    if (mask & POLLERR) {
        if (ctx->waitq_head)
            remove_wait_queue(ctx->waitq_head, &ctx->waitq);
        ret = EINVAL;
    }
    return ret;
}

static void
nm_kthread_stop_poll(struct nm_kthread_ctx *ctx)
{
    if (ctx->waitq_head) {
        remove_wait_queue(ctx->waitq_head, &ctx->waitq);
        ctx->waitq_head = NULL;
    }
}

void
nm_os_kthread_set_affinity(struct nm_kthread *nmk, int affinity)
{
	nmk->affinity = affinity;
}

struct nm_kthread *
nm_os_kthread_create(struct nm_kthread_cfg *cfg)
{
    struct nm_kthread *nmk = NULL;
    int error;

    nmk = kzalloc(sizeof *nmk, GFP_KERNEL);
    if (!nmk)
        return NULL;

    nmk->worker_ctx.worker_fn = cfg->worker_fn;
    nmk->worker_ctx.worker_private = cfg->worker_private;
    nmk->worker_ctx.type = cfg->type;
    atomic_set(&nmk->scheduled, 0);

    /* attach kthread to user process (ptnetmap) */
    nmk->attach_user = cfg->attach_user;

    /* open event fd */
    error = nm_kthread_open_files(nmk, &cfg->event);
    if (error)
        goto err;

    nm_kthread_init_poll(nmk, &nmk->worker_ctx);

    return nmk;
err:
    //XXX: set errno?
    kfree(nmk);
    return NULL;
}

int
nm_os_kthread_start(struct nm_kthread *nmk)
{
    int error = 0;
    char name[16];

    if (nmk->worker) {
        return EBUSY;
    }

    /* check if we want to attach kthread to user process */
    if (nmk->attach_user) {
        nmk->mm = get_task_mm(current);
    }

    /* ToDo Make this able to pass arbitrary string (e.g., for 'nm_') from nmk */
    snprintf(name, sizeof(name), "nm_kthread-%ld-%d", nmk->worker_ctx.type, current->pid);
    nmk->worker = kthread_create(nm_kthread_worker, nmk, name);
    if (!IS_ERR(nmk->worker)) {
	kthread_bind(nmk->worker, nmk->affinity);
	wake_up_process(nmk->worker);
    }

    if (IS_ERR(nmk->worker)) {
	error = -PTR_ERR(nmk->worker);
	goto err;
    }

    if (nmk->worker_ctx.ioevent_file) {
	error = nm_kthread_start_poll(&nmk->worker_ctx, nmk->worker_ctx.ioevent_file);
	if (error) {
            goto err_kstop;
	}
    }

    return 0;
err_kstop:
    kthread_stop(nmk->worker);
err:
    nmk->worker = NULL;
    if (nmk->mm)
        mmput(nmk->mm);
    nmk->mm = NULL;
    return error;
}

void
nm_os_kthread_stop(struct nm_kthread *nmk)
{
    if (!nmk->worker) {
        return;
    }

    nm_kthread_stop_poll(&nmk->worker_ctx);

    if (nmk->worker) {
        kthread_stop(nmk->worker);
        nmk->worker = NULL;
    }

    if (nmk->mm) {
        mmput(nmk->mm);
        nmk->mm = NULL;
    }
}

void
nm_os_kthread_delete(struct nm_kthread *nmk)
{
    if (!nmk)
        return;

    if (nmk->worker) {
        nm_os_kthread_stop(nmk);
    }

    nm_kthread_close_files(nmk);

    kfree(nmk);
}

#define nm_os_pt_memdev_init()        0
#define nm_os_pt_memdev_uninit()


/* ########################## MODULE INIT ######################### */

struct miscdevice netmap_cdevsw = { /* same name as FreeBSD */
	MISC_DYNAMIC_MINOR,
	"netmap",
	&netmap_fops,
};


static int linux_netmap_init(void)
{
        int err;
        /* Errors have negative values on linux. */
        err = -netmap_init();
        if (err)
            return err;

	return nm_os_pt_memdev_init();
}


static void linux_netmap_fini(void)
{
        nm_os_pt_memdev_uninit();
        netmap_fini();
}

#ifndef NETMAP_LINUX_HAVE_LIVE_ADDR_CHANGE
#define IFF_LIVE_ADDR_CHANGE 0
#endif

#ifndef NETMAP_LINUX_HAVE_TX_SKB_SHARING
#define IFF_TX_SKB_SHARING 0
#endif

static struct device_driver linux_dummy_drv = {.owner = THIS_MODULE};

static int linux_nm_vi_open(struct net_device *netdev)
{
	netif_start_queue(netdev);
	return 0;
}

static int linux_nm_vi_stop(struct net_device *netdev)
{
	netif_stop_queue(netdev);
	return 0;
}
static int linux_nm_vi_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	if (skb != NULL)
		kfree_skb(skb);
	return 0;
}

#ifdef NETMAP_LINUX_HAVE_GET_STATS64
static struct rtnl_link_stats64 *linux_nm_vi_get_stats(
		struct net_device *netdev,
		struct rtnl_link_stats64 *stats)
{
	return stats;
}
#endif

static int linux_nm_vi_change_mtu(struct net_device *netdev, int new_mtu)
{
	return 0;
}
static void linux_nm_vi_destructor(struct net_device *netdev)
{
//	netmap_detach(netdev);
	free_netdev(netdev);
}
static const struct net_device_ops nm_vi_ops = {
	.ndo_open = linux_nm_vi_open,
	.ndo_stop = linux_nm_vi_stop,
	.ndo_start_xmit = linux_nm_vi_xmit,
	.ndo_set_mac_address = eth_mac_addr,
	.ndo_change_mtu = linux_nm_vi_change_mtu,
#ifdef NETMAP_LINUX_HAVE_GET_STATS64
	.ndo_get_stats64 = linux_nm_vi_get_stats,
#endif
};
/* dev->name is not initialized yet */
static void
linux_nm_vi_setup(struct ifnet *dev)
{
	ether_setup(dev);
	dev->netdev_ops = &nm_vi_ops;
	dev->priv_flags &= ~IFF_TX_SKB_SHARING;
	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE;
	dev->destructor = linux_nm_vi_destructor;
	dev->tx_queue_len = 0;
	/* XXX */
	dev->features = NETIF_F_LLTX | NETIF_F_SG | NETIF_F_FRAGLIST |
		NETIF_F_HIGHDMA | NETIF_F_HW_CSUM | NETIF_F_TSO;
#ifdef NETMAP_LINUX_HAVE_HW_FEATURES
	dev->hw_features = dev->features & ~NETIF_F_LLTX;
#endif
#ifdef NETMA_LINUX_HAVE_ADDR_RANDOM
	eth_hw_addr_random(dev);
#endif
}

int
nm_os_vi_persist(const char *name, struct ifnet **ret)
{
	struct ifnet *ifp;

	if (!try_module_get(linux_dummy_drv.owner))
		return EFAULT;
#ifdef NETMAP_LINUX_ALLOC_NETDEV_4ARGS
	ifp = alloc_netdev(0, name, NET_NAME_UNKNOWN, linux_nm_vi_setup);
#else
	ifp = alloc_netdev(0, name, linux_nm_vi_setup);
#endif
	if (!ifp) {
		module_put(linux_dummy_drv.owner);
		return ENOMEM;
	}
	dev_net_set(ifp, &init_net);
	ifp->features |= NETIF_F_NETNS_LOCAL; /* just for safety */
	register_netdev(ifp);
	ifp->dev.driver = &linux_dummy_drv;
	netif_start_queue(ifp);
	*ret = ifp;
	return 0;
}

void
nm_os_vi_detach(struct ifnet *ifp)
{
	netif_stop_queue(ifp);
	unregister_netdev(ifp);
	module_put(linux_dummy_drv.owner);
}

void
nm_os_selwakeup(NM_SELINFO_T *si)
{
	/* We use wake_up_interruptible() since select() and poll()
	 * sleep in an interruptbile way. */
	wake_up_interruptible(si);
}

void
nm_os_selrecord(NM_SELRECORD_T *sr, NM_SELINFO_T *si)
{
	poll_wait(sr->file, si, sr->pwait);
}

module_init(linux_netmap_init);
module_exit(linux_netmap_fini);

/* export certain symbols to other modules */
EXPORT_SYMBOL(netmap_attach);		/* driver attach routines */
EXPORT_SYMBOL(netmap_detach);		/* driver detach routines */
EXPORT_SYMBOL(netmap_ring_reinit);	/* ring init on error */
EXPORT_SYMBOL(netmap_reset);		/* ring init routines */
EXPORT_SYMBOL(netmap_rx_irq);	        /* default irq handler */
EXPORT_SYMBOL(netmap_no_pendintr);	/* XXX mitigation - should go away */
#ifdef WITH_VALE
EXPORT_SYMBOL(netmap_bdg_ctl);		/* bridge configuration routine */
EXPORT_SYMBOL(netmap_bdg_learning);	/* the default lookup function */
EXPORT_SYMBOL(netmap_bdg_name);		/* the bridge the vp is attached to */
#endif /* WITH_VALE */
EXPORT_SYMBOL(netmap_disable_all_rings);
EXPORT_SYMBOL(netmap_enable_all_rings);
EXPORT_SYMBOL(netmap_krings_create);


MODULE_AUTHOR("http://info.iet.unipi.it/~luigi/netmap/");
MODULE_DESCRIPTION("The netmap packet I/O framework");
MODULE_LICENSE("Dual BSD/GPL"); /* the code here is all BSD. */
