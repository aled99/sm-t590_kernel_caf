#undef TRACE_SYSTEM
#define TRACE_INCLUDE_PATH ../../drivers/staging/android/trace
#define TRACE_SYSTEM sync

#if !defined(_TRACE_SYNC_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_SYNC_H

#include <linux/sync.h>
#include <linux/tracepoint.h>

TRACE_EVENT(sync_timeline,
	TP_PROTO(struct sync_timeline *timeline),

	TP_ARGS(timeline),

	TP_STRUCT__entry(
			__string(name, timeline->name)
			__array(char, value, 32)
	),

	TP_fast_assign(
			__assign_str(name, timeline->name);
			if (timeline->ops->timeline_value_str) {
				timeline->ops->timeline_value_str(timeline,
							__entry->value,
							sizeof(__entry->value));
			} else {
				__entry->value[0] = '\0';
			}
	),

	TP_printk("name=%s value=%s", __get_str(name), __entry->value)
);

TRACE_EVENT(sync_wait,
	TP_PROTO(struct sync_fence *fence, int begin),

	TP_ARGS(fence, begin),

	TP_STRUCT__entry(
			__string(name, fence->name)
			__field(s32, status)
			__field(u32, begin)
	),

	TP_fast_assign(
			__assign_str(name, fence->name);
			__entry->status = fence->status;
			__entry->begin = begin;
	),

	TP_printk("%s name=%s state=%d", __entry->begin ? "begin" : "end",
			__get_str(name), __entry->status)
);

TRACE_EVENT(sync_pt,
	TP_PROTO(struct sync_pt *pt),

	TP_ARGS(pt),

	TP_STRUCT__entry(
		__string(timeline, pt->parent->name)
		__array(char, value, 32)
	),

	TP_fast_assign(
		__assign_str(timeline, pt->parent->name);
		if (pt->parent->ops->pt_value_str) {
			pt->parent->ops->pt_value_str(pt, __entry->value,
							sizeof(__entry->value));
		} else {
			__entry->value[0] = '\0';
		}
	),

static void sync_fence_signal_pt(struct sync_pt *pt)
{
	LIST_HEAD(signaled_waiters);
	struct sync_fence *fence = pt->fence;
	struct list_head *pos;
	struct list_head *n;
	unsigned long flags;
	int status;

	status = sync_fence_get_status(fence);

	spin_lock_irqsave(&fence->waiter_list_lock, flags);
	/*
	 * this should protect against two threads racing on the signaled
	 * false -> true transition
	 */
	if (status && !fence->status) {
		list_for_each_safe(pos, n, &fence->waiter_list_head)
			list_move(pos, &signaled_waiters);

		fence->status = status;
	} else {
		status = 0;
	}
	spin_unlock_irqrestore(&fence->waiter_list_lock, flags);

	if (status) {
		list_for_each_safe(pos, n, &signaled_waiters) {
			struct sync_fence_waiter *waiter =
				container_of(pos, struct sync_fence_waiter,
					     waiter_list);

			list_del(pos);
			waiter->callback(fence, waiter);
		}
		wake_up(&fence->wq);
	}
}

int sync_fence_wait_async(struct sync_fence *fence,
			  struct sync_fence_waiter *waiter)
{
	unsigned long flags;
	int err = 0;

	spin_lock_irqsave(&fence->waiter_list_lock, flags);

	if (fence->status) {
		err = fence->status;
		goto out;
	}

	list_add_tail(&waiter->waiter_list, &fence->waiter_list_head);
out:
	spin_unlock_irqrestore(&fence->waiter_list_lock, flags);

	return err;
}
EXPORT_SYMBOL(sync_fence_wait_async);

int sync_fence_cancel_async(struct sync_fence *fence,
			     struct sync_fence_waiter *waiter)
{
	struct list_head *pos;
	struct list_head *n;
	unsigned long flags;
	int ret = -ENOENT;

	spin_lock_irqsave(&fence->waiter_list_lock, flags);
	/*
	 * Make sure waiter is still in waiter_list because it is possible for
	 * the waiter to be removed from the list while the callback is still
	 * pending.
	 */
	list_for_each_safe(pos, n, &fence->waiter_list_head) {
		struct sync_fence_waiter *list_waiter =
			container_of(pos, struct sync_fence_waiter,
				     waiter_list);
		if (list_waiter == waiter) {
			list_del(pos);
			ret = 0;
			break;
		}
	}
	spin_unlock_irqrestore(&fence->waiter_list_lock, flags);
	return ret;
}
EXPORT_SYMBOL(sync_fence_cancel_async);

static bool sync_fence_check(struct sync_fence *fence)
{
	/*
	 * Make sure that reads to fence->status are ordered with the
	 * wait queue event triggering
	 */
	smp_rmb();
	return fence->status != 0;
}

int sync_fence_wait(struct sync_fence *fence, long timeout)
{
	int err = 0;
	struct sync_pt *pt;

	trace_sync_wait(fence, 1);
	list_for_each_entry(pt, &fence->pt_list_head, pt_list)
		trace_sync_pt(pt);

	if (timeout > 0) {
		timeout = msecs_to_jiffies(timeout);
		err = wait_event_interruptible_timeout(fence->wq,
						       sync_fence_check(fence),
						       timeout);
	} else if (timeout < 0) {
		err = wait_event_interruptible(fence->wq,
					       sync_fence_check(fence));
	}
	trace_sync_wait(fence, 0);

	if (err < 0)
		return err;

	if (fence->status < 0) {
		pr_info("fence error %d on [%pK]\n", fence->status, fence);
		sync_dump();
		return fence->status;
	}

	if (fence->status == 0) {
		if (timeout > 0) {
			pr_info("fence timeout on [%pK] after %dms\n", fence,
				jiffies_to_msecs(timeout));
			sync_dump();
		}
		return -ETIME;
	}

	return 0;
}
EXPORT_SYMBOL(sync_fence_wait);

static void sync_fence_free(struct kref *kref)
{
	struct sync_fence *fence = container_of(kref, struct sync_fence, kref);

	sync_fence_free_pts(fence);

	kfree(fence);
}

static int sync_fence_release(struct inode *inode, struct file *file)
{
	struct sync_fence *fence = file->private_data;
	unsigned long flags;

	/*
	 * We need to remove all ways to access this fence before droping
	 * our ref.
	 *
	 * start with its membership in the global fence list
	 */
	spin_lock_irqsave(&sync_fence_list_lock, flags);
	list_del(&fence->sync_fence_list);
	spin_unlock_irqrestore(&sync_fence_list_lock, flags);

	/*
	 * remove its pts from their parents so that sync_timeline_signal()
	 * can't reference the fence.
	 */
	sync_fence_detach_pts(fence);

	kref_put(&fence->kref, sync_fence_free);

	return 0;
}

static unsigned int sync_fence_poll(struct file *file, poll_table *wait)
{
	struct sync_fence *fence = file->private_data;

	poll_wait(file, &fence->wq, wait);

	/*
	 * Make sure that reads to fence->status are ordered with the
	 * wait queue event triggering
	 */
	smp_rmb();

	if (fence->status == 1)
		return POLLIN;
	else if (fence->status < 0)
		return POLLERR;
	else
		return 0;
}

static long sync_fence_ioctl_wait(struct sync_fence *fence, unsigned long arg)
{
	__s32 value;

	if (copy_from_user(&value, (void __user *)arg, sizeof(value)))
		return -EFAULT;

	return sync_fence_wait(fence, value);
}

static long sync_fence_ioctl_merge(struct sync_fence *fence, unsigned long arg)
{
	int fd = get_unused_fd_flags(O_CLOEXEC);
	int err;
	struct sync_fence *fence2, *fence3;
	struct sync_merge_data data;

	if (fd < 0)
		return fd;

	if (copy_from_user(&data, (void __user *)arg, sizeof(data))) {
		err = -EFAULT;
		goto err_put_fd;
	}

	fence2 = sync_fence_fdget(data.fd2);
	if (fence2 == NULL) {
		err = -ENOENT;
		goto err_put_fd;
	}

	data.name[sizeof(data.name) - 1] = '\0';
	fence3 = sync_fence_merge(data.name, fence, fence2);
	if (fence3 == NULL) {
		err = -ENOMEM;
		goto err_put_fence2;
	}

	data.fence = fd;
	if (copy_to_user((void __user *)arg, &data, sizeof(data))) {
		err = -EFAULT;
		goto err_put_fence3;
	}

	sync_fence_install(fence3, fd);
	sync_fence_put(fence2);
	return 0;

err_put_fence3:
	sync_fence_put(fence3);

err_put_fence2:
	sync_fence_put(fence2);

err_put_fd:
	put_unused_fd(fd);
	return err;
}

static int sync_fill_pt_info(struct sync_pt *pt, void *data, int size)
{
	struct sync_pt_info *info = data;
	int ret;

	if (size < sizeof(struct sync_pt_info))
		return -ENOMEM;

	info->len = sizeof(struct sync_pt_info);

	if (pt->parent->ops->fill_driver_data) {
		ret = pt->parent->ops->fill_driver_data(pt, info->driver_data,
							size - sizeof(*info));
		if (ret < 0)
			return ret;

		info->len += ret;
	}

	strlcpy(info->obj_name, pt->parent->name, sizeof(info->obj_name));
	strlcpy(info->driver_name, pt->parent->ops->driver_name,
		sizeof(info->driver_name));
	info->status = pt->status;
	info->timestamp_ns = ktime_to_ns(pt->timestamp);

	return info->len;
}

static long sync_fence_ioctl_fence_info(struct sync_fence *fence,
					unsigned long arg)
{
	struct list_head *pos;
	u8 data_buf[4096] __aligned(sizeof(long));
	struct sync_fence_info_data *data = (typeof(data))data_buf;
	__u32 size;
	__u32 len = 0;
	int ret;

	if (copy_from_user(&size, (void __user *)arg, sizeof(size)))
		return -EFAULT;

	if (size < sizeof(struct sync_fence_info_data))
		return -EINVAL;

	if (size > 4096)
		size = 4096;

#ifdef CONFIG_SYNC_DEBUG
	strlcpy(data->name, fence->name, sizeof(data->name));
	data->status = fence->status;
#endif
	len = sizeof(struct sync_fence_info_data);

	list_for_each(pos, &fence->pt_list_head) {
		struct sync_pt *pt =
			container_of(pos, struct sync_pt, pt_list);

		ret = sync_fill_pt_info(pt, (u8 *)data + len, size - len);

		if (ret < 0)
			goto out;

		len += ret;
	}

	data->len = len;

	if (copy_to_user((void __user *)arg, data, len))
		ret = -EFAULT;
	else
		ret = 0;

out:
	return ret;
}

static long sync_fence_ioctl(struct file *file, unsigned int cmd,
			     unsigned long arg)
{
	struct sync_fence *fence = file->private_data;

	switch (cmd) {
	case SYNC_IOC_WAIT:
		return sync_fence_ioctl_wait(fence, arg);

	case SYNC_IOC_MERGE:
		return sync_fence_ioctl_merge(fence, arg);

	case SYNC_IOC_FENCE_INFO:
		return sync_fence_ioctl_fence_info(fence, arg);

	default:
		return -ENOTTY;
	}
}

#ifdef CONFIG_DEBUG_FS
static const char *sync_status_str(int status)
{
	if (status > 0)
		return "signaled";
	else if (status == 0)
		return "active";
	else
		return "error";
}

static void sync_print_pt(struct seq_file *s, struct sync_pt *pt, bool fence)
{
	int status = pt->status;

	seq_printf(s, "  %s%spt %s",
		   fence ? pt->parent->name : "",
		   fence ? "_" : "",
		   sync_status_str(status));
	if (pt->status) {
		struct timeval tv = ktime_to_timeval(pt->timestamp);

		seq_printf(s, "@%ld.%06ld", tv.tv_sec, tv.tv_usec);
	}

	if (pt->parent->ops->timeline_value_str &&
	    pt->parent->ops->pt_value_str) {
		char value[64];

		pt->parent->ops->pt_value_str(pt, value, sizeof(value));
		seq_printf(s, ": %s", value);
		if (fence) {
			pt->parent->ops->timeline_value_str(pt->parent, value,
						    sizeof(value));
			seq_printf(s, " / %s", value);
		}
	} else if (pt->parent->ops->print_pt) {
		seq_puts(s, ": ");
		pt->parent->ops->print_pt(s, pt);
	}

	seq_puts(s, "\n");
}

static void sync_print_obj(struct seq_file *s, struct sync_timeline *obj)
{
	struct list_head *pos;
	unsigned long flags;

	seq_printf(s, "%s %s", obj->name, obj->ops->driver_name);

	if (obj->ops->timeline_value_str) {
		char value[64];

		obj->ops->timeline_value_str(obj, value, sizeof(value));
		seq_printf(s, ": %s", value);
	} else if (obj->ops->print_obj) {
		seq_puts(s, ": ");
		obj->ops->print_obj(s, obj);
	}

	seq_puts(s, "\n");

	spin_lock_irqsave(&obj->child_list_lock, flags);
	list_for_each(pos, &obj->child_list_head) {
		struct sync_pt *pt =
			container_of(pos, struct sync_pt, child_list);
		sync_print_pt(s, pt, false);
	}
	spin_unlock_irqrestore(&obj->child_list_lock, flags);
}

static void sync_print_fence(struct seq_file *s, struct sync_fence *fence)
{
	struct list_head *pos;
	unsigned long flags;

	seq_printf(s, "[%pK] %s: %s\n", fence, fence->name,
		   sync_status_str(fence->status));

	list_for_each(pos, &fence->pt_list_head) {
		struct sync_pt *pt =
			container_of(pos, struct sync_pt, pt_list);
		sync_print_pt(s, pt, true);
	}

	spin_lock_irqsave(&fence->waiter_list_lock, flags);
	list_for_each(pos, &fence->waiter_list_head) {
		struct sync_fence_waiter *waiter =
			container_of(pos, struct sync_fence_waiter,
				     waiter_list);

		seq_printf(s, "waiter %pF\n", waiter->callback);
	}
	spin_unlock_irqrestore(&fence->waiter_list_lock, flags);
}

	TP_printk("name=%s value=%s", __get_str(timeline), __entry->value)
);

#endif /* if !defined(_TRACE_SYNC_H) || defined(TRACE_HEADER_MULTI_READ) */

/* This part must be outside protection */
#include <trace/define_trace.h>

