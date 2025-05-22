// SPDX-License-Identifier: GPL-2.0

#include <linux/perf_event.h>

/* only support 1 counter in read mode, no sampling */
int setup_hw_perfctr(__u64 config, int cpu, struct perf_event **event)
{
	static struct perf_event_attr attr = {
		.type           = PERF_TYPE_HARDWARE,
		.size           = sizeof(struct perf_event_attr),
		.pinned         = 1,
		.disabled       = 1,
	};
	struct perf_event *ev;

	attr.config = config;

	ev = perf_event_create_kernel_counter(&attr, cpu, NULL, NULL, NULL);
	if (IS_ERR(ev)) {
		int err = PTR_ERR(ev);

		pr_err("Failed to create kernel counter %llu on cpu %d: %d\n",
			config, cpu, err);
		return err;
	}

	*event = ev;

	return 0;
}

void teardown_perfctr(struct perf_event *event)
{
	perf_event_release_kernel(event);
}


/* read counter */
static inline u64 read_perfctr(struct perf_event *event)
{
	u64 enabled, running;

	return perf_event_read_value(event, &enabled, &running);
}


/* enable the event */
perf_event_enable(event);

/* disable event */
perf_event_disable(event);
