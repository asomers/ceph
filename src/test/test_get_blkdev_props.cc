#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "include/uuid.h"
#include "common/blkdev.h"

#define BUFSIZE	80

int main(int argc, char **argv)
{
	int fd, ret;
	int64_t size;
	bool discard_support;
	bool nvme;
	bool rotational;
	char dev[BUFSIZE];
	char model[BUFSIZE];
	char serial[BUFSIZE];
	char wholedisk[BUFSIZE];
	char partition[BUFSIZE];

	if (argc != 2) {
		fprintf(stderr, "usage: %s <blkdev>\n", argv[0]);
		return -1;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror("open");
		return -1;
	}

	BlkDev blkdev(fd);

	if ((ret = blkdev.get_block_device_size(&size)) < 0) {
		fprintf(stderr, "get_block_device_size: %s\n", strerror(-ret));
		return -1;
	}

	discard_support = blkdev.block_device_support_discard();

	nvme = blkdev.block_device_is_nvme();

	rotational = blkdev.block_device_is_rotational();

	if ((ret = blkdev.block_device_dev(dev, BUFSIZE)) < 0) {
		fprintf(stderr, "block_device_dev: %s\n", strerror(-ret));
		return -1;
	}

	if ((ret = blkdev.block_device_partition(partition, BUFSIZE)) < 0) {
		fprintf(stderr, "block_device_partition: %s\n", strerror(-ret));
		return -1;
	}

	if ((ret = blkdev.block_device_wholedisk(wholedisk, BUFSIZE)) < 0) {
		fprintf(stderr, "block_device_wholedisk: %s\n", strerror(-ret));
		return -1;
	}

	ret = blkdev.block_device_model(model, BUFSIZE);
	if (ret == -ENOENT) {
		snprintf(model, BUFSIZE, "Unknown");
	} else if (ret < 0) {
		fprintf(stderr, "block_device_model: %s\n", strerror(-ret));
		return -1;
	}

	ret = blkdev.block_device_serial(serial, BUFSIZE);
	if (ret == -ENOENT) {
		snprintf(serial, BUFSIZE, "Unknown");
	} else if (ret < 0) {
		fprintf(stderr, "block_device_serial: %s\n", strerror(-ret));
		return -1;
	}

	fprintf(stdout, "Size:\t\t%" PRId64 "\n", size);
	fprintf(stdout, "Discard:\t%s\n",
		discard_support ? "supported" : "not supported");
	fprintf(stdout, "NVME:\t\t%s\n", nvme ? "yes" : "no");
	fprintf(stdout, "Rotational:\t%s\n", rotational ? "yes" : "no");
	fprintf(stdout, "Dev:\t\t%s\n", dev);
	fprintf(stdout, "Whole disk:\t%s\n", wholedisk);
	fprintf(stdout, "Partition:\t%s\n", partition);
	fprintf(stdout, "Model:\t\t%s\n", model);
	fprintf(stdout, "Serial:\t\t%s\n", serial);

	return 0;
}
