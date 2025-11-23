
#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "raw_device_ctrl.h"

ssize_t raw_read(const char *dev, void *buf, size_t size, off_t offset)
{
    int fd;
    ssize_t ret = -1;


    fd = open(dev, O_RDONLY);
    if(fd < 0) {
        fprintf(stderr, "open %s: %s \n", dev, strerror(errno));
        goto errdone;
    }


    ret = pread(fd, buf, size, offset);
    if(ret < 0) {
        fprintf(stderr, "pread : %s \n", strerror(errno));
        goto errdone;
    }

errdone:
    if(fd > 0) { 
        close(fd);
    }

    return ret;

}

ssize_t raw_write(const char *dev, const void *buf, size_t size, off_t offset)
{
    int fd;
    ssize_t ret = -1;

    fd = open(dev, O_WRONLY | O_SYNC);
    if(fd < 0) {
        fprintf(stderr, "open %s: %s\n", dev, strerror(errno));
        goto errdone;
    }

    hex_dump("write image", buf, size);

    ret = pwrite(fd, buf, size, offset);
    if(ret < 0) {
        fprintf(stderr, "pwrite: %s \n", strerror(errno));
        goto errdone;
    }

    fsync(fd);

errdone:

    if(fd > 0) {
        close(fd);
    }

    return ret;
}

//0x00000000 : [ 4 bytes ] = file_size
//0x00000004 : [ file contents ... ] (512-byte aligned)
int copy_file_to_raw(const char *dev, const char *file)
{
    int fd;
    struct stat st;
    size_t file_size;
    size_t done = 0;
    ssize_t ret;

    unsigned char blk[BLK_SIZE];

    /* get file size */
    if (stat(file, &st) < 0) {
        fprintf(stderr, "stat(%s): %s\n", file, strerror(errno));
        return -1;
    }
    file_size = st.st_size;

    /* open file */
    fd = open(file, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "open(%s): %s\n", file, strerror(errno));
        return -1;
    }

    /*
     * 1) write 4-byte file size header at offset 0
     */
    uint32_t hdr = (uint32_t)file_size;   /* endian 변환 없음 */

    ret = raw_write(dev, &hdr, sizeof(hdr), 0);
    if (ret < 0) {
        fprintf(stderr, "raw_write(%s, hdr): %s\n",
                dev, strerror(errno));
        close(fd);
        return -1;
    }
    if (ret != sizeof(hdr)) {
        fprintf(stderr, "raw_write(hdr): partial write %zd/4\n", ret);
        close(fd);
        return -1;
    }

    /*
     * 2) file → raw device (offset starts at 4)
     */
    off_t dst_offset = 4;

    while (done < file_size) {

        size_t to_read = BLK_SIZE;
        size_t remain = file_size - done;

        if (remain < BLK_SIZE)
            to_read = remain;

        /* read block from file */
        ret = read(fd, blk, to_read);
        if (ret < 0) {
            fprintf(stderr, "read(%s): %s\n", file, strerror(errno));
            close(fd);
            return -1;
        }
        if ((size_t)ret != to_read) {
            fprintf(stderr, "file partial read %zd/%zu\n",
                    ret, to_read);
            close(fd);
            return -1;
        }

        /* pad last block */
        if (to_read < BLK_SIZE)
            memset(blk + to_read, 0, BLK_SIZE - to_read);

        /* write block to raw */
        ret = raw_write(dev, blk, BLK_SIZE, dst_offset + done);
        if (ret < 0) {
            fprintf(stderr, "raw_write(%s): %s\n", dev, strerror(errno));
            close(fd);
            return -1;
        }
        if (ret != BLK_SIZE) {
            fprintf(stderr, "raw_write: partial write %zd/%d\n",
                    ret, BLK_SIZE);
            close(fd);
            return -1;
        }

        done += BLK_SIZE;
    }

    close(fd);
    return 0;
}



int copy_raw_to_raw(const char *src_dev, const char *dst_dev,
               off_t src_offset, off_t dst_offset,
               size_t copy_size)
{
    unsigned char blk[BLK_SIZE];
    size_t done = 0;
    ssize_t ret;

    while (done < copy_size) {

        size_t to_read = BLK_SIZE;
        size_t remain = copy_size - done;

        /* last block process */
        if (remain < BLK_SIZE)
            to_read = remain;

        /* read from source raw */
        ret = raw_read(src_dev, blk, to_read, src_offset + done);
        if (ret < 0) {
            fprintf(stderr, "raw_read(%s): %s\n",
                    src_dev, strerror(errno));
            return -1;
        }
        if ((size_t)ret != to_read) {
            fprintf(stderr, "raw_read: partial read %zd/%zu\n",
                    ret, to_read);
            return -1;
        }

        /* zero-fill to 512B if last block < 512 */
        if (to_read < BLK_SIZE)
            memset(blk + to_read, 0, BLK_SIZE - to_read);

        /* write to destination raw (always BLK_SIZE) */
        ret = raw_write(dst_dev, blk, BLK_SIZE, dst_offset + done);
        if (ret < 0) {
            fprintf(stderr, "raw_write(%s): %s\n",
                    dst_dev, strerror(errno));
            return -1;
        }
        if ((size_t)ret != BLK_SIZE) {
            fprintf(stderr, "raw_write: partial write %zd/%d\n",
                    ret, BLK_SIZE);
            return -1;
        }

        done += BLK_SIZE;
    }

    return 0;
}


int raw_read_u32(const char *dev, off_t offset, uint32_t *out)
{
    ssize_t ret;
    uint32_t val = 0;

    if (!out)
        return -1;

    ret = raw_read(dev, &val, sizeof(val), offset);
    if (ret < 0) {
        fprintf(stderr, "raw_read(%s): %s\n",
                dev, strerror(errno));
        return -1;
    }

    if (ret != sizeof(val)) {
        fprintf(stderr, "raw_read_u32: partial read %zd/4 bytes\n", ret);
        return -1;
    }

    *out = val;   

    return 0;
}

