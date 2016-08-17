/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall dynfilefs.c `pkg-config fuse --cflags --libs` -o dynfilefs
*/

#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <sys/mman.h>
#include <pthread.h>
#include <stdlib.h>

#define PACKED  __attribute__((packed))
#define ROUNDUP(a, b) (((a) + ((b)-1)) & ~((b)-1))
#define ROUNDDOWN(a, b) ((a) & ~((b)-1))
#define IS_ALIGNED(addr, size) (((uint64_t) (addr) & (size - 1)) == 0)
#define MIN(a,b) (((a)<(b))?(a):(b))

static const char *MAGIC_DATA_HDR  = "DyFsDATA";

typedef struct {
    char magic[8];
    uint64_t size;
    uint64_t blocksize;
    uint64_t num_allocated_blocks;
} PACKED dynfilefs_data_hdr_t;

static const char *dynfilefs_path = "/dynfilefs";
static char       *mount_source = NULL;
static int        found_mount_target = 0;
static uint64_t   file_size = 0;
static int        fd_data = -1;
static dynfilefs_data_hdr_t *datahdr = NULL;
static uint64_t   default_block_size = 4096;
static char       *zeroblock = NULL;
static uint64_t   *index_table = NULL;
static uint64_t   first_datablock_offset;
static pthread_mutex_t dynfilefs_mutex = PTHREAD_MUTEX_INITIALIZER;

static int dynfilefs_getattr(const char *path, struct stat *stbuf)
{
    int res = 0;

    memset(stbuf, 0, sizeof(struct stat));
    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
    } else if (strcmp(path, dynfilefs_path) == 0) {
        stbuf->st_mode = S_IFREG | 0444;
        stbuf->st_nlink = 1;
        stbuf->st_size = datahdr->size;
    } else
        res = -ENOENT;

    return res;
}

static int dynfilefs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                             off_t offset, struct fuse_file_info *fi)
{
    (void) offset;
    (void) fi;

    if (strcmp(path, "/") != 0)
        return -ENOENT;

    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    filler(buf, dynfilefs_path + 1, NULL, 0);

    return 0;
}

static int dynfilefs_open(const char *path, struct fuse_file_info *fi)
{
    (void)(fi);

    if (strcmp(path, dynfilefs_path) != 0)
        return -ENOENT;

    return 0;
}

static int dynfilefs_read(const char *path, char *buf, size_t _size, off_t _offset,
                          struct fuse_file_info *fi)
{
    (void) fi;
    off_t ret;

    if (strcmp(path, dynfilefs_path) != 0)
        return -ENOENT;

    uint64_t offset = (uint64_t) _offset;
    uint64_t size   = (uint64_t) _size;

    pthread_mutex_lock(&dynfilefs_mutex);

    uint64_t bytes_read = 0;
    if (offset < datahdr->size) {
        // trim size to prevent reading past our fixed file size
        if (offset + size > datahdr->size)
            size = datahdr->size - offset;

        uint64_t offset_aligned = ROUNDDOWN(offset, datahdr->blocksize);
        uint64_t read_offset = offset - offset_aligned;

        while (size>0) {
            uint64_t block_offset = offset_aligned/datahdr->blocksize;
            uint64_t read_size = MIN(datahdr->blocksize - read_offset, size);

            uint64_t phys_block_offset = index_table[block_offset];
            if (phys_block_offset==0 && block_offset!=0) {
                // block doesn't exist, copy zeroblock
                memcpy(buf, zeroblock + read_offset, read_size);
            }

            else {
                uint64_t phys_read_offset = first_datablock_offset + phys_block_offset*datahdr->blocksize;
                phys_read_offset += read_offset;

                // seek to block in file
                ret = lseek(fd_data, phys_read_offset, SEEK_SET);
                if (ret==(off_t)-1 || (uint64_t)ret!=phys_read_offset) {
                    if (ret!=(off_t)-1)
                        bytes_read += ret;
                    break;
                }

                // read block from file
                ret = read(fd_data, buf, read_size);
                if (ret==(off_t)-1 || (uint64_t)ret!=read_size) {
                    if (ret!=(off_t)-1)
                        bytes_read += ret;
                    break;
                }
            }

            buf += read_size;
            bytes_read += read_size;
            size -= read_size;
            read_offset = 0;
            offset_aligned += datahdr->blocksize;
        }
    }

    // can't read past our fixed file size
    else {
        bytes_read = 0;
    }

    pthread_mutex_unlock(&dynfilefs_mutex);
    return bytes_read;
}


static int dynfilefs_write(const char *path, const char *buf, size_t _size,
                           off_t _offset, struct fuse_file_info *fi)
{
    (void)(fi);
    off_t ret;

    if (strcmp(path, dynfilefs_path) != 0)
        return -ENOENT;

    uint64_t offset = (uint64_t) _offset;
    uint64_t size   = (uint64_t) _size;

    pthread_mutex_lock(&dynfilefs_mutex);

    uint64_t bytes_written = 0;
    if (offset < datahdr->size) {
        // trim size to prevent writing past our fixed file size
        if (offset + size > datahdr->size)
            size = datahdr->size - offset;

        uint64_t offset_aligned = ROUNDDOWN(offset, datahdr->blocksize);
        uint64_t write_offset = offset - offset_aligned;

        while (size>0) {
            uint64_t block_offset = offset_aligned/datahdr->blocksize;
            uint64_t write_size = MIN(datahdr->blocksize - write_offset, size);

            uint64_t phys_block_offset = index_table[block_offset];
            int is_new_block = 0;
            if (phys_block_offset==0 && block_offset!=0) {
                // skip if this block is filled with zeros only
                if (!memcmp(buf, zeroblock, write_size)) {
                    goto next_block;
                }

                // block doesn't exist, allocate one
                phys_block_offset = datahdr->num_allocated_blocks++;
                is_new_block = 1;
            }

            uint64_t phys_write_offset = first_datablock_offset + phys_block_offset*datahdr->blocksize;
            if (!is_new_block)
                phys_write_offset += write_offset;

            // seek to block in file
            ret = lseek(fd_data, phys_write_offset, SEEK_SET);
            if (ret==(off_t)-1 || (uint64_t)ret!=phys_write_offset) {
                if (ret!=(off_t)-1)
                    bytes_written += ret;
                break;
            }

            if (is_new_block && write_offset>0) {
                // write leading zeros
                ret = write(fd_data, zeroblock, write_offset);
                if (ret==(off_t)-1 || (uint64_t)ret!=write_offset) {
                    if (ret!=(off_t)-1)
                        bytes_written += ret;
                    break;
                }
            }

            // write data to file
            ret = write(fd_data, buf, write_size);
            if (ret==(off_t)-1 || (uint64_t)ret!=write_size) {
                if (ret!=(off_t)-1)
                    bytes_written += ret;
                break;
            }

            if (is_new_block) {
                uint64_t trailing_writesize = datahdr->blocksize-write_offset-write_size;
                // write trailing zeros
                if (trailing_writesize>0) {
                    ret = write(fd_data, zeroblock, trailing_writesize);
                    if (ret==(off_t)-1 || (uint64_t)ret!=trailing_writesize) {
                        if (ret!=(off_t)-1)
                            bytes_written += ret;
                        break;
                    }
                }

                // write new block to index table
                // we didn't do that previously, so we won't have an entry
                // to an incomplete block in case of an error
                index_table[block_offset] = phys_block_offset;
            }

next_block:
            buf += write_size;
            bytes_written += write_size;
            size -= write_size;
            write_offset = 0;
            offset_aligned += datahdr->blocksize;
        }
    }

    // can't write past our fixed file size
    else {
        bytes_written = 0;
    }

    pthread_mutex_unlock(&dynfilefs_mutex);
    return (int)bytes_written;
}

static int dynfilefs_fsync(const char *path, int isdatasync,
                           struct fuse_file_info *fi)
{
    (void) path;
    (void) isdatasync;
    (void) fi;
    fsync(fd_data);
    return 0;
}

static int dynfilefs_flush(const char *path, struct fuse_file_info *fi)
{
    (void) path;
    (void) fi;
    fsync(fd_data);
    return 0;
}

static struct fuse_operations dynfilefs_oper = {
    .getattr    = dynfilefs_getattr,
    .readdir    = dynfilefs_readdir,
    .open       = dynfilefs_open,
    .read       = dynfilefs_read,
    .write      = dynfilefs_write,
    .fsync      = dynfilefs_fsync,
    .flush      = dynfilefs_flush,
};

static int dynfilefs_opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs)
{
    (void)(data);
    (void)(outargs);

    if (key==FUSE_OPT_KEY_NONOPT && !mount_source) {
        mount_source = strdup(arg);
        return 0;
    } else if (key==FUSE_OPT_KEY_OPT && strlen(arg)>2 && arg[0]=='-' && arg[1]=='s') {
        sscanf(arg+2, "%llu", &file_size);
        return 0;
    }
    if (key==FUSE_OPT_KEY_NONOPT) {
        found_mount_target = 1;
    }

    return 1;
}

static int util_exists(const char *filename)
{
    struct stat buffer;
    return stat(filename, &buffer)==0;
}

int main(int argc, char *argv[])
{
    uint64_t i;
    int do_create = 0;
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    dynfilefs_data_hdr_t tmpdatahdr = {0};

    // parse args
    mount_source = NULL;
    fuse_opt_parse(&args, NULL, NULL, dynfilefs_opt_proc);

    if (!mount_source || !found_mount_target) {
        fprintf(stderr, "Usage: %s FILE DIRECTORY\n", argv[0]);
        return 1;
    }

    // check if file exists
    if (!util_exists(mount_source)) {
        do_create = 1;

        if (file_size==0) {
            fprintf(stderr, "file %s doesn't exist and no size given\n", mount_source);
            return 1;
        }

        // create file
        fd_data = open(mount_source, O_RDWR|O_CREAT, 0644);
    } else {
        // open existing file
        fd_data = open(mount_source, O_RDWR, 0644);
    }

    // opening error
    if (fd_data<0) {
        fprintf(stderr, "can't open %s: %s\n", mount_source, strerror(errno));
        return 1;
    }

    if (do_create) {
        // write header
        memcpy(tmpdatahdr.magic, MAGIC_DATA_HDR, sizeof(tmpdatahdr.magic));
        tmpdatahdr.blocksize = default_block_size;
        tmpdatahdr.size = ROUNDUP(file_size, tmpdatahdr.blocksize);
        tmpdatahdr.num_allocated_blocks = 1;
        if (write(fd_data, &tmpdatahdr, sizeof(tmpdatahdr))!=sizeof(tmpdatahdr)) {
            fprintf(stderr, "can't write to %s: %s\n", mount_source, strerror(errno));
            close(fd_data);
            return 1;
        }
    } else {
        // read header
        if (read(fd_data, &tmpdatahdr, sizeof(tmpdatahdr))!=sizeof(tmpdatahdr)) {
            fprintf(stderr, "can't read from %s: %s\n", mount_source, strerror(errno));
            close(fd_data);
            return 1;
        }

        // check magic
        if (memcmp(tmpdatahdr.magic, MAGIC_DATA_HDR, sizeof(tmpdatahdr.magic))) {
            fprintf(stderr, "invalid magic in %s\n", mount_source);
            close(fd_data);
            return 1;
        }

        // check size alignment
        if (!IS_ALIGNED(tmpdatahdr.size, tmpdatahdr.blocksize)) {
            fprintf(stderr, "size %llu is not a multiple of the blocksize(%llu)\n", tmpdatahdr.size, tmpdatahdr.blocksize);
            close(fd_data);
            return 1;
        }

        // check allocated block number
        if (tmpdatahdr.num_allocated_blocks<1 || tmpdatahdr.num_allocated_blocks>tmpdatahdr.size/tmpdatahdr.blocksize) {
            fprintf(stderr, "num_allocated_blocks %llu is invalid\n", tmpdatahdr.num_allocated_blocks);
            close(fd_data);
            return 1;
        }
    }

    // allocate zeroblock
    zeroblock = calloc(1, tmpdatahdr.blocksize);
    if (!zeroblock) {
        fprintf(stderr, "can't allocate zeroblock\n");
        close(fd_data);
        return 1;
    }

    if (do_create) {
        // create index table
        uint64_t n0 = 0;
        for (i=0; i<(tmpdatahdr.size/tmpdatahdr.blocksize); i++) {
            if (write(fd_data, &n0, sizeof(n0))!=sizeof(n0)) {
                fprintf(stderr, "can't write to %s: %s\n", mount_source, strerror(errno));
                close(fd_data);
                return 1;
            }
        }

        // first block 0
        if (write(fd_data, zeroblock, tmpdatahdr.blocksize)!=(ssize_t)tmpdatahdr.blocksize) {
            fprintf(stderr, "can't write to %s: %s\n", mount_source, strerror(errno));
            close(fd_data);
            return 1;
        }
    }

    // mmap index table
    uint64_t mmap_size = sizeof(dynfilefs_data_hdr_t) + (tmpdatahdr.size/tmpdatahdr.blocksize)*sizeof(uint64_t);
    void *map_addr = mmap(0, mmap_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd_data, 0);
    if (map_addr==MAP_FAILED) {
        fprintf(stderr, "can't mmap index table: %s\n", strerror(errno));
        close(fd_data);
        return 1;
    }
    datahdr = map_addr;
    index_table = map_addr + sizeof(dynfilefs_data_hdr_t);
    first_datablock_offset = mmap_size;

    // run fuse
    return fuse_main(args.argc, args.argv, &dynfilefs_oper, NULL);
}
