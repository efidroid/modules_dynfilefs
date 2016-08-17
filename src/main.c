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

#define PACKED  __attribute__((packed))
#define ROUNDUP(a, b) (((a) + ((b)-1)) & ~((b)-1))
#define ROUNDDOWN(a, b) ((a) & ~((b)-1))
#define IS_ALIGNED(addr, size) (((uint64_t) (addr) & (size - 1)) == 0)
#define MIN(a,b) (((a)<(b))?(a):(b))

static const char *MAGIC_DATA_HDR  = "DyFsDATA";

typedef struct {
    char magic[8];
    uint64_t size;
    uint32_t blocksize;
    uint32_t reserved[3];
} PACKED dynfilefs_data_hdr_t;

static const char *dynfilefs_path = "/dynfilefs";
static char       *mount_source = NULL;
static int        found_mount_target = 0;
static uint64_t   file_size = 0;
static int        fd_data = -1;
static dynfilefs_data_hdr_t datahdr = {0};
static uint32_t   default_block_size = 4096;
static char       *zeroblock = NULL;
static uint64_t   *index_table = NULL;
static uint64_t   first_datablock_offset;

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
        stbuf->st_size = datahdr.size;
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
    if (strcmp(path, dynfilefs_path) != 0)
        return -ENOENT;

    if ((fi->flags & 3) != O_RDONLY)
        return -EACCES;

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

    uint64_t bytes_read = 0;
    if (offset < datahdr.size) {
        // trim size to prevent reading past our fixed file size
        if (offset + size > datahdr.size)
            size = datahdr.size - offset;

        uint64_t offset_aligned = ROUNDDOWN(offset, datahdr.blocksize);
        uint64_t read_offset = offset - offset_aligned;

        while (size>0) {
            uint64_t block_offset = offset_aligned/datahdr.blocksize;
            uint64_t read_size = MIN(datahdr.blocksize - read_offset, size);

            uint64_t phys_block_offset = index_table[block_offset];
            if (phys_block_offset==0 && offset_aligned!=0) {
                //fprintf(stderr, "ZERO: %llu\n", block_offset);
                // block doesn't exist, copy zeroblock
                memcpy(buf, zeroblock + read_offset, read_size);
            }

            else {
                phys_block_offset += first_datablock_offset;
                //fprintf(stderr, "READ: %llu\n", phys_block_offset);

                // seek to block in file
                ret = lseek(fd_data, phys_block_offset, SEEK_SET);
                if (ret==(off_t)-1 || (uint64_t)ret!=phys_block_offset) {
                    fprintf(stderr, "seek error\n");

                    if (ret!=(off_t)-1)
                        bytes_read += ret;
                    break;
                }

                // read block from file
                ret = read(fd_data, buf, read_size);
                if (ret==(off_t)-1 || (uint64_t)ret!=read_size) {
                    fprintf(stderr, "read error\n");

                    if (ret!=(off_t)-1)
                        bytes_read += ret;
                    break;
                }
            }

            buf += read_size;
            bytes_read += read_size;
            size -= read_size;
            read_offset = 0;
            offset_aligned += datahdr.blocksize;
        }
    }

    // can't read past our fixed file size
    else {
        bytes_read = 0;
    }

    return bytes_read;
}

static struct fuse_operations dynfilefs_oper = {
    .getattr    = dynfilefs_getattr,
    .readdir    = dynfilefs_readdir,
    .open       = dynfilefs_open,
    .read       = dynfilefs_read,
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

    // parse args
    memset(&datahdr, 0, sizeof(datahdr));
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
        memcpy(datahdr.magic, MAGIC_DATA_HDR, sizeof(datahdr.magic));
        datahdr.blocksize = default_block_size;
        datahdr.size = ROUNDUP(file_size, datahdr.blocksize);
        if (write(fd_data, &datahdr, sizeof(datahdr))!=sizeof(datahdr)) {
            fprintf(stderr, "can't write to %s: %s\n", mount_source, strerror(errno));
            close(fd_data);
            return 1;
        }
    } else {
        // read header
        if (read(fd_data, &datahdr, sizeof(datahdr))!=sizeof(datahdr)) {
            fprintf(stderr, "can't read from %s: %s\n", mount_source, strerror(errno));
            close(fd_data);
            return 1;
        }

        // check magic
        if (memcmp(datahdr.magic, MAGIC_DATA_HDR, sizeof(datahdr.magic))) {
            fprintf(stderr, "invalid magic in %s\n", mount_source);
            close(fd_data);
            return 1;
        }

        // check size alignment
        if (!IS_ALIGNED(datahdr.size, datahdr.blocksize)) {
            fprintf(stderr, "size %llu is not a multiple of the blocksize(%u)\n", datahdr.size, datahdr.blocksize);
            close(fd_data);
            return 1;
        }
    }

    // allocate zeroblock
    zeroblock = calloc(1, datahdr.blocksize);
    if (!zeroblock) {
        fprintf(stderr, "can't allocate zeroblock\n");
        close(fd_data);
        return 1;
    }

    if (do_create) {
        // create index table
        uint64_t n0 = 0;
        for (i=0; i<(datahdr.size/datahdr.blocksize); i++) {
            if (write(fd_data, &n0, sizeof(n0))!=sizeof(n0)) {
                fprintf(stderr, "can't write to %s: %s\n", mount_source, strerror(errno));
                close(fd_data);
                return 1;
            }
        }

        // first block 0
        if (write(fd_data, zeroblock, datahdr.blocksize)!=(ssize_t)datahdr.blocksize) {
            fprintf(stderr, "can't write to %s: %s\n", mount_source, strerror(errno));
            close(fd_data);
            return 1;
        }
    }

    // mmap index table
    uint64_t index_table_size = (datahdr.size/datahdr.blocksize)*sizeof(uint64_t);
    void *map_addr = mmap(0, index_table_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd_data, 0);
    if (map_addr==MAP_FAILED) {
        fprintf(stderr, "can't mmap index table: %s\n", strerror(errno));
        close(fd_data);
        return 1;
    }
    index_table = map_addr + sizeof(dynfilefs_data_hdr_t);
    first_datablock_offset = sizeof(dynfilefs_data_hdr_t) + index_table_size;

    // run fuse
    return fuse_main(args.argc, args.argv, &dynfilefs_oper, NULL);
}
