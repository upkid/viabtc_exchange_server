/*
 * Description: misc functions
 *     History: yang@haipo.me, 2016/03/15, create
 */

# ifndef _GNU_SOURCE
# define _GNU_SOURCE
# endif

# include <stdio.h>
# include <stdint.h>
# include <string.h>
# include <stdlib.h>
# include <stdarg.h>
# include <stdbool.h>
# include <limits.h>
# include <ctype.h>
# include <math.h>
# include <errno.h>
# include <unistd.h>
# include <signal.h>
# include <fcntl.h>
# include <sys/types.h>
# include <sys/stat.h>
# include <sys/wait.h>
# include <sys/time.h>
# include <sys/file.h>
# include <sys/resource.h>

# include "ut_misc.h"
# include "ut_signal.h"

int process_exist(const char *fmt, ...)
{
    // PATH_MAX 是一个预定义的宏，表示文件路径名的最大长度。在 Linux 系统中，PATH_MAX 的默认值为 4096。
    char name[PATH_MAX];
	va_list ap;
    va_start(ap, fmt);
    vsnprintf(name, sizeof(name), fmt, ap);
    va_end(ap);

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/tmp/%s.lock", name);

    int fd = open(path, O_CREAT, 400);
    if (fd < 0)
        return -1;
    if (flock(fd, LOCK_EX | LOCK_NB) < 0)
        return 1;

    return 0;
}

int process_keepalive(void)
{
    while (true) {
        int pid = fork();
        if (pid < 0) {
            log_error("fork error: %d: %s", pid, strerror(errno));
            return -1;
        } else if (pid == 0 ) {
            init_signal();
            return 0;
        } else {
            init_signal();
            signal(SIGCHLD, SIG_DFL);
            signal(SIGUSR1, SIG_IGN);
            signal(SIGTTIN, SIG_IGN);
            signal(SIGTTOU, SIG_IGN);
            int status = 0;
            int ret = waitpid(pid, &status, 0);
            if (ret < 0) {
                if (signal_exit) {
                    exit(EXIT_SUCCESS);
                } else {
                    log_error("waitpid: %d error: %d: %s", pid, ret, strerror(errno));
                    exit(EXIT_FAILURE);
                }
            }
            if (WIFEXITED(status)) {
                exit(EXIT_SUCCESS);
            } else if (WIFSIGNALED(status)) {
                log_fatal("process: %d, name: %s terminated by signal: '%s'", \
                        pid, program_invocation_short_name, strsignal(WTERMSIG(status)));
                usleep(1000 * 1000);
                continue;
            } else {
                log_error("process: %d terminated, waitpid status: %d\n", pid, status);
                exit(EXIT_FAILURE);
            }
        }
    }

    return -1;
}

int set_core_limit(size_t limit)
{
    struct rlimit rlim;
    memset(&rlim, 0, sizeof(rlim));
    if (getrlimit(RLIMIT_CORE, &rlim) < 0) {
        return -1;
    }
    if (rlim.rlim_cur >= limit)
        return 0;
    rlim.rlim_cur = limit;
    rlim.rlim_max = limit;
    if (setrlimit(RLIMIT_CORE, &rlim) < 0) {
        return -1;
    }

    return 0;
}

int set_file_limit(size_t limit)
{
    struct rlimit rlim;
    memset(&rlim, 0, sizeof(rlim));
    if (getrlimit(RLIMIT_NOFILE, &rlim) < 0) {
        return -1;
    }
    if (rlim.rlim_cur >= limit)
        return 0;
    rlim.rlim_cur = limit;
    rlim.rlim_max = limit;
    if (setrlimit(RLIMIT_NOFILE, &rlim) < 0) {
        return -1;
    }

    return 0;
}

sds hexdump(const void *mem, size_t len)
{
    uint8_t *data = (uint8_t *)mem;
    size_t pos = 0;
    sds result = sdsempty();

    while (pos < len) {
        char line[100];
        size_t ret = 0;
        size_t left   = len - pos;
        size_t num    = left >= 16 ? 16 : left;
        size_t group  = num / 2;
        size_t single = num % 2;
        const char *start = (char *)(data + pos);

        ret += snprintf(line + ret, sizeof(line) - ret, "0x%04zx:  ", pos);
        for (size_t i = 0; i < group; ++i) {
            uint8_t const *curr = data + pos;
            ret += snprintf(line + ret, sizeof(line) - ret,  \
                    "%02x%02x ", curr[0], curr[1]);
            pos += 2;
        }
        if (group != 8) {
            if (single) {
                ret += snprintf(line + ret, sizeof(line) - ret, \
                        "%02x   ", data[pos++]);
            }
            size_t blank = 8 - group - single;
            for (size_t i = 0; i < blank; ++i) {
                ret += snprintf(line + ret, sizeof(line) - ret, "     ");
            }
        }
        ret += snprintf(line + ret, sizeof(line) - ret, " ");
        for (size_t i = 0; i < num; ++i) {
            char c = start[i];
            ret += snprintf(line + ret, sizeof(line) - ret, "%c", \
                    (c > (char)0x20 && c < (char)0x7f) ? c : '.');
        }
        if (pos < len) {
            snprintf(line + ret, sizeof(line) - ret, "\n");
        }

        result = sdscat(result, line);
    }

    return result;
}

sds bin2hex(const void *mem, size_t len)
{
    static char hex[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    };
    sds result = sdsempty();
    for (size_t i = 0; i < len; ++i) {
        char s[2];
        uint8_t c = *(uint8_t *)(mem + i);
        s[0] = hex[(c & 0xf0) >> 4];
        s[1] = hex[(c & 0x0f)];
        result = sdscatlen(result, s, 2);
    }
    return result;
}

static int hex2int(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

sds hex2bin(const char *hex)
{
    size_t len = strlen(hex);
    if (len % 2 != 0)
        return NULL;

    sds result = sdsempty();
    size_t step = len / 2;
    for (size_t i = 0; i < step; ++i) {
        int part1 = hex2int(hex[i * 2]);
        if (part1 < 0) {
            sdsfree(result);
            return NULL;
        }
        int part2 = hex2int(hex[i * 2 + 1]);
        if (part2 < 0) {
            sdsfree(result);
            return NULL;
        }
        uint8_t c = ((uint8_t)part1) << 4 | (uint8_t)part2;
        result = sdscatlen(result, &c, 1);
    }

    return result;
}

double current_timestamp(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + tv.tv_usec / 1000000.0;
}

char *strftimestamp(time_t t)
{
    static char str[64];
    struct tm *tm = localtime(&t);
    snprintf(str, sizeof(str), "%04d-%02d-%02d %02d:%02d:%02d",
            tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
    return str;
}

char *human_number(double num)
{
    static char str[20];
    const char *units[] = {"", "K", "M", "G", "T"};
    for (int i = 0; i < 5; ++i) {
        if (num < 1000) {
            snprintf(str, sizeof(str), "%.3f%s", num, units[i]);
            return str;
        }
        num /= 1000;
    }
    snprintf(str, sizeof(str), "%.3fP", num);
    return str;
}

double to_fixed(double val, int num)
{
    double multiplier = 1.0;
    for (int i = 0; i < num; ++i) {
        multiplier *= 10;
    }
    return round(val * multiplier) / multiplier;
}

void reverse_mem(char *mem, size_t len)
{
    size_t step = len / 2;
    for (size_t i = 0; i < step; ++i) {
        char tmp = mem[i];
        mem[i] = mem[len - 1 - i];
        mem[len - 1 - i] = tmp;
    }
}

void strtolower(char *str)
{
    size_t len = strlen(str);
    for (size_t i = 0; i < len; ++i) {
        str[i] = tolower(str[i]);
    }
}

void strtoupper(char *str)
{
    size_t len = strlen(str);
    for (size_t i = 0; i < len; ++i) {
        str[i] = toupper(str[i]);
    }
}

void strclearblank(char *str)
{
    size_t len = strlen(str);
    size_t pos = 0;
    for (size_t i = 0; i < len; ++i) {
        if (!isblank(str[i])) {
            str[pos++] = str[i];
        }
    }
    str[pos] = '\0';
}

int urandom(void *buf, size_t size)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
        return -1;
    int n = read(fd, buf, size);
    if (n < 0)
        return -1;
    close(fd);
    return n;
}

char *sstrncpy(char *dest, const char *src, size_t n)
{
    if (n == 0)
        return dest;
    dest[0] = 0;
    return strncat(dest, src, n - 1);
}

time_t get_timezone_offset(void)
{
    time_t timestamp = 0;
    struct tm *timeinfo = localtime(&timestamp);
    if (timeinfo->tm_mday == 1) {
        return -timeinfo->tm_hour * 3600;
    } else {
        return (24 - timeinfo->tm_hour) * 3600;
    }
}


// 以下是系统调用函数注释
/*
open() 函数是一个系统调用，用于打开文件并返回文件描述符。它的原型如下：

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int open(const char *pathname, int flags);
int open(const char *pathname, int flags, mode_t mode);
其中，pathname 是文件路径名，flags 是打开文件的标志，mode 是新建文件的权限。open() 函数返回一个非负整数，表示文件描述符。如果出错，返回值为 -1。

flags 参数可以是以下值之一或它们的组合：

O_RDONLY：只读打开文件。
O_WRONLY：只写打开文件。
O_RDWR：读写打开文件。
O_CREAT：如果文件不存在，则新建文件。
O_EXCL：如果同时指定了 O_CREAT 标志，且文件已经存在，则出错。
O_TRUNC：如果文件已经存在，将其截断为零长度。
O_APPEND：每次写操作都追加到文件末尾。
O_NONBLOCK：以非阻塞方式打开文件。
O_SYNC：每次写操作都等待物理 I/O 操作完成。
O_DIRECTORY：如果 pathname 不是目录，则出错。
O_NOFOLLOW：如果 pathname 是符号链接，则出错。
mode 参数只在创建新文件时使用，用于指定文件的权限。它可以是以下值之一或它们的组合：

S_IRUSR：用户读权限。
S_IWUSR：用户写权限。
S_IXUSR：用户执行权限。
S_IRGRP：组读权限。
S_IWGRP：组写权限。
S_IXGRP：组执行权限。
S_IROTH：其他用户读权限。
S_IWOTH：其他用户写权限。
S_IXOTH：其他用户执行权限。
*/

/*
flock() 函数用于对文件进行加锁和解锁操作。它的原型如下：

#include <sys/file.h>

int flock(int fd, int operation);
其中，fd 是文件描述符，operation 是锁操作。flock() 函数返回 0 表示成功，-1 表示失败。

operation 参数可以是以下值之一：

LOCK_SH：共享锁，允许多个进程同时读取文件。
LOCK_EX：排他锁，只允许一个进程写入文件。
LOCK_UN：解锁文件。
LOCK_NB：以非阻塞方式尝试获取锁。
如果指定了 LOCK_NB 标志，但无法获取锁，则 flock() 函数会立即返回，并设置 errno 为 EWOULDBLOCK。

lockf() 函数详解
lockf() 函数也用于对文件进行加锁和解锁操作，但它比 flock() 函数更加灵活。它的原型如下：

#include <unistd.h>

int lockf(int fd, int cmd, off_t len);
其中，fd 是文件描述符，cmd 是锁操作，len 是锁定的字节数。lockf() 函数返回 0 表示成功，-1 表示失败。

cmd 参数可以是以下值之一：

F_LOCK：获取锁。
F_TLOCK：尝试获取锁，如果无法获取则立即返回。
F_ULOCK：释放锁。
F_TEST：测试锁状态，如果可以获取锁，则返回 0。
len 参数用于指定锁定的字节数，如果 len 为 0，则表示锁定整个文件。

与 flock() 函数相比，lockf() 函数的优势在于可以对文件的任意部分进行加锁和解锁操作。
但需要注意的是，lockf() 函数只能在同一进程内的不同线程之间使用，不能在不同进程之间使用。
*/

