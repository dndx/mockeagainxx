#include <sys/ioctl.h>
#include <fcntl.h>
#include "test_case.h"

int run_test(int fd) {
    int n;
    const char  *buf = "test";
    const int    len = sizeof("test") - 1;
    int           nb = 0;

    /* first make it blocking */
    assert(!ioctl(fd, FIONBIO, &nb));

    n = send(fd, buf, len, 0);
    assert(n == len);

    /* make it nb again */
    nb = 1;
    assert(!ioctl(fd, FIONBIO, &nb));

    n = send(fd, buf, len, 0);
    assert(n == 1);

    /* blocking using fcntl */
    assert(!fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK));

    n = send(fd, buf, len, 0);
    assert(n == len);

    /* nb using fcntl */
    assert(!fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK));
    n = send(fd, buf, len, 0);
    assert(n == 1);

    return EXIT_SUCCESS;
}
