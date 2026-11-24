/*
 * Tells the local event service that it ran, then exits. Built statically into
 * /opt/support/pwn; the image hard-links it at /tmp/pwn.
 *
 * It waits for the service's one-line answer before exiting: by then the service
 * has looked this process up and written the event down, so even a run that is
 * over in a few milliseconds is recorded. Exit 0 when answered, 1 otherwise; it
 * prints nothing either way.
 */
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef EVENTS_SOCKET
#define EVENTS_SOCKET "/run/insights/events.sock"
#endif

static const char message[] = "{\"kind\": \"exec\", \"argv0\": \"/tmp/pwn\"}\n";

int main(void)
{
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    struct timeval patience = {.tv_sec = 5};
    char answer[16];
    int fd;

    if (sizeof(EVENTS_SOCKET) > sizeof(address.sun_path))
        return 1;
    memcpy(address.sun_path, EVENTS_SOCKET, sizeof(EVENTS_SOCKET));

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return 1;
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0)
        return 1;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &patience, sizeof(patience));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &patience, sizeof(patience));
    if (write(fd, message, sizeof(message) - 1) != (ssize_t)(sizeof(message) - 1))
        return 1;
    return read(fd, answer, sizeof(answer)) > 0 ? 0 : 1;
}
