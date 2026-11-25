/*
 * Tells the local event service that it ran, then exits. Built statically into
 * /opt/support/pwn; the image hard-links it at /tmp/pwn.
 *
 * It waits for the service's one-line answer before exiting: by then the service
 * has looked this process up and written the event down, so even a run that is
 * over in a few milliseconds is recorded. Exit 0 when answered, 1 otherwise; it
 * prints nothing either way.
 *
 * It never hangs. The send and receive timeouts are set before connecting (on a
 * Unix socket the send timeout also bounds a connect that waits for room in a
 * full listen queue), and an alarm ends the whole run if anything else stalls.
 */
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef EVENTS_SOCKET
#define EVENTS_SOCKET "/run/insights/events.sock"
#endif
/* how long to wait for each step, in seconds */
#ifndef PATIENCE_S
#define PATIENCE_S 5
#endif

static const char message[] = "{\"kind\": \"exec\", \"argv0\": \"/tmp/pwn\"}\n";

static void give_up(int signal_number)
{
    (void)signal_number;
    _exit(1);
}

int main(void)
{
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    struct timeval patience = {.tv_sec = PATIENCE_S};
    struct sigaction on_alarm = {.sa_handler = give_up};
    char answer[16];
    int fd;

    /* the last resort: connect, send and receive each have PATIENCE_S */
    if (sigaction(SIGALRM, &on_alarm, NULL) != 0)
        return 1;
    alarm(3 * PATIENCE_S);

    if (sizeof(EVENTS_SOCKET) > sizeof(address.sun_path))
        return 1;
    memcpy(address.sun_path, EVENTS_SOCKET, sizeof(EVENTS_SOCKET));

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return 1;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &patience, sizeof(patience)) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &patience, sizeof(patience)) != 0)
        return 1;
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0)
        return 1;
    if (write(fd, message, sizeof(message) - 1) != (ssize_t)(sizeof(message) - 1))
        return 1;
    return read(fd, answer, sizeof(answer)) > 0 ? 0 : 1;
}
