/*
 * Runs a program as the child of a child subreaper. Built statically into
 * /opt/support/subreaper; the entrypoint starts Apache through it.
 *
 * It sets PR_SET_CHILD_SUBREAPER, starts the program as its child and stays its
 * parent. A process of the program's tree whose parent exits (`/tmp/pwn &`,
 * `nohup ... &`) is then handed to this process instead of to PID 1, so it stays
 * in the tree the event service checks; the service pins this process as the
 * tree's root. Nothing started outside that tree can become its child.
 *
 * It reaps every such orphan itself. Apache never sees them, which matters:
 * Apache's prefork master stops when a child it reaps exits 15, so as a
 * subreaper itself it could be stopped by any web user's `sh -c 'exit 15' &`.
 *
 * The program gets a process group of its own. Apache's master signals its whole
 * group when it stops (TERM) or restarts (HUP), and that must not reach PID 1.
 *
 * TERM, INT, HUP, USR1 and WINCH (how Apache is stopped and restarted) are
 * passed on to the program; every other signal that can be caught is ignored,
 * so a stray one never ends the tree's root. When the program exits, this exits
 * too, with the program's status (128 + the signal number if a signal ended it).
 *
 * Usage: subreaper PROGRAM [ARG]...   (exit 2 on bad usage, 127 if the exec fails)
 */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static const int forwarded[] = {SIGTERM, SIGINT, SIGHUP, SIGUSR1, SIGWINCH};
#define FORWARDED (sizeof(forwarded) / sizeof(forwarded[0]))

/* SIGCHLD needs a handler of its own: a blocked signal whose default is to be
 * ignored might otherwise never be queued for sigwaitinfo */
static void noted(int signal_number)
{
    (void)signal_number;
}

/* reap every child that has ended; returns the program's wait status once it has */
static int reap(pid_t program, int *status)
{
    int ended = 0, child_status;
    pid_t pid;

    while ((pid = waitpid(-1, &child_status, WNOHANG)) > 0) {
        if (pid == program) {
            *status = child_status;
            ended = 1;
        }
    }
    return ended;
}

static int exit_code(int status)
{
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    if (WIFSIGNALED(status))
        return 128 + WTERMSIG(status);
    return 1;
}

int main(int argc, char *argv[])
{
    struct sigaction on_child = {.sa_handler = noted};
    sigset_t waited, previous;
    siginfo_t info;
    pid_t program;
    int status = 0;
    size_t i;

    if (argc < 2) {
        fputs("usage: subreaper PROGRAM [ARG]...\n", stderr);
        return 2;
    }
    if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0) {
        perror("subreaper: prctl");
        return 1;
    }

    /* take every signal by sigwaitinfo from here on, so none is lost before the
     * loop starts; the program gets the old mask and default handlers back */
    sigfillset(&waited);
    if (sigaction(SIGCHLD, &on_child, NULL) != 0 ||
        sigprocmask(SIG_BLOCK, &waited, &previous) != 0) {
        perror("subreaper: signals");
        return 1;
    }

    program = fork();
    if (program < 0) {
        perror("subreaper: fork");
        return 1;
    }
    /* also from this side, so the group exists whichever of the two runs first */
    setpgid(program, program);
    if (program == 0) {
        setpgid(0, 0);
        signal(SIGCHLD, SIG_DFL);
        sigprocmask(SIG_SETMASK, &previous, NULL);
        execvp(argv[1], argv + 1);
        perror("subreaper: exec");
        _exit(127);
    }

    for (;;) {
        if (sigwaitinfo(&waited, &info) < 0) {
            if (errno == EINTR)
                continue;
            perror("subreaper: sigwaitinfo");
            return 1;
        }
        if (info.si_signo == SIGCHLD) {
            if (reap(program, &status))
                break;
            continue;
        }
        for (i = 0; i < FORWARDED; i++) {
            if (info.si_signo == forwarded[i])
                kill(program, info.si_signo);
        }
    }
    /* orphans still running go on to PID 1 when this exits */
    return exit_code(status);
}
