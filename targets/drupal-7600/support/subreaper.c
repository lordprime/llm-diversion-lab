/*
 * Starts a program as a child subreaper. Built statically into
 * /opt/support/subreaper; the entrypoint starts Apache through it.
 *
 * It sets PR_SET_CHILD_SUBREAPER, which the kernel keeps across execve, and then
 * replaces itself with the program. So Apache's master is a subreaper: a process
 * of its tree whose parent exits (`/tmp/pwn &`, `nohup ... &`) is handed to the
 * master instead of to PID 1, and stays in the tree the event service checks.
 * Nothing started outside that tree can become the master's child.
 *
 * Usage: subreaper PROGRAM [ARG]...   (exit 2 on bad usage, 127 if the exec fails)
 */
#include <stdio.h>
#include <sys/prctl.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fputs("usage: subreaper PROGRAM [ARG]...\n", stderr);
        return 2;
    }
    if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0) {
        perror("subreaper: prctl");
        return 1;
    }
    execvp(argv[1], argv + 1);
    perror("subreaper: exec");
    return 127;
}
