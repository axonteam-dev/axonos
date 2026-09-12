#include <osh.h>
#include <vga.h>
#include <string.h>
#include <stdio.h>
#include <keyboard.h>

static int help() {
    kprintf("available commands:\n");
    kprintf("  help - Show this help message\n");
    kprintf("  exit - Exit the shell\n");
    return 0;
}

static int clear_screen() {
    kprintf("\033[2J\033[1;1H");
    return 0;
}

void start_osh() {
    kprintf("  osh %s\n", OSH_VERSION);
    kprintf("  Type 'help' for available commands.\n");
    while (1) {
        kprintf("[osh] > ");
        char command[1024];
        kgets(command, sizeof(command));
        char **args = split(command, " ", NULL);
        if (args[0] == NULL) {
            continue;
        } else if (strcmp(args[0], "exit") == 0) {
            break;
        } else if (strcmp(args[0], "help") == 0) {
            help();
        } else if (strcmp(args[0], "clear") == 0) {
            clear_screen();
        }
        else {
            kprintf("unknown command: %s\n", args[0]);
        }
    }
}