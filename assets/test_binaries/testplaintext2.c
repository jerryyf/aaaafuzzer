#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>

volatile int flag = 0;

void segfault_handler(int signum) {
    printf("Segmentation fault detected! Possible bit flip.\n");
    exit(EXIT_FAILURE);
}

void detect_bit_flips(const char *input) {
    volatile char *ptr = (volatile char *)input;

    while (*ptr != '\0') {
        if (!isprint(*ptr)) {
            flag = 1;
            break;
        }
        ptr++;
    }
}

int main() {
    signal(SIGSEGV, segfault_handler);

    int option;

    printf("Menu:\n");
    printf("1. Say: Hi\n");
    printf("2. Say: How are you\n");
    printf("3. Say: What is your name\n");
    printf("4. Say: Goodbye\n");
    printf("Enter your choice (1-4): ");


    if (scanf("%d", &option) != 1 || option < 1 || option > 4) {
        printf("Invalid input. Please enter a valid option (1-4).\n");
        return EXIT_FAILURE;
    }

    printf("Enter your input: ");
    char input[100];
    scanf(" %[^\n]", input);

    detect_bit_flips(input);

    if (flag) {
        printf("Input contains non-printable characters. Triggering segmentation fault...\n");
        char *ptr = NULL;
        *ptr = 'x';
    }

    switch (option) {
        case 1:
            printf("You said: Hi\n");
            break;
        case 2:
            printf("You said: How are you\n");
            break;
        case 3:
            printf("You said: What is your name\n");
            break;
        case 4:
            printf("You said: Goodbye\n");
            break;
    }

    return 0;
}