#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[10];
    strcpy(buffer, input); // Vulnerable function - no boundary checking
    printf("Input: %s\n", buffer);
}


int main() {
    char password[10];
    printf("Enter your password: ");
    scanf("%9s", password); // Limit input to the size of the 'password' buffer

    if (strcmp(password, "password") == 0) {
        char input[20];
        printf("Enter your input: ");
        scanf("%s", input); // Limit input to the size of the 'input' buffer
        vulnerable_function(input);
        return 0;
    }
    return 1;
}
