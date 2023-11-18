#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[10];
    strcpy(buffer, input); // Vulnerable function - no boundary checking
    printf("Input: %s\n", buffer);
}

int main() {
    char input[20];
    printf("Enter your input: ");
    scanf("%s", input);
    vulnerable_function(input);
    return 0;
}
