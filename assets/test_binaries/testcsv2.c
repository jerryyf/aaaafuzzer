/**
 Vulnerable CSV program:
 Takes in csv value.
 Crashes when the length of value exceeds 5.
 **/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_VALUES_PER_ROW 5
#define MAX_VALUE_LENGTH 5

void process_csv_data(char *csv_data) {
    char *token;
    const char *delimiters = ",\n";  // Comma and newline as delimiters

    token = strtok(csv_data, delimiters);

    while (token != NULL) {
        // Process each token or value
        //printf("%s\n", token);

        // Move to the next token
        token = strtok(NULL, delimiters);
    }
}

int main() {
    char csv_data[1000];
    printf("Enter CSV data (Ctrl+D to finish input):\n");

    // Read CSV data line by line until encountering EOF
    while (fgets(csv_data, sizeof(csv_data), stdin) != NULL) {
        // Check the length of each value
        char *token;
        const char *delimiters = ",\n";  // Comma and newline as delimiters

        token = strtok(csv_data, delimiters);

        while (token != NULL) {
            if (strlen(token) > MAX_VALUE_LENGTH) {
                printf("Value too long! Triggering segmentation fault...\n");
                // Cause a segmentation fault by accessing an invalid memory location
                char *ptr = NULL;
                *ptr = 'x';
            }

            // Move to the next token
            token = strtok(NULL, delimiters);
        }

        process_csv_data(csv_data);
    }

    return 0;
}