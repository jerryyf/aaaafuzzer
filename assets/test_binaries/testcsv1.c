/**
 Vulnerable CSV program:
 Takes in csv value.
 Crashes when more than 5 values are given
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
        printf("%s\n", token);

        // Move to the next token
        token = strtok(NULL, delimiters);
    }
}

int main() {
    char csv_data[1000];
    printf("Enter CSV data: ");

    // Read CSV data using scanf
    scanf("%999[^\n]", csv_data);

    // Check for maximum values per row
    int count = 0;
    for (int i = 0; i < strlen(csv_data); i++) {
        count++;
        if (count > MAX_VALUES_PER_ROW) {
            printf("Value too long! Triggering segmentation fault...\n");
            // Cause a segmentation fault by accessing an invalid memory location
            char *ptr = NULL;
            *ptr = 'x';
        }
    }
    printf("%d", count);

    process_csv_data(csv_data);
    return 0;
}