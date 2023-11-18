/**
 Vulnerable CSV program:
 Takes in csv value.
 Crashes when more than 5 rows of value are given
 **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ROWS 5
#define MAX_VALUE_LENGTH 100

void process_csv_data(char *csv_data) {
    char *token;
    const char *delimiters = ",\n";  // Comma and newline as delimiters

    token = strtok(csv_data, delimiters);

    while (token != NULL) {
        // Move to the next token
        token = strtok(NULL, delimiters);
    }
}

int main() {
    char csv_data[1000];
    int row_count = 0;

    printf("Enter CSV data (Ctrl+D to finish input):\n");

    // Read CSV data line by line until encountering EOF or reaching the row limit
    while (fgets(csv_data, sizeof(csv_data), stdin) != NULL) {
        row_count++;

        // Check if row limit exceeded
        if (row_count > MAX_ROWS) {
            printf("Maximum rows reached! Triggering segmentation fault...\n");
            // Cause a segmentation fault by accessing an invalid memory location
            char *ptr = NULL;
            *ptr = 'x'; // Attempt to write to a null pointer
        }

        process_csv_data(csv_data);
    }

    return 0;
}