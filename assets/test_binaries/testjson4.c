#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_RECORDS 5
#define RECORD_SIZE 100

int main() {
    char records[MAX_RECORDS][RECORD_SIZE];
    char buffer[RECORD_SIZE];
    int record_count = 0;

    printf("Enter JSON records (Type 'quit' to stop):\n");

    while (scanf("%s", buffer) != EOF) {
        if (record_count >= MAX_RECORDS) {
            printf("Too many records! Triggering segmentation fault...\n");
            char *ptr = NULL;
            *ptr = 'x';
        } else {
            strcpy(records[record_count], buffer);
            record_count++;
        }
    }

    char json_data[MAX_RECORDS * RECORD_SIZE];  // Variable to concatenate records
    strcpy(json_data, records[0]);

    for (int i = 1; i < record_count; ++i) {
        strcat(json_data, records[i]);
    }
    return 0;
}