#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_VALUE_LENGTH 40

void process_json(char *json) {
    char *token;
    const char *delimiters = "{\":,}";

    token = strtok(json, delimiters);

    while (token != NULL) {
        if (token[0] != ' ') {
            // Move to the value field
            token = strtok(NULL, delimiters);
            if (token != NULL && strlen(token) > MAX_VALUE_LENGTH) {
                printf("Value is too big! Triggering segmentation fault...\n");
                char buffer[MAX_VALUE_LENGTH];
                strcpy(buffer, "overflow!"); // Buffer overflow here
            }
        }
        token = strtok(NULL, delimiters);
    }

    printf("Processed JSON\n");
}

int main() {
    char json_data[1000];
    printf("Enter JSON data: ");

    // Read JSON data using scanf
    scanf("%999[^\n]", json_data);

    process_json(json_data);
    return 0;
}