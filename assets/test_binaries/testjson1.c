#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_KEYS 5
#define MAX_KEY_LENGTH 5

void process_json(char *json) {
    int key_count = 0;
    char *token;
    const char *delimiters = "{\":,}";

    token = strtok(json, delimiters);
    char keys[MAX_KEYS][MAX_KEY_LENGTH];

    while (token != NULL) {
        if (key_count >= MAX_KEYS) {
            printf("Too many keys! Triggering segmentation fault...\n");
            char buffer[MAX_KEY_LENGTH];
            strcpy(buffer, "overflow!"); // Buffer overflow here
        } else {
            if (token[0] != ' ' && strlen(token) < MAX_KEY_LENGTH) {
                strcpy(keys[key_count], token);
                key_count++;
            }
        }
        token = strtok(NULL, delimiters);
    }
    printf("Processed JSON with %d keys\n", key_count);
}

int main() {
    char json_data[1000];
    printf("Enter JSON data: ");

    // Read JSON data using scanf
    scanf("%999[^\n]", json_data);

    process_json(json_data);
    return 0;
}