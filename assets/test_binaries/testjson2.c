#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_KEY_LENGTH 10
#define MAX_VALUE_LENGTH 10
#define MAX_JSON_LENGTH 100

int main() {
    char key[MAX_KEY_LENGTH + 1];
    char value[MAX_VALUE_LENGTH + 1];
    char json_data[MAX_JSON_LENGTH];

    printf("Enter JSON keys and values (Type 'quit' to stop):\n");

    while (scanf("%10s%*c%10s%*c", key, value) != EOF) {
        if (strlen(key) >= MAX_KEY_LENGTH || strlen(value) >= MAX_VALUE_LENGTH) {
            printf("Key or value is too long! Triggering segmentation fault...\n");
            char buffer[MAX_JSON_LENGTH];
            strcpy(buffer, "overflow!");
        } else {
            strcat(json_data, key);
            strcat(json_data, ":");
            strcat(json_data, value);
            strcat(json_data, ",");
        }
    }
    return 0;
}