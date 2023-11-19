#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_CHILD_TAGS 10

void process_xml_data(char *xml_data) {
    int tag_count = 0;
    char *token;
    const char *start_tag = "<";
    const char *end_tag = ">";

    token = strtok(xml_data, start_tag);
    while (token != NULL) {
        tag_count++;
        token = strtok(NULL, start_tag);
    }

    if (tag_count > MAX_CHILD_TAGS) {
        printf("More than %d child tags! Triggering segmentation fault...\n", MAX_CHILD_TAGS);
        char *ptr = NULL;
        *ptr = "x";
        exit(EXIT_FAILURE);
    }
}

int main() {
    char xml_data[1000];
    printf("Enter XML data with child tags: ");

    fgets(xml_data, sizeof(xml_data), stdin);

    if (xml_data[strlen(xml_data) - 1] == '\n') {
        xml_data[strlen(xml_data) - 1] = '\0';
    }

    process_xml_data(xml_data);
    return 0;
}