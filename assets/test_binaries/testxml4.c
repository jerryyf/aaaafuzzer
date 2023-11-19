#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_TAG_LENGTH 20

void process_xml_data(char *xml_data) {
    char *token;
    const char *start_tag = "<";
    const char *end_tag = ">";

    token = strtok(xml_data, start_tag);

    while (token != NULL) {
        if (token[0] == '/') {
            token = strtok(NULL, start_tag);
            continue;
        }

        char *closing_tag = strstr(token, ">");
        if (closing_tag != NULL) {
            closing_tag[0] = '\0';
            char *tag_content = closing_tag + 1;

            if (strlen(tag_content) > MAX_TAG_LENGTH) {
                printf("Tag content exceeds limit.s Triggering segmentation fault...\n");
                char *ptr = NULL;
                *ptr = "x";
                exit(EXIT_FAILURE);
            }
        }

        token = strtok(NULL, start_tag);
    }

    printf("XML data as plaintext:\n%s\n", xml_data);
}

int main() {
    char xml_data[1000];
    printf("Enter XML data with tags: ");

    fgets(xml_data, sizeof(xml_data), stdin);

    if (xml_data[strlen(xml_data) - 1] == '\n') {
        xml_data[strlen(xml_data) - 1] = '\0';
    }

    process_xml_data(xml_data);
    return 0;
}