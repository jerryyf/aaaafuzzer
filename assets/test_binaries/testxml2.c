/*
XML test:
- Crashes on empty XML file
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process_xml_data(char *xml_data) {
    if (strcmp(xml_data, "<></>") == 0) {
        printf("Empty XML data. Triggering segmentation fault...\n");
        char *ptr = NULL;
        *ptr = "x";
        exit(EXIT_FAILURE);
    }
}

int main() {
    char xml_data[1000];
    printf("Enter XML data: ");

    fgets(xml_data, sizeof(xml_data), stdin);

    if (xml_data[strlen(xml_data) - 1] == '\n') {
        xml_data[strlen(xml_data) - 1] = '\0';
    }

    process_xml_data(xml_data);
    return 0;
}