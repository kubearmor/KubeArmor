#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s [file]\n", argv[0]);
	return 1;
    }

    FILE *f = fopen(argv[1], "w");
    if (f != NULL) {
        fputs("hello", f);
	printf("write hello into %s\n", argv[1]);
        fclose(f);
    } else {
	printf("failed to open %s with the WRITE mode\n", argv[1]);
    }

    sleep(5);

    return 0;
}
