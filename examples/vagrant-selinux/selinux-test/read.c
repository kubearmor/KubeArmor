#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
	printf("Usage: %s [file]\n", argv[0]);
	return 1;
    }

    FILE *f = fopen(argv[1], "r");
    if (f != NULL) {
        char buf[200] = {0};

	fgets(buf, 200, f);
        printf("read %s from %s\n", buf, argv[1]);

        fclose(f);
    } else {
	printf("failed to open %s with the READONLY mode\n", argv[1]);
    }

    sleep(5);

    return 0;
}
