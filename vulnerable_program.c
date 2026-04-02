#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <limits.h>  // Required for integer limits

void randStringGen(int x, char* c) {
    srand(time(NULL));
    for (int i = 0; i < x - 1; ++i) {
        *c = 'A' + (rand() % 26);
        c++;
    }
    *c = '\0';
}

// argv[1] = 1
void overRun(void) {
    int *x = malloc(10 * sizeof(int));
    // Below I have changed `x[10]` to `x[9]` to avoid an out-of-bounds access.
    x[9] = 0;
    // Below I have added `free(x)` to properly deallocate the memory that was allocated for `x`.
    free(x);
}

// argv[1] = 2
void unInitializedPtr(void) {
    // Below I have allocated memory for `buffer` and `c` to avoid using and uninitialized pointer.
    char *buffer = malloc(10 * sizeof(char));
    char *c = malloc(10 * sizeof(char));
    randStringGen(10, c);
    strcpy(buffer, c);
    printf("%s\n", buffer);
    free(c);
    free(buffer);
}

// argv[1] = 3
void danglingPtr(void) {
    int *x;
    int *y = malloc(10 * sizeof(int));
    x = y;
    // Below, I initialize the dynamic memory to all 0's to avoid valgrind reporting an 'Uninitialized value` error
    memset(y, 0, 10 * sizeof(int));
    int t = x[2];
    printf("Dangling pointer value: %d\n", t);
    // Below is where I moved the call to `free()`, which is after the last point in the code where it is used.
    free(y);
}

// argv[1] = 4
void bufferUnder(void) {
    char buffer[256];
    char *c = malloc(255 * sizeof(char));
    randStringGen(255, c);
    // `buffer` is an array of 256 characters (with the final character being the null terminator), but `c` is only allocated 255 characters. When we call `strcpy()` we are attempting to to copy 255 characters into dynamic memory that is allocated for 256 characters, which has one extra character.  The final character is pointing to undefined memory, which is a buffer underflow vulnerability if `buffer[255]` is used later in the program.  It might not be that much of a problem since it currently holds a null-terminated string and most string functions will stop at the null terminater, but it could be a problem in other cases.
    strcpy(buffer, c);  // Possible buffer underflow
    printf("%s\n", buffer);
    free(c);
}

// argv[1] = 5
void bufferOver(void) {
    char buffer[256];
    char *c = malloc(260 * sizeof(char));
    randStringGen(260, c);
    // `buffer` is an array of 256 characters, and `c` is allocated to 260 characters of dynamic memory.  When we copy `c` into `buffer`, we are writing 4 characters past the end of `buffer`'s stack memory.  This is a buffer overflow that overwrites whatever is in the next memory position.
    strcpy(buffer, c);  // Buffer overflow
    printf("%s\n", buffer);
    free(c);
}

// argv[1] = 6
void integerOverflow(void) {
    int a = INT_MAX;  // Max signed int value
    int b = 1;
    // We set `a` to the maxium value for a signed integer, and then we add 1 to it.  This causes an integer overflow because the result exceeds the maximum representable value for an `int`. This should cause the value to wrap around to the lowest negative value for a signed `int`, which is not what the coder intended.
    int result = a + b;  // Causes overflow
    printf("Integer Overflow: %d + %d = %d\n", a, b, result);
}

int main(int argc, char**argv) {
    if (argc != 2) {
        return 0;
    }
    int x = atoi(argv[1]);  // Convert input to integer

    if (x == 1) {
        overRun();
    } else if (x == 2) {
        unInitializedPtr();
    } else if (x == 3) {
        danglingPtr();
    } else if (x == 4) {
        bufferUnder();
    } else if (x == 5) {
        bufferOver();
    } else if (x == 6) {
        integerOverflow();
    }

    return 0;
}
