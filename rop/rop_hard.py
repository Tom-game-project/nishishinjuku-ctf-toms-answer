from ptrlib import *

def main():
    """
```
<< EOF cat | gcc hard.c -static-pie -o hard -x c -
#include <stdio.h>
#include <unistd.h>

int main(void) {
    char msg[0x10] = {};

    setbuf(stdout, NULL);

    puts("You can put message 4 times");
    for (int i = 0; i < 4; i++) {
        printf("Input (%d/4) >> ", i + 1);
        read(STDIN_FILENO, msg, 0x70);
        printf("Output : %s\n", msg);
    }
    puts("Bye!");

    return 0;
}
// gcc hard.c -static-pie -o hard

```
    """
    pass

if __name__ == "__main__":
    main()
