#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    int BUFF_SIZE = 1024;
    char *buff = NULL;
    int isAppending = 0;
    char *fileName = NULL;
    int fd;
    int flags = O_RDWR | O_CREAT;
    int mode = S_IRUSR | S_IWUSR;
    // Observation:
    // Why ssize_t?

    // 1) Why not int? 
    // Because int it's not guaranteed to be large
    // enough on all platforms.
    // On 64-bits platforms it would be possible to read 
    // more than 2GB (~2^31) and therefore it wouldn't be enough

    /// 2) Why not long?
    // That could work
    // The reason ssize_t is chosen is mostly semantic
    // (POSIX-defined type)
    ssize_t numRead, numWrite;

    if (argc < 2 || strcmp(argv[1], "--help") == 0){
        printf("Usage: %s [-a] filename", argv[0]);
        return 0;
    }

    // For now let's just assume that the 
    // flag can be placed only as first arg
    // we could check getopt() later on
    if (argc == 3 && strcmp(argv[1], "-a") == 0){
        isAppending = 1;
        fileName = argv[2];
    }

    if (argc == 2 && strcmp(argv[1], "-a")) {
        fileName = argv[1];
    }

    if (fileName == NULL){
        printf("Error parsing arguments\n");
        return 1;
    }

    if (isAppending) {
        flags = flags | O_APPEND;
    }

    fd = open(fileName, flags, mode);
    if (fd == -1){
        perror("Error opening file");
    }

    // else {
    //     printf("Correctly opened/created file %s", fileName);
    // }
    
    buff = malloc(BUFF_SIZE + 1);
    if (buff == NULL){
        printf("malloc error");
        return 1;
    }

    while (1)
    {
        numRead = read(0, buff, BUFF_SIZE);
        if (numRead == -1){
            perror("Error reading from stdin");
            break;
        }

        if (numRead == 0){
            break;
        }

        write(1, buff, numRead);
        write(fd, buff, numRead);
    }


    free(buff);
    close(fd);

    return 0;
}