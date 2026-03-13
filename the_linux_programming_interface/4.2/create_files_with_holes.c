#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>

int main(int argc, char *argv[]){
    char *filePath = "file_with_holes.txt";
    int fd;
    int flags = O_WRONLY | O_CREAT;
    int mode = S_IRUSR | S_IWUSR;
    int SEEK_BYTES = 50000;
    ssize_t numWrite;

    fd = open(filePath, flags, mode);
    if (fd == -1){
        perror("Error open: ");
        return 1;
    }

    numWrite = write(fd, "First 14 bytes", 14);
    if (numWrite != 14){
        perror("Error writing first bytes: ");
        return 1;
    }

    if (lseek(fd, SEEK_BYTES, SEEK_CUR) == -1){
        perror("Error seeking: ");
        return 1;
    }

    numWrite = write(fd, "TEST", 4);
    if (numWrite != 4){
        perror("Error writing TEST: ");
        return 1;
    }

    if (lseek(fd, SEEK_BYTES, SEEK_CUR) == -1){
        perror("Error seeking: ");
        return 1;
    }

    numWrite = write(fd, "FINISH", 6);
    if (numWrite != 6){
        perror("Error writing FINISH: ");
        return 1;
    }

    close(fd);
}