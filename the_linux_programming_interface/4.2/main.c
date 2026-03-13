#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    int sourceFd;
    int targetFd;
    char *buff;
    char *toWriteBuff;
    int BUFF_SIZE = 4096;
    char *sourcePath = NULL;
    char *targetPath = NULL;
    int sourceFlags = O_RDONLY;
    int targetFlags = O_CREAT | O_WRONLY;
    int modeFlags = S_IRUSR | S_IWUSR;
    struct stat sb;
    int statRes;

    ssize_t numRead;
    ssize_t toReadIndex = 0;
    ssize_t toWrite;
    ssize_t toWriteIndex = 0;
    ssize_t offset = 0;
    
    if (argc < 3 || strcmp(argv[1], "--help") == 0){
        printf("Usage: %s <src_path> <target_path>", argv[0]);
        return 0;
    }

    sourcePath = argv[1];
    targetPath = argv[2];

    sourceFd = open(sourcePath, sourceFlags);
    if (sourceFd == -1){
        perror("Error source: ");
        return 1;
    }
    
    targetFd = open(targetPath, targetFlags, modeFlags);
    if (targetFd == -1){
        perror("Error target: ");
        return 1;
    }

    buff = malloc(BUFF_SIZE);
    toWriteBuff = malloc(BUFF_SIZE);

    while (1){
        numRead = read(sourceFd, buff, BUFF_SIZE);
        
        if (numRead == 0){
            break;
        }

        toReadIndex = 0;

        while (toReadIndex < numRead) {
            if (buff[toReadIndex] != '\0'){
                if (offset > 0){
                    lseek(targetFd, offset, SEEK_CUR);
                    offset = 0;
                }
                toWriteBuff[toWriteIndex] = buff[toReadIndex];
                toWriteIndex += 1;
            } 
            else {
                if (offset == 0) {
                    write(targetFd, toWriteBuff, toWriteIndex);
                    toWriteIndex = 0;
                }
                offset += 1;
            }
            toReadIndex += 1;
        }
        
        // Flush last bytes
        if (toWriteIndex > 0){
            if (offset > 0) {
                lseek(targetFd, offset, SEEK_CUR);
                offset = 0;
            }
            write(targetFd, toWriteBuff, toWriteIndex);
        }

        if (offset > 0){
            lseek(targetFd, offset, SEEK_CUR);
            offset = 0;
            write(targetFd, "", 1);
        }
    }
    
    return 0;
}