#include<stdio.h>
#include <fcntl.h>
#include<unistd.h>

static char file[] = "normalfile.txt";
static char buf[128];
static char root[] = "file3\n";

void action (int filedes, int size, int times) {
    if (times == 0)
    return;
    if (filedes > 0){
        read(filedes, buf, size);
    }
    action(filedes, size, times-1);
}

void writewrap (int filedes) {
write(filedes, root, 6);
}

void func () {
int fd = open(file, O_RDWR);
for (int i=0; i<2; ++i)
    action(fd, 128, 3);
writewrap(fd);
action(fd, 16, 3);
close(fd);
}

int main(){
    func();
}