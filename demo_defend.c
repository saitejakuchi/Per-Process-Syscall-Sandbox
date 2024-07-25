#include<stdio.h>
#include <fcntl.h>
#include<unistd.h>

static char file[] = "normalfile.txt";
static char secretfile[] = "secretfile.txt";
static char buf[128];
static char root[] = "file2\n";

void action (int filedes, int size) {
if (filedes > 0)
read(filedes, buf, size);
}

void writewrap (int filedes) {
write(filedes, root, 6);
}


void func () {
int fd = open(file, O_RDWR);
for (int i=0; i<10; ++i)
action(fd, 128);
writewrap(fd);
action(fd, 16);
int kd = open(secretfile, O_RDWR);
action(kd, 256);
writewrap(fd);
close(fd);
close(kd);
}


int main(){
    func();
}