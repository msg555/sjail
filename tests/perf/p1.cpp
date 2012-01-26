#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>

int main() {
	for(long long i = 0; i < 1000000LL; i++) {
		syscall(SYS_brk, 0);
	}
}
