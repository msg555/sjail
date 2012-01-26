#include <iostream>
#include <vector>

#include <sys/types.h>
#include <sys/socket.h>

int main() {
  socket(1, 2, 3);
  send(0, NULL, 0, 0); 
}

