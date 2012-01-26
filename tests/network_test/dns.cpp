#include <iostream>
#include <vector>
#include <linux/socket.h>
#include <linux/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <cstdlib>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

using namespace std;

int main() {
  int s = socket(AF_INET, SOCK_STREAM, 0);
  if(!s) {
    cout << "Failed to create socket :(" << endl;
    return 1;
  }

  hostent * he = gethostbyname("www.google.com");
  if(!he) {
    cout << "Failed to get address of www.google.com" << endl;
    return 2;
  }

  char buf[INET_ADDRSTRLEN];
  printf("Name: %s\n", he->h_name);
  printf("IP: %s\n", inet_ntop(he->h_addrtype, he->h_addr, buf, sizeof(buf)));
  
  sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(80);
  memcpy(&addr.sin_addr, he->h_addr, sizeof(addr.sin_addr));

  if(connect(s, (sockaddr *)&addr, sizeof(addr))) {
    cout << "Connection failed :(" << endl;
    return 3;
  }

  string m1 = "GET /search?q=Alex+Halderman HTTP/1.1\r\n";
  string m2 = "Host: www.google.com\r\n";
  string m3 = "Connection: Close\r\n\r\n";
  if(send(s, m1.c_str(), m1.size(), 0) == -1) {
    cout << "send failed" << endl;
    return 4;
  }
  if(sendto(s, m2.c_str(), m2.size(), 0, NULL, 0) == -1) {
    cout << "sendto failed" << endl;
    return 5;
  }
  if(write(s, m3.c_str(), m3.size()) == -1) {
    cout << "write failed" << endl;
    return 6;
  }

  int res = 1;
  string message;
  for(int i = 0; res; i++) {
    char ch;
    if(i % 3 == 0) {
      res = recv(s, &ch, 1, 0);
      if(res == -1) {
        cout << "recv failed" << endl;
        return 7;
      }
    } else if(i % 3 == 1) {
      res = recvfrom(s, &ch, 1, 0, NULL, 0);
      if(res == -1) {
        cout << "recvfrom failed" << endl;
        return 8;
      }
    } else {
      res = read(s, &ch, 1);
      if(res == -1) {
        cout << "read failed" << endl;
        return 9;
      }
    }
    message += ch;
  }

  close(s);

  int rnrn = message.find("\r\n\r\n");
  string headers = message.substr(0, rnrn);
  message = message.substr(rnrn + 4);

  cout << "Recieved the following headers" << endl;
  cout << headers << endl;

  int f = open("search.html", O_CREAT | O_WRONLY);
  if(!f) {
    cout << "Failed to open file search.html for writing" << endl;
    return 10;
  }

  res = write(f, message.c_str(), message.size());
  if(res == -1) {
    cout << "Failed to write to search.html" << endl;
    return 11;
  }

  close(f);

  return 0;
}
