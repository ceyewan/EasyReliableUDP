#include "RudpPacket.h"
#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_BUFFER_SIZE 1024

const std::string sourceIp = "127.0.0.1";
const std::string destIp = "127.0.0.1";

struct sockaddr_in server_addr, client_addr;

int initSocket() {
  int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd == -1) {
    perror("socket");
    return -1;
  }
  memset(&client_addr, 0, sizeof(client_addr));
  client_addr.sin_family = AF_INET;
  client_addr.sin_addr.s_addr = htonl(INADDR_ANY); // 本地任意IP地址
  client_addr.sin_port = htons(9999);              // 绑定到8888端口
  if (bind(sockfd, (struct sockaddr *)&client_addr, sizeof(client_addr)) ==
      -1) {
    perror("bind");
    close(sockfd);
    return -1;
  }
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // 指定服务器IP地址
  server_addr.sin_port = htons(8888); // 指定服务器端口号
  return sockfd;
}
bool clientConnect(int sockfd) {
  RudcpPacket packet;
  /* 发送第一次握手, 生成一个随机的 seq */
  uint32_t seq = rand() % int(1e9);
  packet.buildSynPacket(9999, 8888, seq);
  std::string data = packet.rudpPacketString();
  if (sendto(sockfd, data.c_str(), data.size(), 0,
             (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
    perror("sendto");
    close(sockfd);
    return false;
  }
  printf("Send Syn, 三次握手第一步发出!\n");
  /* 接受第二次握手, 解析 ack 和 syn 并检验 */
  std::string buffer(MAX_BUFFER_SIZE, 0);
  socklen_t addr_len = sizeof(server_addr);
  ssize_t n =
      recvfrom(sockfd, const_cast<char *>(buffer.c_str()), MAX_BUFFER_SIZE, 0,
               (struct sockaddr *)&server_addr, &addr_len);
  if (n == -1) {
    perror("recvfrom");
    close(sockfd);
    return false;
  }
  packet.parseTcpPacket(buffer);
  if (!packet.hasAck() || !packet.hasSyn() || !(packet.getAck() == seq + 1) ||
      !packet.validateTcpChecksum()) {
    perror("第二次握手失败!");
    close(sockfd);
    return false;
  }
  printf("Get Syn Ack, 三次握手第二步收到!\n");
  /* 发送第三次握手, 将 ack 设置为 seq + 1 表示收到了 */
  packet.buildAckPacket(packet.getDestPort(), packet.getSourcePort(), seq + 1,
                        packet.getSeq() + 1);
  data = packet.rudpPacketString();
  if (sendto(sockfd, data.c_str(), data.size(), 0,
             (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
    perror("sendto");
    close(sockfd);
    return false;
  }
  printf("Send Ack, 三次握手第三步发出!\n");
  return true;
}

bool clientClose(int sockfd) {
  RudcpPacket packet;
  std::string buffer(MAX_BUFFER_SIZE, 0);
  socklen_t addr_len = sizeof(client_addr);
  ssize_t n =
      recvfrom(sockfd, const_cast<char *>(buffer.c_str()), MAX_BUFFER_SIZE, 0,
               (struct sockaddr *)&client_addr, &addr_len);
  if (n == -1) {
    perror("recvfrom");
    close(sockfd);
    return false;
  }
  packet.parseTcpPacket(buffer);
  if (!packet.hasFin() || !packet.validateTcpChecksum()) {
    perror("第一次挥手检查失败!");
    close(sockfd);
    return false;
  }
  printf("Get Fin, 四次挥手第一步收到!\n");
  uint32_t seq = rand() % int(1e8);
  uint32_t ack = packet.getSeq() + 1;
  packet.buildAckPacket(9999, 8888, seq, ack);
  std::string data = packet.rudpPacketString();
  n = sendto(sockfd, data.c_str(), data.size(), 0,
             (struct sockaddr *)&client_addr, sizeof(client_addr));
  if (n == -1) {
    perror("sendto");
    close(sockfd);
    return false;
  }
  printf("Send Ack, 四次挥手第二步发出!\n");
  packet.buildFinPacket(9999, 8888, seq, ack);
  data = packet.rudpPacketString();
  n = sendto(sockfd, data.c_str(), data.size(), 0,
             (struct sockaddr *)&client_addr, sizeof(client_addr));
  if (n == -1) {
    perror("sendto");
    close(sockfd);
    return false;
  }
  printf("Send Fin, 四次挥手第三步发出!\n");
  buffer.resize(MAX_BUFFER_SIZE, 0);
  n = recvfrom(sockfd, const_cast<char *>(buffer.c_str()), MAX_BUFFER_SIZE, 0,
               (struct sockaddr *)&client_addr, &addr_len);
  if (n == -1) {
    perror("recvfrom");
    close(sockfd);
    return false;
  }
  packet.parseTcpPacket(buffer);
  if (!packet.hasAck() || !packet.validateTcpChecksum() ||
      packet.getAck() != seq + 1) {
    perror("第四次挥手检查失败!");
    close(sockfd);
    return false;
  }
  printf("Get Ack, 四次挥手第四步收到!\n");
  return true;
}
int main() {
  int sockfd = initSocket();

  bool flag = clientConnect(sockfd);
  if (!flag) {
    perror("ThreeWayHandshake failed!");
    close(sockfd);
    return -1;
  }
  const char *msg = "a.mp4"; // 待发送的消息
  if (sendto(sockfd, msg, strlen(msg) + 1, 0, (struct sockaddr *)&server_addr,
             sizeof(server_addr)) == -1) {
    perror("sendto");
    close(sockfd);
    return -1;
  }

  char buffer[MAX_BUFFER_SIZE];
  memset(buffer, 0, MAX_BUFFER_SIZE);
  socklen_t addr_len = sizeof(server_addr);
  ssize_t n = recvfrom(sockfd, buffer, MAX_BUFFER_SIZE, 0,
                       (struct sockaddr *)&server_addr, &addr_len);
  if (n == -1) {
    perror("recvfrom");
    close(sockfd);
    return -1;
  }

  printf("Received %zd bytes from %s:%d: %s\n", n,
         inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port), buffer);

  flag = clientClose(sockfd);
  if (!flag) {
    perror("close failed!");
    close(sockfd);
    return -1;
  }
  close(sockfd);
  return 0;
}
