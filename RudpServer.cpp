#include "RudpPacket.h"
#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_BUFFER_SIZE 1024

const std::string sourceIp = "127.0.0.1";
const std::string destIp = "127.0.0.1";

struct sockaddr_in server_addr, client_addr;

int initSockfd() {
  // 创建UDP套接字
  int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd == -1) {
    perror("socket");
    return -1;
  }
  // 绑定本地IP地址和端口号
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY); // 本地任意IP地址
  server_addr.sin_port = htons(8888);              // 绑定到8888端口
  if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) ==
      -1) {
    perror("bind");
    close(sockfd);
    return -1;
  }
  return sockfd;
}

bool serverConnect(int sockfd) {
  RudcpPacket packet;
  /* 接收第一次握手, 解析之后拿到 seq 的值 */
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
  if (!packet.hasSyn() || !packet.validateTcpChecksum()) {
    perror("第一次握手失败");
    close(sockfd);
    return false;
  }
  printf("Get Syn, 三次握手第一步收到!\n");
  /* 构造第二次握手, 随机一个 seq 并且 ack = seq + 1 */
  uint32_t ack = packet.getSeq() + 1;
  uint32_t seq = rand() % int(1e8);
  packet.buildSynAckPacket(packet.getDestPort(), packet.getSourcePort(), seq,
                           ack);
  std::string data = packet.rudpPacketString();
  n = sendto(sockfd, data.c_str(), data.size(), 0,
             (struct sockaddr *)&client_addr, sizeof(client_addr));
  if (n == -1) {
    perror("sendto");
    close(sockfd);
    return false;
  }
  printf("Send Syn Ack, 三次握手第二步发出!\n");
  /* 接收第三次握手, 解析拿到 ack 的值为 seq + 1 且通过校验和 */
  buffer.resize(MAX_BUFFER_SIZE, 0);
  n = recvfrom(sockfd, const_cast<char *>(buffer.c_str()), MAX_BUFFER_SIZE, 0,
               (struct sockaddr *)&client_addr, &addr_len);
  if (n == -1) {
    perror("recvfrom");
    close(sockfd);
    return false;
  }
  packet.parseTcpPacket(buffer);
  if (!packet.hasAck() || !(packet.getAck() == seq + 1) ||
      !packet.validateTcpChecksum()) {
    perror("第三次握手失败!");
    close(sockfd);
    return false;
  }
  printf("Get Ack, 三次握手第三步收到!\n");
  return true;
}

bool serverClose(int sockfd) {
  RudcpPacket packet;
  uint32_t seq = rand() % int(1e9);
  packet.buildFinPacket(8888, 9999, seq, 0);
  std::string data = packet.rudpPacketString();
  ssize_t n = sendto(sockfd, data.c_str(), data.size(), 0,
                     (struct sockaddr *)&client_addr, sizeof(client_addr));
  if (n == -1) {
    perror("sendto");
    close(sockfd);
    return false;
  }
  printf("Send Fin, 四次挥手第一步发出!\n");
  std::string buffer(MAX_BUFFER_SIZE, 0);
  socklen_t addr_len = sizeof(client_addr);
  n = recvfrom(sockfd, const_cast<char *>(buffer.c_str()), MAX_BUFFER_SIZE, 0,
               (struct sockaddr *)&client_addr, &addr_len);
  if (n == -1) {
    perror("recvfrom");
    close(sockfd);
    return false;
  }
  packet.parseTcpPacket(buffer);
  if (!packet.hasAck() || !packet.validateTcpChecksum() ||
      !(packet.getAck() == seq + 1)) {
    perror("第二次挥手检查失败!");
    close(sockfd);
    return false;
  }
  printf("Get Ack, 四次挥手第二步收到!\n");
  buffer.resize(MAX_BUFFER_SIZE, 0);
  n = recvfrom(sockfd, const_cast<char *>(buffer.c_str()), MAX_BUFFER_SIZE, 0,
               (struct sockaddr *)&client_addr, &addr_len);
  if (n == -1) {
    perror("recvfrom");
    close(sockfd);
    return false;
  }
  packet.parseTcpPacket(buffer);
  if (!packet.hasFin() || !packet.validateTcpChecksum() ||
      packet.getAck() != seq + 1) {
    perror("第三次次挥手检查失败!");
    close(sockfd);
    return false;
  }
  printf("Get Fin, 四次挥手第三步收到!\n");
  packet.buildAckPacket(8888, 9999, seq + 1, packet.getSeq() + 1);
  data = packet.rudpPacketString();
  n = sendto(sockfd, data.c_str(), data.size(), 0,
             (struct sockaddr *)&client_addr, sizeof(client_addr));
  if (n == -1) {
    perror("sendto");
    close(sockfd);
    return false;
  }
  printf("Send Ack, 四次挥手第四步发出!\n");
  return true;
}

int main() {
  int sockfd = initSockfd();
  bool flag = serverConnect(sockfd);
  if (!flag) {
    perror("ThreeWayHandshake failed!");
    close(sockfd);
    return -1;
  }
  // 不断等待客户端发来消息
  char buffer[MAX_BUFFER_SIZE];
  while (true) {
    socklen_t addr_len = sizeof(client_addr);
    memset(buffer, 0, MAX_BUFFER_SIZE);
    ssize_t n = recvfrom(sockfd, buffer, MAX_BUFFER_SIZE, 0,
                         (struct sockaddr *)&client_addr, &addr_len);
    if (n == -1) {
      perror("recvfrom");
      continue;
    }
    const char *filename = buffer;
    int fd = open(filename, O_RDONLY);

    flag = serverClose(sockfd);
    if (!flag) {
      perror("close failed!");
      close(sockfd);
      return -1;
    }
  }
  close(sockfd);
  return 0;
}
