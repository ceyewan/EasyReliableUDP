/*+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |          Source Port          |       Destination Port        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                        Sequence Number                        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Acknowledgment Number                      |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |  Data |       |C|E|U|A|P|R|S|F|                               |
  | Offset| Rsrvd |W|C|R|C|S|S|Y|I|            Window             |
  |       |       |R|E|G|K|H|T|N|N|                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |           Checksum            |         Urgent Pointer        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Options                    |    Padding    |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                             data                              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                           TCP Header Format
           Note that one tick mark represents one bit position.
*/
#include <arpa/inet.h>
#include <cstdio>
#include <stdint.h>
#include <string>

class RudcpPacket {
public:
  RudcpPacket() { data.clear(); }
  // 将 rudp 报文序列化为字符串, 将字符串解析为 rdup 报文
  std::string serializeTcpPacket();
  bool parseTcpPacket(const std::string &);
  // 计算 checksum, 校验 checksum
  uint16_t calculateTcpChecksum();
  bool validateTcpChecksum();
  // 操作 flags
  void setSyn() { flags |= 0x02; }
  void setAck() { flags |= 0x10; }
  void setFin() { flags |= 0x01; }
  bool hasAck() { return (flags & 0x10) == 0x10; }
  bool hasSyn() { return (flags & 0x02) == 0x02; }
  bool hasFin() { return (flags & 0x01) == 0x01; }
  // 序列号和确认号
  int getSeq() { return seqNum; }
  int getAck() { return ackNum; }
  // 构造三次握手的报文
  void buildSynPacket(uint16_t, uint16_t, uint32_t);
  void buildSynAckPacket(uint16_t, uint16_t, uint32_t, uint32_t);
  void buildAckPacket(uint16_t, uint16_t, uint32_t, uint32_t);
  void buildFinPacket(uint16_t, uint16_t, uint32_t, uint32_t);
  // rudp 报文
  std::string rudpPacketString() { return serializeTcpPacket() + data; }
  // 源端口号和目的端口号
  uint16_t getSourcePort() { return sourcePort; }
  uint16_t getDestPort() { return destPort; }

private:
  uint16_t sourcePort{0};    // 源端口号
  uint16_t destPort{0};      // 目的端口号
  uint32_t seqNum{0};        // 序列号
  uint32_t ackNum{0};        // 确认号
  uint8_t flags{0};          // 标记位
  uint16_t windowSize{0};    // 窗口大小
  uint16_t checksum{0};      // 校验和
  uint16_t urgentPointer{0}; // 紧急指针
  std::string data;          // 数据
};
