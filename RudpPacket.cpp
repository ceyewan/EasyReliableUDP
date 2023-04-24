#include "RudpPacket.h"
#include <cstdio>

std::string RudcpPacket::serializeTcpPacket() {
  std::string packetData(20, 0);
  // 将 TcpPacket 对象的各个字段序列化为字符串
  packetData[0] = (sourcePort >> 8) & 0xFF;
  packetData[1] = sourcePort & 0xFF;
  packetData[2] = (destPort >> 8) & 0xFF;
  packetData[3] = destPort & 0xFF;
  packetData[4] = (seqNum >> 24) & 0xFF;
  packetData[5] = (seqNum >> 16) & 0xFF;
  packetData[6] = (seqNum >> 8) & 0xFF;
  packetData[7] = seqNum & 0xFF;
  packetData[8] = (ackNum >> 24) & 0xFF;
  packetData[9] = (ackNum >> 16) & 0xFF;
  packetData[10] = (ackNum >> 8) & 0xFF;
  packetData[11] = ackNum & 0xFF;
  packetData[13] = flags;
  packetData[14] = (windowSize >> 8) & 0xFF;
  packetData[15] = windowSize & 0xFF;
  packetData[16] = (checksum >> 8) & 0xFF;
  packetData[17] = checksum & 0xFF;
  packetData[18] = (urgentPointer >> 8) & 0xFF;
  packetData[19] = urgentPointer & 0xFF;
  return packetData;
}

bool RudcpPacket::parseTcpPacket(const std::string &packetData) {
  if (packetData.size() < 20) {
    // TCP 报文至少包含 20 个字节的首部，否则无法解析
    return false;
  }
  // 将 TCP 报文的首部解析为 TcpPacket 对象
  sourcePort = ((uint8_t)packetData[0] << 8) | (uint8_t)packetData[1];
  destPort = ((uint8_t)packetData[2] << 8) | (uint8_t)packetData[3];
  seqNum = ((uint8_t)packetData[4] << 24) | ((uint8_t)packetData[5] << 16) |
           ((uint8_t)packetData[6] << 8) | (uint8_t)packetData[7];
  ackNum = (packetData[8] << 24) | ((uint8_t)packetData[9] << 16) |
           ((uint8_t)packetData[10] << 8) | (uint8_t)packetData[11];
  flags = packetData[13];
  windowSize = ((uint8_t)packetData[14] << 8) | (uint8_t)packetData[15];
  checksum = ((uint8_t)packetData[16] << 8) | (uint8_t)packetData[17];
  urgentPointer = ((uint8_t)packetData[18] << 8) | (uint8_t)packetData[19];
  data = packetData.substr(20);
  return true;
}

uint16_t RudcpPacket::calculateTcpChecksum() {
  uint32_t sum = 0;
  // 将 TCP 报文的首部和数据部分拼接起来
  std::string packetData = rudpPacketString();
  // 计算 TCP 报文的校验和
  for (size_t i = 0; i < packetData.size() - 1; i += 2) {
    uint16_t word = ((uint8_t)packetData[i] << 8) | (uint8_t)packetData[i + 1];
    sum += word;
  }
  if (packetData.size() % 2 == 1) {
    uint16_t word = ((uint8_t)packetData.back() << 8) | 0x00;
    sum += word;
  }
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }
  return (uint16_t)~sum;
}

bool RudcpPacket::validateTcpChecksum() {
  uint16_t checksum = calculateTcpChecksum();
  return checksum == 0;
}

void RudcpPacket::buildSynPacket(uint16_t srcPort, uint16_t dstPort,
                                 uint32_t seqNum) {
  this->sourcePort = srcPort;
  this->destPort = dstPort;
  this->seqNum = seqNum;
  this->ackNum = 0;
  this->flags = 0x02;      // SYN 标志位
  this->windowSize = 8192; // 窗口大小为 8192 字节
  this->checksum = 0;
  this->checksum = calculateTcpChecksum();
}
void RudcpPacket::buildSynAckPacket(uint16_t srcPort, uint16_t dstPort,
                                    uint32_t seqNum, uint32_t ackNum) {
  this->sourcePort = srcPort;
  this->destPort = dstPort;
  this->seqNum = seqNum;
  this->ackNum = ackNum;
  this->flags = 0x12;      // SYN 和 ACK 标志位
  this->windowSize = 8192; // 窗口大小为 8192 字节
  this->checksum = 0;
  this->checksum = calculateTcpChecksum();
}
void RudcpPacket::buildAckPacket(uint16_t srcPort, uint16_t dstPort,
                                 uint32_t seqNum, uint32_t ackNum) {
  this->sourcePort = srcPort;
  this->destPort = dstPort;
  this->seqNum = 0;
  this->ackNum = ackNum;
  this->flags = 0x10;      // ACK 标志位
  this->windowSize = 8192; // 窗口大小为 8192 字节
  this->checksum = 0;
  this->checksum = calculateTcpChecksum();
}
void RudcpPacket::buildFinPacket(uint16_t srcPort, uint16_t dstPort,
                                 uint32_t seqNum, uint32_t ackNum) {
  this->sourcePort = srcPort;
  this->destPort = dstPort;
  this->seqNum = seqNum;
  this->ackNum = ackNum;
  this->flags = 0x01;      // FIN 标志位
  this->windowSize = 8192; // 窗口大小为 8192 字节
  this->checksum = 0;
  this->checksum = calculateTcpChecksum();
}