all:
	g++ -std=c++14 RudpClient.cpp RudpPacket.cpp -o RudpClient
	g++ -std=c++14 RudpServer.cpp RudpPacket.cpp -o RudpServer

clean:
	rm -rf RudpClient RudpServer