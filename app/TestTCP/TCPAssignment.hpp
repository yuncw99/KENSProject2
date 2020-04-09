/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>


#include <E/E_TimerModule.hpp>
#include <list>

using namespace std;

namespace E
{

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:

private:
	virtual void timerCallback(void* payload) final;
	virtual int syscall_socket(UUID syscallUUID, int pid, int type, int protocol) final;
	virtual int syscall_close(UUID syscallUUID, int pid, int sockfd) final;
	virtual int syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *my_addr, socklen_t addrlen) final;
	virtual int syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen) final;
	virtual struct socketInterface* find_sock_byId(int sockfd) final;
	virtual bool is_overlapped(struct sockaddr_in *my_addr) final;

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
	list<struct socketInterface*> socket_list;

protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

struct socketInterface
{
	int sockfd;
	int type;
	int protocol;
	struct sockaddr *myaddr;
	socklen_t myaddr_len;
	struct sockaddr *oppoaddr;
	socklen_t oppoaddr_len;

	bool is_bind;
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */
