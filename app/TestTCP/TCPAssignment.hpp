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
	virtual int syscall_connect(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen) final;
	virtual int syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen) final;
	virtual int syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog) final;
	virtual int syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen) final;
	virtual int syscall_read(UUID syscallUUID, int pid, int sockfd, void *buf, size_t count) final;
	virtual int syscall_write(UUID syscallUUID, int pid, int sockfd, const void *buf, size_t count) final;

	virtual bool is_overlapped(struct sockaddr_in *my_addr) final;
	virtual void send_packet(struct socketInterface *sender, unsigned char flag, struct packetData *data) final;
	virtual int make_DuplSocket(struct socketInterface *listener, in_addr_t oppo_addr, in_port_t oppo_port, in_addr_t my_addr, in_port_t my_port) final;
	virtual void remove_socket(struct socketInterface *socket) final;
	virtual size_t read_buffer(struct socketInterface *receiver, void *buf, size_t count) final;
	virtual size_t write_buffer(struct socketInterface *sender, void *buf, size_t count) final;
	virtual struct packetData* make_PacketData(void* data, size_t size, int start_num, int flag) final;
	virtual void push_packet_sortbySeqnum(std::list<struct packetData *> *buffer, struct packetData *data) final;
	virtual bool deleteBeforeAcknum_senderBuffer(struct socketInterface *socket, int oppo_ack) final;
	virtual struct timerArgs* make_TimerArgs(struct socketInterface *socket, struct packetData *data, int flag) final;
	virtual void direct_retransmit(struct socketInterface *socket) final;

	virtual struct socketInterface* find_sock_byId(int pid, int sockfd) final;
	virtual struct socketInterface* find_sock_byAddr(in_addr_t addr, in_port_t port) final;
	virtual struct socketInterface* find_sock_byConnection(in_addr_t oppo_addr, in_port_t oppo_port, in_addr_t my_addr, in_port_t my_port) final;
	virtual struct socketInterface* find_childsock_byId(int pid, int parentfd) final;
	virtual struct acceptSyscallArgs* find_acceptSyscall_byId(int pid, int parentfd) final;
	virtual struct dataSyscallArgs* find_dataSyscall_byUUID(UUID syscallUUID) final;
	virtual unsigned short estimate_oppo_window(struct socketInterface *socket, int oppo_ack) final;

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
	std::list<struct socketInterface*> socket_list;	
	std::list<struct acceptSyscallArgs*> acceptUUID_list;
	std::list<struct dataSyscallArgs*> dataUUID_list;

	const size_t PACKETH_SIZE = 54;
	const size_t EH_SIZE = 14;
	const size_t IH_SIZE = 34;
	const size_t MSS = 512;

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

enum State
{
	TCP_CLOSED,
	TCP_LISTEN,
	TCP_SYN_SENT,
	TCP_SYN_RCVD,
	TCP_ESTAB,
	TCP_FIN_WAIT1,
	TCP_FIN_WAIT2,
	TCP_TIMED_WAIT,
	TCP_CLOSE_WAIT,
	TCP_LAST_ACK,
	TCP_CLOSING
};

enum Flag
{
	FLAG_SYN = 0x02,
	FLAG_SYNACK = 0x012,
	FLAG_ACK = 0x010,
	FLAG_FINACK = 0x011
};

enum Congestion_State
{
	CON_SLOW_START,
	CON_AVOID,
	CON_FAST_RECOVERY
};

enum Timer_Flag
{
	TIMER_PACKET,
	TIMER_WAIT,
	TIMER_SOCKET
};

struct acceptSyscallArgs
{
	UUID syscallUUID;
	int pid;
	int parentfd;

	struct sockaddr *addr;
	socklen_t *addrlen;
};

struct dataSyscallArgs
{
	UUID syscallUUID;

	void *buf;
	size_t count;
};

struct packetData
{
	void* data;
	size_t size;
	int start_num;
	size_t now;
	int flag;

	UUID timer;
	struct timerArgs *timer_args;
};

struct timerArgs
{
	struct socketInterface *socket;
	struct packetData *packet;
	int flag;
};

struct socketInterface
{
	int sockfd;
	int pid;
	int type;
	int protocol;
	
	State state;

	// my address part
	struct sockaddr_in *myaddr;
	socklen_t myaddr_len;
	int seqnum;
	bool is_myaddr_exist;

	// opponent address part
	struct sockaddr_in *oppoaddr;
	socklen_t oppoaddr_len;
	int acknum;
	bool is_oppoaddr_exist;

	// for blocking syscall
	UUID conn_syscallUUID;
	UUID accept_syscallUUID;
	UUID read_syscallUUID;
	UUID write_syscallUUID;

	// informations about listen()
	int max_backlog;
	int curr_backlog;
	int parent_sockfd;

	UUID timed_wait_timer;
	UUID congestion_timer;

	// internal sender buffer
	std::list<struct packetData *> *sender_buffer;
	size_t sender_unused;
	size_t cwnd_max;
	size_t cwnd_using;
	std::list<struct packetData *> *receiver_buffer;
	size_t receiver_unused;
	unsigned short oppo_window;

	int sender_buffer_last;
	int dupl_num;
	int sender_recentack;
	bool sender_ackchange;

	size_t ssthresh;
	int con_state;
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */
