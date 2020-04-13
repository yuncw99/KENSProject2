/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"

namespace E
{

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{

}

void TCPAssignment::finalize()
{

}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	int ret;
	switch(param.syscallNumber)
	{
	case SOCKET:
		ret = this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		returnSystemCall(syscallUUID, ret);
		break;
	case CLOSE:
		ret = this->syscall_close(syscallUUID, pid, param.param1_int);
		returnSystemCall(syscallUUID, ret);
		break;
	case READ:
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		ret = this->syscall_connect(syscallUUID, pid, param.param1_int,
			static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		
		if (ret == -1)
			returnSystemCall(syscallUUID, ret);
		break;
	case LISTEN:
		ret = this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		returnSystemCall(syscallUUID, ret);
		break;
	case ACCEPT:
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		ret = this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		returnSystemCall(syscallUUID, ret);
		break;
	case GETSOCKNAME:
		ret = this->syscall_getsockname(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		returnSystemCall(syscallUUID, ret);
		break;
	case GETPEERNAME:
		ret = this->syscall_getpeername(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		returnSystemCall(syscallUUID, ret);
		break;
	default:
		assert(0);
	}
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
	struct socketInterface *temp;
	unsigned char flag;
	int oppo_seq, oppo_ack;
	UUID returnUUID;

	in_addr_t src_ip, dest_ip;
	in_port_t src_port, dest_port;
	int dupl_fd;
	struct socketInterface *dupl_sock;

	// read packet
	packet->readData(EH_SIZE+12, &src_ip, 4);
	packet->readData(IH_SIZE, &src_port, 2);
	packet->readData(EH_SIZE+16, &dest_ip, 4);
	packet->readData(IH_SIZE+2, &dest_port, 2);

	packet->readData(IH_SIZE+13, &flag, 1);
	packet->readData(IH_SIZE+8, &oppo_ack, 4);
	packet->readData(IH_SIZE+4, &oppo_seq, 4);

	// find socket by Connection
	temp = find_sock_byConnection(src_ip, src_port, dest_ip, dest_port);
	// find socket by destination port only. for LISTEN.
	if(temp == NULL)
		temp = find_sock_byPort(dest_port);
	if(temp == NULL)
		return;

	// receiving SYNACK or duplicate connect
	if(temp->state == TCP_SYN_SENT) {
		temp->seqnum = oppo_ack;
		temp->acknum = htonl(ntohl(oppo_seq) + 1);

		// on duplicate connect. active
		if(flag == FLAG_SYN) {
			send_packet(temp, FLAG_SYNACK);
			temp->state = TCP_SYN_RCVD;

		// on receiving SYNACK properly. active
		} else if(flag == FLAG_SYNACK) {
			send_packet(temp, FLAG_ACK);
			temp->state = TCP_ESTAB;

			returnUUID = temp->conn_syscallUUID;
			temp->conn_syscallUUID = 0;
			printf("return syscall! : %d\n", returnUUID);
			returnSystemCall(returnUUID, 0);
		}

	// handling duplicate connect
	} else if(temp->state == TCP_SYN_RCVD) {
		temp->seqnum = oppo_ack;
		temp->acknum = htonl(ntohl(oppo_seq) + 1);

		// on duplicate connect. active
		if(flag == FLAG_SYNACK) {
			send_packet(temp, FLAG_ACK);
			temp->state = TCP_ESTAB;

			returnUUID = temp->conn_syscallUUID;
			temp->conn_syscallUUID = 0;
			printf("return syscall! : %d\n", returnUUID);
			returnSystemCall(returnUUID, 0);

		// on receiving ACK properly. passive
		} 
		// else if(flag == FLAG_ACK) {
		// 	temp->state = TCP_ESTAB;

		// 	returnUUID = temp->accept_syscallUUID;
		// 	temp->accept_syscallUUID = 0;
		// 	printf("return syscall! : %d\n", returnUUID);
		// 	returnSystemCall(returnUUID, 0);
		// }

	// handling SYN
	} else if(temp->state == TCP_LISTEN) {
		// on receiving SYN. passive
		if(flag == FLAG_SYN && temp->curr_backlog < temp->max_backlog) {
			dupl_fd = make_DuplSocket(temp, src_ip, src_port, dest_ip, dest_port);
			dupl_sock = find_sock_byId(dupl_fd);

			//dupl_sock->seqnum = oppo_ack;
			dupl_sock->acknum = htonl(ntohl(oppo_seq) + 1);

			send_packet(dupl_sock, FLAG_SYNACK);
			dupl_sock->state = TCP_SYN_RCVD;

			temp->curr_backlog += 1;
			dupl_sock->parent_sockfd = temp->sockfd;
			printf("curr backlog : %d, max backlog : %d\n", temp->curr_backlog, temp->max_backlog);
		}
	}

	return;
}

void TCPAssignment::timerCallback(void* payload)
{

}

int TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int type, int protocol)
{
	int sockfd;
	sockfd = createFileDescriptor(pid);

	struct socketInterface *new_sock = (struct socketInterface*) malloc(sizeof(struct socketInterface));
	new_sock->sockfd = sockfd;
	new_sock->pid = pid;
	new_sock->type = type;
	new_sock->protocol = protocol;
	new_sock->state = TCP_CLOSED;
	new_sock->is_myaddr_exist = false;
	new_sock->is_oppoaddr_exist = false;

	socket_list.push_back(new_sock);

	return sockfd;
}

int TCPAssignment::syscall_close(UUID syscallUUID, int pid, int sockfd)
{
	struct socketInterface *temp;
	temp = find_sock_byId(sockfd);

	if(temp == NULL)
		return -1;

	socket_list.remove(temp);
	if(temp->is_myaddr_exist)
		free(temp->myaddr);
	if(temp->is_oppoaddr_exist)
		free(temp->oppoaddr);
	free(temp);
	
	removeFileDescriptor(pid, sockfd);
	return 0;
}

int TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *my_addr, socklen_t addrlen)
{
	struct socketInterface *temp;
	temp = find_sock_byId(sockfd);

	if(temp == NULL || temp->is_myaddr_exist)
		return -1;

	if(is_overlapped((struct sockaddr_in*)my_addr))
		return -1;

	temp->myaddr = (struct sockaddr_in *) malloc(addrlen);
	memcpy(temp->myaddr, my_addr, addrlen);
	temp->myaddr_len = addrlen;
	temp->seqnum = 0;
	temp->is_myaddr_exist = true;

	return 0;
}

int TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	struct socketInterface *temp;
	temp = find_sock_byId(sockfd);

	if(temp == NULL || !temp->is_myaddr_exist)
		return -1;

	memcpy(addr, temp->myaddr, temp->myaddr_len);
	addrlen = &temp->myaddr_len;

	return 0;
}

int TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen)
{
	struct socketInterface *my_sock;
	struct sockaddr_in *my_addr;

	in_addr_t *src_ip, *dest_ip;
	in_port_t temp_port;
	bool impl_bind_res = false;
	my_sock = find_sock_byId(sockfd);

	if(my_sock == NULL || my_sock->is_oppoaddr_exist)
		return -1;

	// implicit bind.
	if(!my_sock->is_myaddr_exist) {
		my_addr = (struct sockaddr_in *) malloc(addrlen);
		src_ip = (in_addr_t *) malloc(sizeof(in_addr_t));
		dest_ip = (in_addr_t *) &(((struct sockaddr_in *)addr)->sin_addr.s_addr);
		temp_port = getHost()->getRoutingTable((uint8_t *) dest_ip);
		
		impl_bind_res = getHost()->getIPAddr((uint8_t *)src_ip, temp_port);

		if(impl_bind_res) {
			my_addr->sin_addr.s_addr = *src_ip;
			my_addr->sin_port = htons(temp_port + 46000 + my_sock->sockfd);
			my_addr->sin_family = 2;

			if(is_overlapped(my_addr)) {
				free(src_ip);
				free(my_addr);
				return -1;
			}

			my_sock->myaddr = (struct sockaddr_in *) malloc(addrlen);
			memcpy(my_sock->myaddr, my_addr, addrlen);
			my_sock->myaddr_len = addrlen;
			my_sock->seqnum = 0;
			my_sock->is_myaddr_exist = true;
		}

		free(src_ip);
		free(my_addr);
		
		if(!impl_bind_res)
			return -1;
	}

	// connect to opponent.
	my_sock->oppoaddr = (struct sockaddr_in *) malloc(addrlen);
	memcpy(my_sock->oppoaddr, addr, addrlen);
	my_sock->oppoaddr_len = addrlen;
	my_sock->acknum = 0;
	my_sock->is_oppoaddr_exist = true;
	printf("dest : %x, port : %d, src : %x, port : %d\n", ntohl(my_sock->oppoaddr->sin_addr.s_addr), my_sock->oppoaddr->sin_port, ntohl(my_sock->myaddr->sin_addr.s_addr), my_sock->myaddr->sin_port);

	// send SYN packet.
	send_packet(my_sock, FLAG_SYN);
	my_sock->state = TCP_SYN_SENT;

	// save syscallUUID for receiving SYNACK
	my_sock->conn_syscallUUID = syscallUUID;

	return 0;
}

int TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	struct socketInterface *temp;
	temp = find_sock_byId(sockfd);

	if(temp == NULL || !temp->is_oppoaddr_exist)
		return -1;

	memcpy(addr, temp->oppoaddr, temp->oppoaddr_len);
	addrlen = &temp->oppoaddr_len;

	return 0;
}

int TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog)
{
	struct socketInterface *temp;
	temp = find_sock_byId(sockfd);

	if(temp == NULL || !temp->is_myaddr_exist)
		return -1;

	// change state to listen.
	temp->max_backlog = backlog;
	temp->curr_backlog = 0;
	temp->state = TCP_LISTEN;

	return 0;
}

struct socketInterface* TCPAssignment::find_sock_byId(int sockfd)
{
	list<struct socketInterface*>::iterator iter;

	for(iter = socket_list.begin(); iter != socket_list.end(); iter++) {
		if((*iter)->sockfd == sockfd)
			return *iter;
	}

	return NULL;
}

struct socketInterface* TCPAssignment::find_sock_byPort(in_port_t port)
{
	list<struct socketInterface*>::iterator iter;

	for(iter = socket_list.begin(); iter != socket_list.end(); iter++) {
		if((*iter)->is_myaddr_exist && (*iter)->myaddr->sin_port == port)
			return *iter;
	}

	return NULL;
}

struct socketInterface* TCPAssignment::find_sock_byConnection(in_addr_t src_ip, in_port_t src_port, in_addr_t dest_ip, in_port_t dest_port)
{
	list<struct socketInterface*>::iterator iter;

	for(iter = socket_list.begin(); iter != socket_list.end(); iter++) {
		if((*iter)->is_myaddr_exist && (*iter)->myaddr->sin_addr.s_addr == dest_ip && (*iter)->myaddr->sin_port == dest_port) {
			if((*iter)->is_oppoaddr_exist && (*iter)->oppoaddr->sin_addr.s_addr == src_ip && (*iter)->oppoaddr->sin_port == src_port)
				return *iter;
		}
	}

	return NULL;
}

bool TCPAssignment::is_overlapped(struct sockaddr_in *my_addr)
{
	list<struct socketInterface*>::iterator iter;
	struct sockaddr_in *temp;

	for(iter = socket_list.begin(); iter != socket_list.end(); iter++) {
		if((*iter)->is_myaddr_exist == false)
			continue;

		temp = (*iter)->myaddr;
		if(my_addr->sin_addr.s_addr == temp->sin_addr.s_addr && my_addr->sin_port == temp->sin_port)
			return true;
		if((ntohl(my_addr->sin_addr.s_addr) == 0 || ntohl(temp->sin_addr.s_addr) == 0) && my_addr->sin_port == temp->sin_port)
			return true;
	}

	return false;
}

void TCPAssignment::send_packet(struct socketInterface *sender, unsigned char flag)
{
	Packet *myPacket = this->allocatePacket(PACKETH_SIZE);

	in_addr_t src_ip = sender->myaddr->sin_addr.s_addr;
	in_addr_t dest_ip = sender->oppoaddr->sin_addr.s_addr;
	unsigned short checksum;
	unsigned char header_len = 0x05 << 4;
	unsigned short window = htons(51200);
	uint8_t *tcp_seg = (uint8_t *)malloc(20);

	myPacket->writeData(EH_SIZE+12, &src_ip, 4);
	myPacket->writeData(EH_SIZE+16, &dest_ip, 4);
	myPacket->writeData(IH_SIZE, &sender->myaddr->sin_port, 2);
	myPacket->writeData(IH_SIZE+2, &sender->oppoaddr->sin_port, 2);

	myPacket->writeData(IH_SIZE+4, &sender->seqnum, 4);
	myPacket->writeData(IH_SIZE+8, &sender->acknum, 4);
	myPacket->writeData(IH_SIZE+12, &header_len, 1);
	myPacket->writeData(IH_SIZE+13, &flag, 1);
	myPacket->writeData(IH_SIZE+14, &window, 2);

	myPacket->readData(IH_SIZE, tcp_seg, 20);
	checksum = htons(~NetworkUtil::tcp_sum(src_ip, dest_ip, tcp_seg, 20));
	printf("checksum : %x\n", checksum);
	myPacket->writeData(IH_SIZE+16, &checksum, 2);

	this->sendPacket("IPv4", myPacket);
	free(tcp_seg);

	return;
}

int TCPAssignment::make_DuplSocket(struct socketInterface *listener, in_addr_t oppo_addr, in_port_t oppo_port, in_addr_t my_addr, in_port_t my_port)
{
	int sockfd = createFileDescriptor(listener->pid);
	socklen_t addrlen = sizeof(struct sockaddr_in);
	struct sockaddr_in *oppo_info = (struct sockaddr_in *) malloc(addrlen);
	struct socketInterface *dupl_sock = (struct socketInterface*) malloc(sizeof(struct socketInterface));

	// duplicate socket listener.
	memcpy(dupl_sock, listener, sizeof(struct socketInterface));
	dupl_sock->sockfd = sockfd;

	// put my addr information.
	dupl_sock->myaddr->sin_addr.s_addr = my_addr;
	dupl_sock->myaddr->sin_port = my_port;
	dupl_sock->myaddr->sin_family = 2;

	dupl_sock->myaddr_len = addrlen;
	dupl_sock->seqnum = 0;
	dupl_sock->is_myaddr_exist = true;

	// put opponent addr information.
	oppo_info->sin_addr.s_addr = oppo_addr;
	oppo_info->sin_port = oppo_port;
	oppo_info->sin_family = 2;

	dupl_sock->oppoaddr = (struct sockaddr_in *) malloc(addrlen);
	memcpy(dupl_sock->oppoaddr, oppo_info, addrlen);
	free(oppo_info);

	dupl_sock->oppoaddr_len = addrlen;
	dupl_sock->acknum = 0;
	dupl_sock->is_oppoaddr_exist = true;

	socket_list.push_back(dupl_sock);

	return sockfd;
}

}
