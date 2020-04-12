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
		//this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
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
		//this->syscall_getpeername(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{

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
	new_sock->type = type;
	new_sock->protocol = protocol;
	new_sock->state = CLOSED;
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
	temp->my_seqnum = 0;
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
	my_addr = (struct sockaddr_in *) malloc(addrlen);
	src_ip = (in_addr_t *) malloc(sizeof(in_addr_t));
	dest_ip = (in_addr_t *) &(((struct sockaddr_in *)addr)->sin_addr.s_addr);
	temp_port = getHost()->getRoutingTable((uint8_t *) dest_ip);
	
	impl_bind_res = getHost()->getIPAddr((uint8_t *)src_ip, temp_port);

	if(impl_bind_res) {
		my_addr->sin_addr.s_addr = *src_ip;
		my_addr->sin_port = temp_port;

		if(is_overlapped(my_addr)) {
			free(src_ip);
			free(my_addr);
			return -1;
		}

		my_sock->myaddr = (struct sockaddr_in *) malloc(addrlen);
		memcpy(my_sock->myaddr, my_addr, addrlen);
		my_sock->myaddr_len = addrlen;
		my_sock->my_seqnum = 0;
		my_sock->is_myaddr_exist = true;
	}

	free(src_ip);
	free(my_addr);
	
	if(!impl_bind_res)
		return -1;

	// connect to opponent.
	my_sock->oppoaddr = (struct sockaddr_in *) malloc(addrlen);
	memcpy(my_sock->oppoaddr, addr, addrlen);
	my_sock->oppoaddr_len = addrlen;
	my_sock->oppo_seqnum = 0;
	my_sock->is_oppoaddr_exist = true;
	printf("dest : %x, port : %d, src : %x, port : %d\n", ntohl(my_sock->oppoaddr->sin_addr.s_addr), my_sock->oppoaddr->sin_port, ntohl(my_sock->myaddr->sin_addr.s_addr), my_sock->myaddr->sin_port);

	// send SYN packet.
	send_SYN_packet(my_sock);
	my_sock->state = SYN_SENT;

	// save syscallUUID for receiving SYNACK
	my_sock->conn_syscallUUID = syscallUUID;

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

void TCPAssignment::send_SYN_packet(struct socketInterface *sender)
{
	Packet *myPacket = this->allocatePacket(PACKETH_SIZE);

	in_addr_t src_ip = sender->myaddr->sin_addr.s_addr;
	in_addr_t dest_ip = sender->oppoaddr->sin_addr.s_addr;
	unsigned short checksum;
	unsigned char header_len = 0x05 << 4;
	unsigned char flag = 0x02;
	uint8_t *tcp_seg = (uint8_t *)malloc(20);

	myPacket->writeData(EH_SIZE+12, &src_ip, 4);
	myPacket->writeData(EH_SIZE+16, &dest_ip, 4);
	myPacket->writeData(IH_SIZE, &sender->myaddr->sin_port, 2);
	myPacket->writeData(IH_SIZE+2, &sender->oppoaddr->sin_port, 2);

	myPacket->writeData(IH_SIZE+4, &sender->my_seqnum, 4);
	myPacket->writeData(IH_SIZE+8, &sender->oppo_seqnum, 4);
	myPacket->writeData(IH_SIZE+12, &header_len, 1);
	myPacket->writeData(IH_SIZE+13, &flag, 1);

	myPacket->readData(IH_SIZE, tcp_seg, 20);
	checksum = htons(~NetworkUtil::tcp_sum(src_ip, dest_ip, tcp_seg, 20));
	printf("checksum : %x\n", checksum);
	myPacket->writeData(IH_SIZE+16, &checksum, 2);

	this->sendPacket("IPv4", myPacket);
	free(tcp_seg);

	return;
}

}
