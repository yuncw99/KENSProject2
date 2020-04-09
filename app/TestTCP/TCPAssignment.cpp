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
		//this->syscall_connect(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
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
	new_sock->is_bind = false;

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
	if(temp->is_bind)
		free(temp->myaddr);
	free(temp);
	
	removeFileDescriptor(pid, sockfd);
	return 0;
}

int TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *my_addr, socklen_t addrlen)
{
	struct socketInterface *temp;
	temp = find_sock_byId(sockfd);

	if(temp == NULL || temp->is_bind)
		return -1;

	if(is_overlapped((struct sockaddr_in*)my_addr))
		return -1;

	temp->myaddr = (struct sockaddr *) malloc(addrlen);
	memcpy(temp->myaddr, my_addr, addrlen);
	temp->myaddr_len = addrlen;
	temp->is_bind = true;

	return 0;
}

int TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	struct socketInterface *temp;
	temp = find_sock_byId(sockfd);

	if(temp == NULL || !temp->is_bind)
		return -1;

	//addr = temp->myaddr;
	memcpy(addr, temp->myaddr, temp->myaddr_len);
	addrlen = &temp->myaddr_len;

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
		if((*iter)->is_bind == false)
			continue;

		temp = (struct sockaddr_in*) (*iter)->myaddr;
		if(my_addr->sin_addr.s_addr == temp->sin_addr.s_addr && my_addr->sin_port == temp->sin_port)
			return true;
		if((ntohl(my_addr->sin_addr.s_addr) == 0 || ntohl(temp->sin_addr.s_addr) == 0) && my_addr->sin_port == temp->sin_port)
			return true;
	}

	return false;
}

}
