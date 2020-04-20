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

		if (ret >= -1)
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
		ret = this->syscall_accept(syscallUUID, pid, param.param1_int,
			static_cast<struct sockaddr*>(param.param2_ptr),
			static_cast<socklen_t*>(param.param3_ptr));

		if (ret >= -1)
			returnSystemCall(syscallUUID, ret);
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
	struct socketInterface *parent_sock;
	struct acceptSyscallArgs *syscallArgs;

	// read packet
	packet->readData(EH_SIZE+12, &src_ip, 4);
	packet->readData(IH_SIZE, &src_port, 2);
	packet->readData(EH_SIZE+16, &dest_ip, 4);
	packet->readData(IH_SIZE+2, &dest_port, 2);

	packet->readData(IH_SIZE+13, &flag, 1);
	packet->readData(IH_SIZE+8, &oppo_ack, 4);
	packet->readData(IH_SIZE+4, &oppo_seq, 4);

	this->freePacket(packet);

	// find socket by Connection
	temp = find_sock_byConnection(src_ip, src_port, dest_ip, dest_port);
	// find socket by destination port only. for LISTEN.
	if(temp == NULL)
		temp = find_sock_byAddr(dest_ip, dest_port);
	if(temp == NULL)
		return;

	//printf("packetArrived. state : %d\n", temp->state);
	// receiving SYNACK or duplicate connect
	if(temp->state == TCP_SYN_SENT) {
		// on duplicate connect. active
		if(flag == FLAG_SYN) {
			//temp->seqnum = oppo_ack;
			temp->acknum = htonl(ntohl(oppo_seq) + 1);

			send_packet(temp, FLAG_SYNACK);
			temp->state = TCP_SYN_RCVD;

		// on receiving SYNACK properly. active
		} else if(flag == FLAG_SYNACK) {
			temp->seqnum = oppo_ack;
			temp->acknum = htonl(ntohl(oppo_seq) + 1);

			send_packet(temp, FLAG_ACK);
			temp->state = TCP_ESTAB;

			returnUUID = temp->conn_syscallUUID;
			temp->conn_syscallUUID = -1;
			//printf("return syscall! : %d\n", returnUUID);
			returnSystemCall(returnUUID, 0);
		}

	// handling duplicate connect
	} else if(temp->state == TCP_SYN_RCVD) {
		// on duplicate connect. active
		if(flag == FLAG_SYNACK) {
			//temp->seqnum = oppo_ack;
			temp->acknum = htonl(ntohl(oppo_seq) + 1);

			send_packet(temp, FLAG_ACK);
			temp->state = TCP_ESTAB;

			returnUUID = temp->conn_syscallUUID;
			temp->conn_syscallUUID = 0;
			//printf("return syscall! : %d\n", returnUUID);
			returnSystemCall(returnUUID, 0);

		// on receiving ACK properly. passive
		} else if(flag == FLAG_ACK) {
			//temp->seqnum = oppo_ack;
			temp->acknum = oppo_seq;

			temp->state = TCP_ESTAB;
			parent_sock = find_sock_byId(temp->pid, temp->parent_sockfd);
			parent_sock->curr_backlog -= 1;
			//printf("ack! backlog : %d, syscallID : %d\n", parent_sock->curr_backlog, temp->accept_syscallUUID);
			//printf("myaddr : %x, myport : %d, oppoaddr : %x, oppoport : %d\n", temp->myaddr->sin_addr.s_addr, temp->myaddr->sin_port, temp->oppoaddr->sin_addr.s_addr, temp->oppoaddr->sin_port);

			// if accept() syscall already called.
			if(temp->accept_syscallUUID != (UUID)-1) {
				temp->parent_sockfd = -1;
				returnUUID = temp->accept_syscallUUID;
				temp->accept_syscallUUID = -1;
				//printf("return syscall! : %d, sockfd : %d\n", returnUUID, temp->sockfd);
				returnSystemCall(returnUUID, temp->sockfd);
			}
		}

	// handling SYN
	} else if(temp->state == TCP_LISTEN) {
		// on receiving SYN. passive
		if(flag == FLAG_SYN && temp->curr_backlog < temp->max_backlog) {
			dupl_fd = make_DuplSocket(temp, src_ip, src_port, dest_ip, dest_port);
			dupl_sock = find_sock_byId(temp->pid, dupl_fd);

			dupl_sock->seqnum = oppo_ack;
			dupl_sock->acknum = htonl(ntohl(oppo_seq) + 1);

			send_packet(dupl_sock, FLAG_SYNACK);

			// if accept() called before dupl_sock creates.
			if(acceptUUID_list.size() != 0 && dupl_sock->accept_syscallUUID == (UUID)-1) {
				syscallArgs = acceptUUID_list.front();

				dupl_sock->accept_syscallUUID = syscallArgs->syscallUUID;
				memcpy(syscallArgs->addr, dupl_sock->oppoaddr, dupl_sock->oppoaddr_len);
				syscallArgs->addrlen = &dupl_sock->oppoaddr_len;
				acceptUUID_list.pop_front();
				free(syscallArgs);
			}
			
			temp->curr_backlog += 1;
			dupl_sock->parent_sockfd = temp->sockfd;
			dupl_sock->state = TCP_SYN_RCVD;

			//printf("curr backlog : %d, max backlog : %d, fd : %d\n", temp->curr_backlog, temp->max_backlog, dupl_sock->sockfd);
		}

	// handling FINACK client side
	} else if(temp->state == TCP_FIN_WAIT1) {
		if(flag == FLAG_ACK) {
			//temp->seqnum = oppo_ack;
			temp->acknum = oppo_seq;

			temp->state = TCP_FIN_WAIT2;

		// handling simultaneous close
		} else if(flag == FLAG_FINACK) {
			//temp->seqnum = oppo_ack;
			temp->acknum = htonl(ntohl(oppo_seq) + 1);

			send_packet(temp, FLAG_ACK);
			temp->state = TCP_CLOSING;
		}
	} else if(temp->state == TCP_FIN_WAIT2 || temp->state == TCP_TIMED_WAIT) {
		if(flag == FLAG_FINACK) {
			//temp->seqnum = oppo_ack;
			temp->acknum = htonl(ntohl(oppo_seq) + 1);

			send_packet(temp, FLAG_ACK);

			if(temp->state == TCP_TIMED_WAIT)
				cancelTimer(temp->close_timer);
			temp->close_timer = addTimer(temp, 120);

			temp->state = TCP_TIMED_WAIT;
		}

	// handling simultaneous close
	} else if(temp->state == TCP_CLOSING) {
		if(flag == FLAG_ACK) {
			//temp->seqnum = oppo_ack;
			temp->acknum = oppo_seq;

			if(temp->state == TCP_TIMED_WAIT)
				cancelTimer(temp->close_timer);
			temp->close_timer = addTimer(temp, 120);
	
			temp->state = TCP_TIMED_WAIT;
		}

	// handling FINACK server side
	} else if(temp->state == TCP_ESTAB) {
		if(flag == FLAG_FINACK) {
			printf("received FINACK!\n");
			//temp->seqnum = oppo_ack;
			temp->acknum = htonl(ntohl(oppo_seq) + 1);

			send_packet(temp, FLAG_ACK);
			temp->state = TCP_CLOSE_WAIT;
		}
	} else if(temp->state == TCP_LAST_ACK) {
		if(flag == FLAG_ACK) {
			printf("received last ACK!\n");
			//temp->seqnum = oppo_ack;
			temp->acknum = oppo_seq;

			temp->state = TCP_CLOSED;

			returnUUID = temp->close_syscallUUID;
			remove_socket(temp);

			returnSystemCall(returnUUID, 0);
		}
	}

	return;
}

void TCPAssignment::timerCallback(void* payload)
{
	printf("timer!\n");
	UUID returnUUID;

	struct socketInterface *timed_socket = (struct socketInterface *) payload;
	cancelTimer(timed_socket->close_timer);

	returnUUID = timed_socket->close_syscallUUID;
	timed_socket->state = TCP_CLOSED;
	remove_socket(timed_socket);

	returnSystemCall(returnUUID, 0);
}

int TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int type, int protocol)
{
	int sockfd;
	sockfd = createFileDescriptor(pid);

	// initialize.
	struct socketInterface *new_sock = (struct socketInterface*) malloc(sizeof(struct socketInterface));
	new_sock->sockfd = sockfd;
	new_sock->pid = pid;
	new_sock->type = type;
	new_sock->protocol = protocol;
	new_sock->state = TCP_CLOSED;
	new_sock->is_myaddr_exist = false;
	new_sock->is_oppoaddr_exist = false;

	new_sock->conn_syscallUUID = -1;
	new_sock->accept_syscallUUID = -1;
	new_sock->close_syscallUUID = -1;
	new_sock->parent_sockfd = -1;

	socket_list.push_back(new_sock);
	return sockfd;
}

int TCPAssignment::syscall_close(UUID syscallUUID, int pid, int sockfd)
{
	struct socketInterface *temp;
	temp = find_sock_byId(pid, sockfd);

	if(temp == NULL)
		return -1;

	// close() syscall. active close and passive close.
	if(temp->state == TCP_ESTAB) {
		// send FINACK packet.
		send_packet(temp, FLAG_FINACK);
		temp->state = TCP_FIN_WAIT1;

		// save syscallUUID for receiving SYNACK
		temp->close_syscallUUID = syscallUUID;

		return -2;
	} else if(temp->state == TCP_CLOSE_WAIT) {
		// send FINACK packet.
		send_packet(temp, FLAG_FINACK);
		temp->state = TCP_LAST_ACK;

		// save syscallUUID for receiving SYNACK
		temp->close_syscallUUID = syscallUUID;

		return -2;
	}

	remove_socket(temp);
	return 0;
}

int TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *my_addr, socklen_t addrlen)
{
	struct socketInterface *temp;
	temp = find_sock_byId(pid, sockfd);
	//printf("bind!, fd : %d, socket list size : %d\n", sockfd, socket_list.size());
	//printf("addr : %x, port : %d\n", ((struct sockaddr_in *)my_addr)->sin_addr.s_addr, ((struct sockaddr_in *)my_addr)->sin_port);
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
	temp = find_sock_byId(pid, sockfd);

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
	my_sock = find_sock_byId(pid, sockfd);

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
	//printf("dest : %x, port : %d, src : %x, port : %d\n", ntohl(my_sock->oppoaddr->sin_addr.s_addr), my_sock->oppoaddr->sin_port, ntohl(my_sock->myaddr->sin_addr.s_addr), my_sock->myaddr->sin_port);

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
	temp = find_sock_byId(pid, sockfd);

	if(temp == NULL || !temp->is_oppoaddr_exist)
		return -1;

	memcpy(addr, temp->oppoaddr, temp->oppoaddr_len);
	addrlen = &temp->oppoaddr_len;

	return 0;
}

int TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog)
{
	struct socketInterface *temp;
	temp = find_sock_byId(pid, sockfd);

	if(temp == NULL || !temp->is_myaddr_exist)
		return -1;

	// change state to listen.
	temp->max_backlog = backlog;
	temp->curr_backlog = 0;

	temp->state = TCP_LISTEN;

	return 0;
}

int TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	struct socketInterface *temp;
	struct socketInterface *child_sock;
	struct acceptSyscallArgs *syscallArgs;

	temp = find_sock_byId(pid, sockfd);

	if(temp == NULL || !temp->is_myaddr_exist)
		return -1;

	child_sock = find_childsock_byId(pid, sockfd);

	// if there is no established socket.
	// if no dupl sockets. save UUID in global list.
	if(child_sock == NULL) {
		//printf("accept : no established. \n");

		syscallArgs = (struct acceptSyscallArgs *) malloc(sizeof(struct acceptSyscallArgs));
		syscallArgs->syscallUUID = syscallUUID;
		syscallArgs->addr = addr;
		syscallArgs->addrlen = addrlen;
		acceptUUID_list.push_back(syscallArgs);

		return -2;
	}
	
	// if dupl socket exists, save UUID in child_sock.
	if(child_sock->state != TCP_ESTAB && child_sock->state != TCP_CLOSE_WAIT) {
		//printf("accept : no established. \n");
		child_sock->accept_syscallUUID = syscallUUID;

		//printf("family. addr : %d, child_sock : %d\n", addr->sa_family, child_sock->oppoaddr->sin_family);
		memcpy(addr, child_sock->oppoaddr, child_sock->oppoaddr_len);
		addrlen = &child_sock->oppoaddr_len;

		return -2;
	}

	// if there is established socket.
	//printf("accept : established. %d\n", child_sock->sockfd);
	memcpy(addr, child_sock->oppoaddr, child_sock->oppoaddr_len);
	addrlen = &child_sock->oppoaddr_len;

	child_sock->parent_sockfd = -1;
	return child_sock->sockfd;
}

struct socketInterface* TCPAssignment::find_sock_byId(int pid, int sockfd)
{
	std::list<struct socketInterface*>::iterator iter;

	for(iter = socket_list.begin(); iter != socket_list.end(); iter++) {
		if((*iter)->pid == pid && (*iter)->sockfd == sockfd)
			return *iter;
	}

	return NULL;
}

struct socketInterface* TCPAssignment::find_sock_byAddr(in_addr_t addr, in_port_t port)
{
	std::list<struct socketInterface*>::iterator iter;

	for(iter = socket_list.begin(); iter != socket_list.end(); iter++) {
		if((*iter)->is_myaddr_exist && ((*iter)->myaddr->sin_addr.s_addr == addr || (*iter)->myaddr->sin_addr.s_addr == 0) && (*iter)->myaddr->sin_port == port)
			return *iter;
	}

	return NULL;
}

struct socketInterface* TCPAssignment::find_sock_byConnection(in_addr_t oppo_addr, in_port_t oppo_port, in_addr_t my_addr, in_port_t my_port)
{
	std::list<struct socketInterface*>::iterator iter;

	for(iter = socket_list.begin(); iter != socket_list.end(); iter++) {
		if((*iter)->is_myaddr_exist && (*iter)->myaddr->sin_addr.s_addr == my_addr && (*iter)->myaddr->sin_port == my_port) {
			if((*iter)->is_oppoaddr_exist && (*iter)->oppoaddr->sin_addr.s_addr == oppo_addr && (*iter)->oppoaddr->sin_port == oppo_port)
				return *iter;
		}
	}

	return NULL;
}

struct socketInterface* TCPAssignment::find_childsock_byId(int pid, int parentfd)
{
	std::list<struct socketInterface*>::iterator iter;

	for(iter = socket_list.begin(); iter != socket_list.end(); iter++) {
		if((*iter)->pid == pid && (*iter)->parent_sockfd == parentfd)
			return *iter;
	}

	return NULL;
}

bool TCPAssignment::is_overlapped(struct sockaddr_in *my_addr)
{
	std::list<struct socketInterface*>::iterator iter;
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
	//printf("checksum : %x\n", checksum);
	myPacket->writeData(IH_SIZE+16, &checksum, 2);

	this->sendPacket("IPv4", myPacket);
	free(tcp_seg);

	if(flag != FLAG_SYN && flag != FLAG_ACK)
		sender->seqnum = ntohl(htonl(sender->seqnum) + 1);

	return;
}

int TCPAssignment::make_DuplSocket(struct socketInterface *listener, in_addr_t oppo_addr, in_port_t oppo_port, in_addr_t my_addr, in_port_t my_port)
{
	int sockfd = createFileDescriptor(listener->pid);
	struct sockaddr_in *oppo_info;
	struct socketInterface *dupl_sock = (struct socketInterface*) malloc(sizeof(struct socketInterface));
	socklen_t addr_len = listener->myaddr_len;

	// initialize dupl_sock
	dupl_sock->sockfd = sockfd;
	dupl_sock->pid = listener->pid;
	dupl_sock->type = listener->type;
	dupl_sock->protocol = listener->protocol;
	dupl_sock->state = TCP_CLOSED;

	dupl_sock->conn_syscallUUID = -1;
	dupl_sock->accept_syscallUUID = -1;
	dupl_sock->parent_sockfd = -1;

	// change listener myaddr information. 0 to real addr.
	listener->myaddr->sin_addr.s_addr = my_addr;
	listener->myaddr->sin_port = my_port;
	listener->myaddr->sin_family = 2;

	// put my addr information.
	dupl_sock->myaddr = (struct sockaddr_in *) malloc(addr_len);
	memcpy(dupl_sock->myaddr, listener->myaddr, addr_len);

	dupl_sock->myaddr_len = addr_len;
	dupl_sock->seqnum = 0;
	dupl_sock->is_myaddr_exist = true;

	// put opponent addr information.
	oppo_info = (struct sockaddr_in *) malloc(addr_len);
	oppo_info->sin_addr.s_addr = oppo_addr;
	oppo_info->sin_port = oppo_port;
	oppo_info->sin_family = 2;

	dupl_sock->oppoaddr = (struct sockaddr_in *) malloc(addr_len);
	memcpy(dupl_sock->oppoaddr, oppo_info, addr_len);
	free(oppo_info);

	dupl_sock->oppoaddr_len = addr_len;
	dupl_sock->acknum = 0;
	dupl_sock->is_oppoaddr_exist = true;

	socket_list.push_back(dupl_sock);

	return sockfd;
}

void TCPAssignment::remove_socket(struct socketInterface *socket)
{
	socket_list.remove(socket);
	if(socket->is_myaddr_exist)
		free(socket->myaddr);
	if(socket->is_oppoaddr_exist)
		free(socket->oppoaddr);

	removeFileDescriptor(socket->pid, socket->sockfd);
	free(socket);
}

}
