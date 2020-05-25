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
		ret = this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);

		if (ret != 0)
			returnSystemCall(syscallUUID, ret);
		break;
	case WRITE:
		ret = this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);

		if (ret != 0)
			returnSystemCall(syscallUUID, ret);
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
	unsigned short oppo_window;
	UUID returnUUID;

	in_addr_t src_ip, dest_ip;
	in_port_t src_port, dest_port;
	int dupl_fd;
	struct socketInterface *dupl_sock;
	struct socketInterface *parent_sock;
	struct acceptSyscallArgs *acceptSyscallArgs;
	struct dataSyscallArgs *dataSyscallArgs;

	struct packetData *packet_data;
	void *temp_data;
	size_t saved_data_len;
	size_t packetdata_size;
	unsigned short packet_checksum, calc_checksum;
	unsigned short zero = 0;

	// read packet
	packet->readData(EH_SIZE+12, &src_ip, 4);
	packet->readData(IH_SIZE, &src_port, 2);
	packet->readData(EH_SIZE+16, &dest_ip, 4);
	packet->readData(IH_SIZE+2, &dest_port, 2);

	packet->readData(IH_SIZE+13, &flag, 1);
	packet->readData(IH_SIZE+8, &oppo_ack, 4);
	packet->readData(IH_SIZE+4, &oppo_seq, 4);
	packet->readData(IH_SIZE+14, &oppo_window, 2);
	packet->readData(IH_SIZE+16, &packet_checksum, 2);

	//printf("packet received! size : %d\n", packet->getSize());
	uint8_t *tcp_seg = (uint8_t *)malloc(packet->getSize() - IH_SIZE);
	packet->writeData(IH_SIZE+16, &zero, 2);

	packet->readData(IH_SIZE, tcp_seg, packet->getSize() - IH_SIZE);
	calc_checksum = htons(~NetworkUtil::tcp_sum(src_ip, dest_ip, tcp_seg, packet->getSize() - IH_SIZE));
	//printf("packet_checksum : %x, calc_checksum : %x\n", packet_checksum, calc_checksum);
	free(tcp_seg);

	// if checksum is not valid, just ignore the packet.
	if(packet_checksum != calc_checksum) {
		printf("not valid checksum!\n");
		return;
	}

	packetdata_size = packet->getSize() - PACKETH_SIZE;
	// if packet has payload
	if(packetdata_size > 0) {
		temp_data = malloc(packetdata_size);
		packet->readData(PACKETH_SIZE, temp_data, packetdata_size);
	}
	
	this->freePacket(packet);

	// find socket by Connection
	temp = find_sock_byConnection(src_ip, src_port, dest_ip, dest_port);
	// find socket by destination port only. for LISTEN.
	if(temp == NULL)
		temp = find_sock_byAddr(dest_ip, dest_port);
	if(temp == NULL)
		return;

	temp->oppo_window = ntohs(oppo_window);

	//printf("packetArrived. state : %d\n", temp->state);

	//printf("flag : %d, state : %d\n", flag, temp->state);
	// on receiving SYN
	if(flag == FLAG_SYN) {
		// passive
		if(temp->state == TCP_LISTEN) {
			if(temp->curr_backlog < temp->max_backlog) {
				dupl_fd = make_DuplSocket(temp, src_ip, src_port, dest_ip, dest_port);
				dupl_sock = find_sock_byId(temp->pid, dupl_fd);
				
				dupl_sock->acknum = htonl(ntohl(oppo_seq) + 1);

				packet_data = make_PacketData(NULL, 0, dupl_sock->seqnum);
				dupl_sock->sender_buffer->push_back(packet_data);

				// if accept() called before dupl_sock creates.
				if(acceptUUID_list.size() != 0 && dupl_sock->accept_syscallUUID == (UUID)-1) {
					acceptSyscallArgs = find_acceptSyscall_byId(temp->pid, temp->sockfd);

					dupl_sock->accept_syscallUUID = acceptSyscallArgs->syscallUUID;

					// input address value
					memcpy(acceptSyscallArgs->addr, dupl_sock->oppoaddr, dupl_sock->oppoaddr_len);
					acceptSyscallArgs->addrlen = &dupl_sock->oppoaddr_len;
					acceptUUID_list.remove(acceptSyscallArgs);
					free(acceptSyscallArgs);
				}
				
				temp->curr_backlog += 1;
				dupl_sock->parent_sockfd = temp->sockfd;
				dupl_sock->state = TCP_SYN_RCVD;
				send_packet(dupl_sock, FLAG_SYNACK, packet_data);
			}
			//printf("curr backlog : %d, max backlog : %d, fd : %d\n", temp->curr_backlog, temp->max_backlog, dupl_sock->sockfd);

		// on duplicate connect. active
		} else {
			temp->acknum = htonl(ntohl(oppo_seq) + 1);

			packet_data = make_PacketData(NULL, 0, temp->seqnum);
			temp->sender_buffer->push_back(packet_data);

			if(temp->state == TCP_SYN_SENT)
				temp->state = TCP_SYN_RCVD;
			send_packet(temp, FLAG_SYNACK, packet_data);
		}

	} else if(flag == FLAG_SYNACK) {
		if(temp->timer != (UUID)-1)
			cancelTimer(temp->timer);
		deleteFront_senderBuffer(temp);

		temp->acknum = htonl(ntohl(oppo_seq) + 1);
		send_packet(temp, FLAG_ACK, NULL);

		// on receiving SYNACK properly. active
		if(temp->state == TCP_SYN_SENT) {
			returnUUID = temp->conn_syscallUUID;
			temp->conn_syscallUUID = -1;
			//printf("return syscall! : %d\n", returnUUID);
			returnSystemCall(returnUUID, 0);

			temp->state = TCP_ESTAB;

		// on duplicate connect. active
		} else if(temp->state == TCP_SYN_RCVD) {
			returnUUID = temp->conn_syscallUUID;
			temp->conn_syscallUUID = 0;
			//printf("return syscall! : %d\n", returnUUID);
			returnSystemCall(returnUUID, 0);

			temp->state = TCP_ESTAB;

		}

	} else if(flag == FLAG_FINACK) {
		temp->acknum = htonl(ntohl(oppo_seq) + 1);
		send_packet(temp, FLAG_ACK, NULL);

		// handling FINACK client side
		// handling simultaneous close
		if(temp->state == TCP_FIN_WAIT1) {
			temp->state = TCP_CLOSING;

		// receiving second FINACK from server
		} else if(temp->state == TCP_FIN_WAIT2 || temp->state == TCP_TIMED_WAIT) {
			temp->state = TCP_TIMED_WAIT;

		// receiving first FINACK
		} else if(temp->state == TCP_ESTAB) {
			//printf("received FINACK!\n");
			temp->state = TCP_CLOSE_WAIT;

			// if EOF!
			if(temp->read_syscallUUID != (UUID)-1) {
				dataSyscallArgs = find_dataSyscall_byUUID(temp->read_syscallUUID);
				dataUUID_list.remove(dataSyscallArgs);
				free(dataSyscallArgs);

				returnUUID = temp->read_syscallUUID;
				temp->read_syscallUUID = -1;
				returnSystemCall(returnUUID, -1);
			}
		}

	} else if(flag == FLAG_ACK) {
		if(temp->timer != (UUID)-1)
			cancelTimer(temp->timer);

		// handling connect server state
		// on receiving ACK properly. passive
		if(temp->state == TCP_SYN_RCVD) {
			deleteFront_senderBuffer(temp);

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

		// receiving ACK for first FINACK
		} else if(temp->state == TCP_FIN_WAIT1) {
			deleteFront_senderBuffer(temp);

			// if ACK for FINACK received.
			if(temp->sender_buffer->empty()) {
				temp->acknum = oppo_seq;

				temp->state = TCP_FIN_WAIT2;

			// if any ACKs received after sending FINACK
			} else {
				packet_data = temp->sender_buffer->front();
					
				// if proper packet is received.
				if(htonl(ntohl(packet_data->start_num) + packet_data->size) == oppo_ack) {
					//printf("proper packet! : %d\n", ntohl(oppo_ack));
					deleteFront_senderBuffer(temp);
				}
			}

		// receiveing ACK in simultaneous close
		} else if(temp->state == TCP_CLOSING) {
			deleteFront_senderBuffer(temp);

			temp->acknum = oppo_seq;

			temp->state = TCP_TIMED_WAIT;
			temp->timer = addTimer(temp, 120 * 1000 * 1000);

		// receiving second ACK from server
		} else if(temp->state == TCP_LAST_ACK) {
			deleteFront_senderBuffer(temp);
			//printf("received last ACK!\n");
			temp->acknum = oppo_seq;

			temp->state = TCP_CLOSED;
			remove_socket(temp);

		// data transfer, and first FINACK
		} else if(temp->state == TCP_ESTAB) {
			//printf("received! size : %d\n", packet_data->size);

			// if data is received.
			if(packetdata_size > 0) {
				packet_data = make_PacketData(temp_data, packetdata_size, oppo_seq);
				//temp->acknum = htonl(ntohl(oppo_seq) + packet_data->size);

				// if receiver buffer is empty, set seqnum_recentRead to packet_data->start_num.
				if(temp->receiver_buffer->empty())
					temp->seqnum_recentRead = packet_data->start_num;
				
				// push packet to receiver buffer and sort the buffer by seqnum
				push_packet_sortbySeqnum(temp->receiver_buffer, packet_data);
				temp->receiver_unused -= packet_data->size;

				// set acknum of socket by traversing receiver buffer
				set_acknumForPacket(temp);

				// if read() already called
				if(temp->read_syscallUUID != (UUID)-1) {
					dataSyscallArgs = find_dataSyscall_byUUID(temp->read_syscallUUID);
					
					saved_data_len = read_buffer(temp, dataSyscallArgs->buf, dataSyscallArgs->count);
					dataUUID_list.remove(dataSyscallArgs);
					free(dataSyscallArgs);

					returnUUID = temp->read_syscallUUID;
					temp->read_syscallUUID = -1;
					returnSystemCall(returnUUID, saved_data_len);
				}

				send_packet(temp, FLAG_ACK, NULL);
			
			// if ACK of data is received.
			} else {
				temp->acknum = oppo_seq;
				if(temp->sender_buffer->empty())
					return;
				
				packet_data = temp->sender_buffer->front();
				
				// if proper packet is received.
				if(htonl(ntohl(packet_data->start_num) + packet_data->size) == oppo_ack) {
					//printf("proper packet! : %d\n", ntohl(oppo_ack));
					deleteFront_senderBuffer(temp);

					// if write() already called
					if(temp->write_syscallUUID != (UUID)-1) {
						dataSyscallArgs = find_dataSyscall_byUUID(temp->write_syscallUUID);
						
						if(temp->sender_unused < dataSyscallArgs->count) {
							saved_data_len = write_buffer(temp, dataSyscallArgs->buf, temp->sender_unused);
						} else {
							saved_data_len = write_buffer(temp, dataSyscallArgs->buf, dataSyscallArgs->count);
						}
						dataUUID_list.remove(dataSyscallArgs);
						free(dataSyscallArgs);

						returnUUID = temp->write_syscallUUID;
						temp->write_syscallUUID = -1;
						returnSystemCall(returnUUID, saved_data_len);
					}
				}
			}
		}
	}

	return;
}

void TCPAssignment::timerCallback(void* payload)
{
	struct socketInterface *timed_socket = (struct socketInterface *) payload;
	struct packetData *packetData;

	cancelTimer(timed_socket->timer);
	printf("timer! state : %d\n", timed_socket->state);

	// retransmit SYN. SYNACK not received. (2)
	if(timed_socket->state == TCP_SYN_SENT) {
		packetData = timed_socket->sender_buffer->front();
		send_packet(timed_socket, FLAG_SYN, packetData);

	// retransmit SYNACK. ACK not received. (3)
	} else if(timed_socket->state == TCP_SYN_RCVD) {
		packetData = timed_socket->sender_buffer->front();
		send_packet(timed_socket, FLAG_SYNACK, packetData);

	} else if(timed_socket->state == TCP_FIN_WAIT1) {
		packetData = timed_socket->sender_buffer->front();
		send_packet(timed_socket, FLAG_FINACK, packetData);

	} else if(timed_socket->state == TCP_LAST_ACK) {
		packetData = timed_socket->sender_buffer->front();
		send_packet(timed_socket, FLAG_FINACK, packetData);

	} else if(timed_socket->state == TCP_CLOSING) {
		packetData = timed_socket->sender_buffer->front();
		send_packet(timed_socket, FLAG_FINACK, packetData);
	}

	// timed wait to close connections completely. (7)
	if(timed_socket->state == TCP_TIMED_WAIT) {
		timed_socket->state = TCP_CLOSED;
		remove_socket(timed_socket);
	}
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
	new_sock->read_syscallUUID = -1;
	new_sock->write_syscallUUID = -1;

	new_sock->parent_sockfd = -1;

	new_sock->sender_unused = 51200;
	new_sock->receiver_unused = 51200;
	new_sock->oppo_window = 0;

	new_sock->timer = -1;

	new_sock->sender_buffer = new std::list<struct packetData*>();
	new_sock->receiver_buffer = new std::list<struct packetData*>();
	new_sock->seqnum_recentRead = 0;

	socket_list.push_back(new_sock);
	return sockfd;
}

int TCPAssignment::syscall_close(UUID syscallUUID, int pid, int sockfd)
{
	struct socketInterface *temp;
	struct packetData *packet_data;
	temp = find_sock_byId(pid, sockfd);

	if(temp == NULL)
		return -1;

	// close() syscall. active close and passive close.
	if(temp->state == TCP_ESTAB) {
		// send FINACK packet.
		packet_data = make_PacketData(NULL, 0, temp->seqnum);
		temp->sender_buffer->push_back(packet_data);
		send_packet(temp, FLAG_FINACK, packet_data);
		temp->state = TCP_FIN_WAIT1;
	} else if(temp->state == TCP_CLOSE_WAIT) {
		// send FINACK packet.
		packet_data = make_PacketData(NULL, 0, temp->seqnum);
		temp->sender_buffer->push_back(packet_data);
		send_packet(temp, FLAG_FINACK, packet_data);
		temp->state = TCP_LAST_ACK;
	} else {
		remove_socket(temp);
		return 0;
	}

	//remove_socket(temp);
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
	struct packetData *packet_data;

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
	packet_data = make_PacketData(NULL, 0, my_sock->seqnum);
	my_sock->sender_buffer->push_back(packet_data);
	send_packet(my_sock, FLAG_SYN, packet_data);
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
		syscallArgs->pid = pid;
		syscallArgs->parentfd = sockfd;

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

int TCPAssignment::syscall_read(UUID syscallUUID, int pid, int sockfd, void *buf, size_t count)
{
	struct socketInterface *temp;
	struct dataSyscallArgs *syscallArgs;
	temp = find_sock_byId(pid, sockfd);

	if(temp == NULL)
		return -1;

	if(temp->state != TCP_ESTAB)
		return -1;

	// block if receiver buffer is empty
	if(temp->receiver_buffer->empty()) {
		syscallArgs = (struct dataSyscallArgs *) malloc(sizeof(struct dataSyscallArgs));
		syscallArgs->syscallUUID = syscallUUID;

		syscallArgs->buf = buf;
		syscallArgs->count = count;
		dataUUID_list.push_back(syscallArgs);

		temp->read_syscallUUID = syscallUUID;
		//printf("buffer empty\n");
		return 0;
	}

	return read_buffer(temp, buf, count);
}

int TCPAssignment::syscall_write(UUID syscallUUID, int pid, int sockfd, const void *buf, size_t count)
{
	struct socketInterface *temp;
	struct dataSyscallArgs *syscallArgs;
	temp = find_sock_byId(pid, sockfd);

	if(temp == NULL)
		return -1;

	if(temp->state != TCP_ESTAB)
		return -1;

	// block if sender buffer is full
	if(temp->sender_unused <= 0) {
		syscallArgs = (struct dataSyscallArgs *) malloc(sizeof(struct dataSyscallArgs));
		syscallArgs->syscallUUID = syscallUUID;

		syscallArgs->buf = (void *)buf;
		syscallArgs->count = count;
		dataUUID_list.push_back(syscallArgs);

		temp->write_syscallUUID = syscallUUID;
		//printf("buffer empty\n");
		return 0;
	}

	if(temp->sender_unused < count)
		return write_buffer(temp, (void *)buf, temp->sender_unused);

	return write_buffer(temp, (void *)buf, count);
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

void TCPAssignment::send_packet(struct socketInterface *sender, unsigned char flag, struct packetData *data)
{
	Packet *myPacket;

	size_t tcp_packet_len;
	int seqnum;

	if(flag == FLAG_SYN || flag == FLAG_SYNACK)
		sender->seqnum = 0;

	if(data == NULL || data->size == 0) {
		myPacket = this->allocatePacket(PACKETH_SIZE);
		tcp_packet_len = PACKETH_SIZE - IH_SIZE;
		seqnum = sender->seqnum;
	} else {
		myPacket = this->allocatePacket(PACKETH_SIZE + data->size);
		tcp_packet_len = PACKETH_SIZE - IH_SIZE + data->size;
		seqnum = data->start_num;
	}

	in_addr_t src_ip = sender->myaddr->sin_addr.s_addr;
	in_addr_t dest_ip = sender->oppoaddr->sin_addr.s_addr;
	unsigned short checksum;
	unsigned char header_len = 0x05 << 4;
	//unsigned short window = htons(51200);
	unsigned short window = htons(sender->receiver_unused);
	uint8_t *tcp_seg = (uint8_t *)malloc(tcp_packet_len);

	myPacket->writeData(EH_SIZE+12, &src_ip, 4);
	myPacket->writeData(EH_SIZE+16, &dest_ip, 4);
	myPacket->writeData(IH_SIZE, &sender->myaddr->sin_port, 2);
	myPacket->writeData(IH_SIZE+2, &sender->oppoaddr->sin_port, 2);

	myPacket->writeData(IH_SIZE+4, &seqnum, 4);
	myPacket->writeData(IH_SIZE+8, &sender->acknum, 4);
	myPacket->writeData(IH_SIZE+12, &header_len, 1);
	myPacket->writeData(IH_SIZE+13, &flag, 1);
	myPacket->writeData(IH_SIZE+14, &window, 2);

	if(data != NULL && data->size > 0) {
		myPacket->setSize(PACKETH_SIZE + data->size);
		myPacket->writeData(PACKETH_SIZE, data->data, data->size);
	}
	//printf("packet size : %d\n", myPacket->getSize());

	myPacket->readData(IH_SIZE, tcp_seg, tcp_packet_len);
	checksum = htons(~NetworkUtil::tcp_sum(src_ip, dest_ip, tcp_seg, tcp_packet_len));
	//printf("checksum : %x\n", checksum);
	myPacket->writeData(IH_SIZE+16, &checksum, 2);

	this->sendPacket("IPv4", myPacket);
	free(tcp_seg);

	if (data != NULL) {
		if(flag != FLAG_ACK)
			sender->seqnum = ntohl(htonl(seqnum) + 1);
		if(flag == FLAG_ACK)
			sender->seqnum = ntohl(htonl(seqnum) + data->size);
	}

	if(flag == FLAG_ACK && data == NULL)
		return;

	// add timer for retransmission
	if(sender->timer != (UUID)-1)
		cancelTimer(sender->timer);
	sender->timer = addTimer(sender, 100 * 1000 * 1000);

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
	dupl_sock->read_syscallUUID = -1;
	dupl_sock->write_syscallUUID = -1;
	dupl_sock->parent_sockfd = -1;

	dupl_sock->sender_unused = 51200;
	dupl_sock->receiver_unused = 51200;
	dupl_sock->oppo_window = 0;

	dupl_sock->timer = -1;

	dupl_sock->sender_buffer = new std::list<struct packetData*>();
	dupl_sock->receiver_buffer = new std::list<struct packetData*>();
	dupl_sock->seqnum_recentRead = 0;

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

	while(!socket->sender_buffer->empty()) {
		free(socket->sender_buffer->front()->data);
		delete socket->sender_buffer->front();
		socket->sender_buffer->pop_front();
	}
	while(!socket->receiver_buffer->empty()) {
		free(socket->receiver_buffer->front()->data);
		delete socket->receiver_buffer->front();
		socket->receiver_buffer->pop_front();
	}
	delete socket->sender_buffer;
	delete socket->receiver_buffer;

	acceptUUID_list.remove(find_acceptSyscall_byId(socket->pid, socket->sockfd));
	dataUUID_list.remove(find_dataSyscall_byUUID(socket->read_syscallUUID));

	removeFileDescriptor(socket->pid, socket->sockfd);
	free(socket);
}

size_t TCPAssignment::read_buffer(struct socketInterface *receiver, void *buf, size_t count)
{
	size_t saved_data_len = 0;
	struct packetData *packetData;

	while(!receiver->receiver_buffer->empty() && saved_data_len < count) {
		//printf("receiver buffer size : %d\n", receiver->receiver_buffer->size());

		packetData = receiver->receiver_buffer->front();

		// if read data in each packet first.
		if(packetData->now == 0) {
			// if seqnum of packetData and recent acknum is different, it is not proper data.
			if(packetData->start_num != receiver->seqnum_recentRead)
				return saved_data_len;

			receiver->seqnum_recentRead = htonl(ntohl(packetData->start_num) + packetData->size);
		}

		// partially read data
		if(count < (packetData->size - packetData->now)) {
			memcpy(buf, (char*)packetData->data + packetData->now, count);
			saved_data_len += count;
			packetData->now += count;
			receiver->receiver_unused += count;

		// if all data in the packet can be read
		} else {
			memcpy(buf, (char*)packetData->data + packetData->now, packetData->size - packetData->now);
			saved_data_len += (packetData->size - packetData->now);
			receiver->receiver_buffer->pop_front();
			receiver->receiver_unused += (packetData->size - packetData->now);
			free(packetData->data);
			delete packetData;
		}

		//printf("saved data : %d\n", saved_data_len);
	}

	return saved_data_len;
}

size_t TCPAssignment::write_buffer(struct socketInterface *sender, void *buf, size_t count)
{
	size_t saved_data_len = 0;
	size_t temp_size, packet_size;
	struct packetData *packet_data;
	void *temp_data;

	// if opponent receiver window size is smaller than count
	if(sender->oppo_window < count) {
		temp_size = sender->oppo_window;
	} else {
		temp_size = count;
	}

	while(saved_data_len < temp_size) {
		// chunk packet to 512 bytes
		if((temp_size - saved_data_len) > 512) {
			packet_size = 512;
		} else {	
			packet_size = temp_size - saved_data_len;
		}

		temp_data = malloc(packet_size);
		memcpy(temp_data, (char*)buf + saved_data_len, packet_size);

		packet_data = make_PacketData(temp_data, packet_size, sender->seqnum);

		sender->sender_buffer->push_back(packet_data);
		sender->sender_unused -= packet_data->size;
		saved_data_len += packet_data->size;

		send_packet(sender, FLAG_ACK, packet_data);
	}

	return saved_data_len;
}

struct packetData* TCPAssignment::make_PacketData(void* data, size_t size, int start_num)
{
	struct packetData *packet_data;
	packet_data = new struct packetData();
	packet_data->data = data;
	packet_data->size = size;
	packet_data->start_num = start_num;
	packet_data->now = 0;

	return packet_data;
}

void TCPAssignment::set_acknumForPacket(struct socketInterface *receiver)
{
	std::list<struct packetData*>::iterator iter;

	for(iter = receiver->receiver_buffer->begin(); iter != receiver->receiver_buffer->end(); iter++) {
		if((*iter)->start_num == receiver->acknum) {
			receiver->acknum = htonl(ntohl((*iter)->start_num) + (*iter)->size);
		} else {
			break;
		}
	}

	return;
}

void TCPAssignment::push_packet_sortbySeqnum(std::list<struct packetData *> *buffer, struct packetData *data)
{
	std::list<struct packetData*>::iterator iter;

	for(iter = buffer->begin(); iter != buffer->end(); iter++) {
		if((*iter)->start_num >= data->start_num) {
			buffer->insert(iter, data);
			return;
		}
	}

	buffer->push_back(data);
	return;
}

void TCPAssignment::deleteFront_senderBuffer(struct socketInterface *socket)
{
	struct packetData *packet_data;

	if(socket->sender_buffer->empty())
		return;

	packet_data = socket->sender_buffer->front();
	socket->sender_unused += packet_data->size;
	socket->sender_buffer->pop_front();

	free(packet_data->data);
	delete packet_data;
	return;
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

struct acceptSyscallArgs* TCPAssignment::find_acceptSyscall_byId(int pid, int parentfd)
{
	std::list<struct acceptSyscallArgs*>::iterator iter;

	for(iter = acceptUUID_list.begin(); iter != acceptUUID_list.end(); iter++) {
		if((*iter)->pid == pid && (*iter)->parentfd == parentfd)
			return *iter;
	}

	return NULL;
}

struct dataSyscallArgs* TCPAssignment::find_dataSyscall_byUUID(UUID syscallUUID)
{
	std::list<struct dataSyscallArgs*>::iterator iter;

	for(iter = dataUUID_list.begin(); iter != dataUUID_list.end(); iter++) {
		if((*iter)->syscallUUID == syscallUUID)
			return *iter;
	}

	return NULL;
}

}
