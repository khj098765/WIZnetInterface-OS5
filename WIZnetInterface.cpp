/* Copyright (C) 2012 mbed.org, MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 * and associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
 * BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include <string.h>
#include "WIZnetInterface.h"
#include "eth_arch.h"

#if (not defined TARGET_WIZwiki_W7500) && (not defined TARGET_WIZwiki_W7500P) && (not defined TARGET_WIZwiki_W7500ECO)
WIZnetInterface::WIZnetInterface(PinName mosi, PinName miso, PinName sclk, PinName cs, PinName reset) :
        WIZnet_Chip(mosi, miso, sclk, cs, reset)
{
    ip_set = false;
}

WIZnetInterface::WIZnetInterface(SPI* spi, PinName cs, PinName reset) :
        WIZnet_Chip(spi, cs, reset)
{
    ip_set = false;
}
#endif

int WIZnetInterface::init(uint8_t * mac)
{
    dhcp = true;
    eth->reset(mac);
	
    return 0;
}

int WIZnetInterface::init(uint8_t * mac, const char* ip, const char* mask, const char* gateway)
{
    dhcp = false;
    //
    //
    this->ip = str_to_ip(ip);
    strcpy(ip_string, ip);
    ip_set = true;
    this->netmask = str_to_ip(mask);
    this->gateway = str_to_ip(gateway);
    eth->reset(mac);

    // @Jul. 8. 2014 add code. should be called to write chip.
    eth->setmac(mac);
    eth->setip(this->ip);
    
    return 0;
}

// Connect Bring the interface up, start DHCP if needed.
int WIZnetInterface::connect()
{
    if (dhcp) {
        /*int r = IPrenew();
        if (r < 0) {
            return r;
        }*/
        return NSAPI_ERROR_UNSUPPORTED;
    }
    
    if (eth->setip(this->ip) == false) return NSAPI_ERROR_NO_ADDRESS;
    return 0;
}

// Disconnect Bring the interface down.
int WIZnetInterface::disconnect()
{
    //if (WIZnet_Chip::disconnect() == false) return -1;
    return 0;
}


const char *WIZnetInterface::get_ip_address()
{
    uint32_t ip = eth->reg_rd<uint32_t>(SIPR);
    snprintf(ip_string, sizeof(ip_string), "%d.%d.%d.%d", 
				(uint8_t)((ip>>24)&0xff), 
				(uint8_t)((ip>>16)&0xff), 
				(uint8_t)((ip>>8)&0xff), 
				(uint8_t)(ip&0xff));
    return ip_string;
}

const char *WIZnetInterface::get_netmask()
{
    uint32_t ip = eth->reg_rd<uint32_t>(SUBR);
    snprintf(mask_string, sizeof(mask_string), "%d.%d.%d.%d", 
				(uint8_t)((ip>>24)&0xff), 
				(uint8_t)((ip>>16)&0xff), 
				(uint8_t)((ip>>8)&0xff), 
				(uint8_t)(ip&0xff));
    return mask_string;
}

const char *WIZnetInterface::get_gateway()
{
    uint32_t ip = eth->reg_rd<uint32_t>(GAR);
    snprintf(gw_string, sizeof(gw_string), "%d.%d.%d.%d", 
				(uint8_t)((ip>>24)&0xff), 
				(uint8_t)((ip>>16)&0xff), 
				(uint8_t)((ip>>8)&0xff), 
				(uint8_t)(ip&0xff));
    return gw_string;
}

const char *WIZnetInterface::get_mac_address()
{
    uint8_t mac[6];
    eth->reg_rd_mac(SHAR, mac);
    snprintf(mac_string, sizeof(mac_string), "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	//ethernet_address(mac_string);
    return mac_string; 
    
}

struct wiznet_socket {
    int id;
    nsapi_protocol_t proto;
    bool connected;
    SocketAddress addr;
};

//int WIZnetInterface::IPrenew(int timeout_ms)
//{
    /*
    DHCPClient dhcp;
    int err = dhcp.setup(timeout_ms);
    if (err == (-1)) {
        return -1;
    }
//    printf("Connected, IP: %d.%d.%d.%d\n", dhcp.yiaddr[0], dhcp.yiaddr[1], dhcp.yiaddr[2], dhcp.yiaddr[3]);
    ip      = (dhcp.yiaddr[0] <<24) | (dhcp.yiaddr[1] <<16) | (dhcp.yiaddr[2] <<8) | dhcp.yiaddr[3];
    gateway = (dhcp.gateway[0]<<24) | (dhcp.gateway[1]<<16) | (dhcp.gateway[2]<<8) | dhcp.gateway[3];
    netmask = (dhcp.netmask[0]<<24) | (dhcp.netmask[1]<<16) | (dhcp.netmask[2]<<8) | dhcp.netmask[3];
    dnsaddr = (dhcp.dnsaddr[0]<<24) | (dhcp.dnsaddr[1]<<16) | (dhcp.dnsaddr[2]<<8) | dhcp.dnsaddr[3];
    return 0;
    */
//}

/* WIZNET network stack implementation */
//tatic nsapi_error_t wiznet_gethostbyname(nsapi_stack_t *stack, const char *name, SocketAddress *address, nsapi_version_t version)
//int WIZnetInterface::wiznet_gethostbyname(nsapi_stack_t *stack, const char *host, nsapi_addr_t *addr)
//{
    /*
    eth->gethostbyname(host, addr);

    return 0;
    */
//}

//void WIZnetInterface::wiznet_socket_set_blocking(bool blocking, unsigned int timeout)
//{
    /*
    _blocking = blocking;
    _timeout = timeout;
    */
//}
//static nsapi_error_t wiznet_add_dns_server(nsapi_stack_t *stack, const SocketAddress &address)
//{
//}


int WIZnetInterface::socket_open(void **handle, nsapi_protocol_t proto)
//int WIZnetInterface::wiznet_socket_open(nsapi_stack_t *stack, int *_sock_fd, nsapi_protocol_t proto)
{
    // Look for an unused socket
    int id = -1;
 
    for (int i = 0; i < WIZNET_SOCKET_COUNT; i++) {
        if (!_ids[i]) {
            id = i;
            _ids[i] = true;
            break;
        }
    }
 
    if (id == -1) {
        return NSAPI_ERROR_NO_SOCKET;
    }
    
    struct wiznet_socket *socket = new struct wiznet_socket;
    if (!socket) {
        return NSAPI_ERROR_NO_SOCKET;
    }
    
    socket->id = id;
    socket->proto = proto;
    socket->connected = false;
    *handle = socket;
    return NSAPI_ERROR_OK;
    /*
    g_proto = proto;

    if(proto == NSAPI_TCP) {
        eth->setProtocol(_sock_fd, WIZnet_Chip::TCP);
    }
    else {
        eth->setProtocol(_sock_fd, WIZnet_Chip::UDP);
    }

    return 0;
    */
}

int WIZnetInterface::socket_close(void *handle)
//int WIZnetInterface::wiznet_socket_close(nsapi_stack_t *stack, int _sock_fd)
{
    struct wiznet_socket *socket = (struct wiznet_socket *)handle;
    int err = NSAPI_ERROR_OK;
    //_esp.setTimeout(ESP8266_MISC_TIMEOUT);
 
    eth->scmd(socket->id, WIZnet_Chip::CLOSE);

    socket->connected = false;
    _ids[socket->id] = false;
    delete socket;
    return err;
    /*
    eth->scmd(_sock_fd, WIZnet_Chip::CLOSE);

    return 0;
    */
}

int WIZnetInterface::socket_bind(void *handle, const SocketAddress &address)
//int WIZnetInterface::wiznet_socket_bind(nsapi_stack_t *stack, int _sock_fd, nsapi_addr_t addr, uint16_t port)
{
    struct wiznet_socket *socket = (struct wiznet_socket *)handle;

    eth->sreg<uint16_t>(socket->id, Sn_PORT, address.get_port());
    
    if(socket->proto == NSAPI_TCP) {
        eth->setProtocol(socket->id, WIZnet_Chip::TCP);
    }
    else {
        eth->setProtocol(socket->id, WIZnet_Chip::UDP);
    } 

    eth->scmd(socket->id, WIZnet_Chip::OPEN);

    return NSAPI_ERROR_OK;

    /*
    listen_port = port;
    if (_sock_fd < 0) {
        _sock_fd = new_socket();
        if (_sock_fd < 0) {
            return -1;
        }
    }

    // set local port
    if (port != 0 || proto == NSAPI_TCP) {
        eth->sreg<uint16_t>(_sock_fd, Sn_PORT, port);
    } else {
        udp_local_port++;
        eth->sreg<uint16_t>(_sock_fd, Sn_PORT, udp_local_port);
    }

    // set protocol
    if(proto == NSAPI_TCP) {
        eth->setProtocol(_sock_fd, WIZnet_Chip::TCP);
    }
    else {
        eth->setProtocol(_sock_fd, WIZnet_Chip::UDP);
    }
    
    // connect the network
    eth->scmd(_sock_fd, WIZnet_Chip::OPEN);

    return 0;
    */
}

int WIZnetInterface::socket_listen(void *handle, int backlog)
//int WIZnetInterface::wiznet_socket_listen(nsapi_stack_t *stack, int backlog)
{
    struct wiznet_socket *socket = (struct wiznet_socket *)handle;

    if (socket->id < 0) {
        return NSAPI_ERROR_DEVICE_ERROR;
    }
    if (backlog != 1) {
        return NSAPI_ERROR_IS_CONNECTED;
    }
    eth->scmd(socket->id, WIZnet_Chip::LISTEN);
    return NSAPI_ERROR_OK;
    /*
    if (_sock_fd < 0) {
        return -1;
    }
    if (backlog != 1) {
        return -1;
    }
    eth->scmd(_sock_fd, WIZnet_Chip::LISTEN);
    return 0;
    */
}

int WIZnetInterface::socket_connect(void *handle, const SocketAddress &address)
//int WIZnetInterface::wiznet_socket_connect(nsapi_stack_t *stack, const char* host, uint16_t port)
{
    struct wiznet_socket *socket = (struct wiznet_socket *)handle;
    
    //const char *proto = (socket->proto == NSAPI_UDP) ? "UDP" : "TCP";
    
    if (remote.set_address(address.get_ip_address(), address.get_port()) != 0) {
        return -1;
    }
    if (!eth->connect(socket->id, remote.get_address(), remote.get_port())) {
        return -1;
    }
    //set_blocking(false);
    // add code refer from EthernetInterface.
    socket->connected = true;

    return NSAPI_ERROR_OK;

    /*
    if (_sock_fd < 0) {
        _sock_fd = eth->new_socket();
        if (_sock_fd < 0) {
            return -1;
        }
    }
    if (set_address(addr, port) != 0) {
        return -1;
    }
    if (!connect(_sock_fd, get_ip_address(), port)) {
        return -1;
    }
    set_blocking(false);
    // add code refer from EthernetInterface.
    _is_connected = true;

    return 0;
    */
}

//bool WIZnetInterface::is_connected(void)
//{
    /*
    // force update recent state.
    _is_connected = eth->is_connected(_sock_fd);
    return _is_connected;
    */
//}

int WIZnetInterface::socket_accept(void *server, void **socket, SocketAddress *addr)
//int WIZnetInterface::wiznet_socket_accept(nsapi_stack_t *stack, TCPSocket& connection)
{
    /*
    if (_sock_fd < 0) {
        return -1;
    }
    Timer t;
    t.reset();
    t.start();
    while(1) {
        if (t.read_ms() > _timeout && _blocking == false) {
            return -1;
        }
        if (eth->sreg<uint8_t>(_sock_fd, Sn_SR) == WIZnet_Chip::SOCK_ESTABLISHED) {
            break;
        }
    }
    uint32_t ip = eth->sreg<uint32_t>(_sock_fd, Sn_DIPR);
    char host[16];
    snprintf(addr, sizeof(addr), "%d.%d.%d.%d", (ip>>24)&0xff, (ip>>16)&0xff, (ip>>8)&0xff, ip&0xff);
    uint16_t port = eth->sreg<uint16_t>(_sock_fd, Sn_DPORT);

    // change this server socket to connection socket.
    connection._sock_fd = _sock_fd;
    connection._is_connected = true;
    connection.set_address(addr, port);

    // and then, for the next connection, server socket should be assigned new one.
    s = -1; // want to assign new available _sock_fd.
    if(bind(listen_port) < 0) {
        // modified by Patrick Pollet
        error("No more socket for listening, bind error");
        return -1;
    } else {
        //return -1;
        if(listen(1) < 0) {
            // modified by Patrick Pollet
            error("No more socket for listening, listen error");
            return -1;
        }
    }

    return 0;
    */
    return NSAPI_ERROR_UNSUPPORTED;
}

int WIZnetInterface::socket_send(void *handle, const void *data, unsigned length)
//int WIZnetInterface::wiznet_socket_send(nsapi_stack_t *stack, char* data, int length)
{
    struct wiznet_socket *socket = (struct wiznet_socket *)handle;
 
//    if((socket->id<0) || !(is_connected(socket->id)))
//        return -1;

    int size = eth->wait_writeable(socket->id, _blocking ? -1 : _timeout);
    if (size < 0) 
        return NSAPI_ERROR_WOULD_BLOCK;

    if (size > length) 
        size = length;

    return eth->send(socket->id, data, size);

    /*
    if((_sock_fd<0) || !(is_connected(_sock_fd)))
        return -1;

    int size = eth->wait_writeable(_sock_fd, _blocking ? -1 : _timeout);
    if (size < 0) 
        return -1;

    if (size > length) 
        size = length;

    return eth->send(_sock_fd, data, size);
    */
}

int WIZnetInterface::socket_recv(void *handle, void *data, unsigned length)
//int WIZnetInterface::wiznet_socket_recv(nsapi_stack_t *stack, char* data, int length)
{
    struct wiznet_socket *socket = (struct wiznet_socket *)handle;

    //if((socket->id<0) || !(is_connected(socket->id)))
    //    return -1;

    int size = eth->wait_readable(socket->id, _blocking ? -1 : _timeout);
    if (size < 0) {
        return NSAPI_ERROR_WOULD_BLOCK;
    }
    if (size > length) {
        size = length;
    }
    return eth->recv(socket->id, data, size);
    /*
    if((_sock_fd<0) || !(is_connected(_sock_fd)))
        return -1;

    int size = eth->wait_readable(_sock_fd, _blocking ? -1 : _timeout);
    if (size < 0) {
        return -1;
    }
    if (size > length) {
        size = length;
    }
    return eth->recv(_sock_fd, data, size);
    */
}

int WIZnetInterface::socket_sendto(void *handle, const SocketAddress &addr, const void *data, unsigned length)
//int WIZnetInterface::wiznet_socket_sendto(nsapi_stack_t *stack, Endpoint &remote, char *packet, int length)
{
    struct wiznet_socket *socket = (struct wiznet_socket *)handle;

    int size = eth->wait_writeable(socket->id, _blocking ? -1 : _timeout, length-1);
    if (size < 0) {
        return NSAPI_ERROR_WOULD_BLOCK;
    }

    int ret = eth->send(socket->id, data, length);
    return ret;

    /*
    int size = eth->wait_writeable(_sock_fd, _blocking ? -1 : _timeout, length-1);
    if (size < 0) {
        return -1;
    }
    confEndpoint(remote);
    int ret = eth->send(_sock_fd, packet, length);
    return ret;
    */
}

int WIZnetInterface::socket_recvfrom(void *handle, SocketAddress *address, void *data, unsigned length)
//int WIZnetInterface::wiznet_socket_recvfrom(nsapi_stack_t *stack, Endpoint &remote, char *buffer, int length)
{
    //Endpoint remote;

    struct wiznet_socket *socket = (struct wiznet_socket *)handle;

    uint8_t info[8];
    int size = eth->wait_readable(socket->id, _blocking ? -1 : _timeout, sizeof(info));
    if (size < 0) {
        return NSAPI_ERROR_WOULD_BLOCK;
    }
    eth->recv(socket->id, (char*)info, sizeof(info));
    readEndpoint(remote, info);
    int udp_size = info[6]<<8|info[7];
    //TEST_ASSERT(udp_size <= (size-sizeof(info)));
    if (udp_size > (size-sizeof(info))) {
        return NSAPI_ERROR_WOULD_BLOCK;
    }

    // Perform Length check here to prevent buffer overrun 
    // fixed by Sean Newton (https://developer.mbed.org/users/SeanNewton/) 
    if (udp_size > length) {
        //printf("udp_size: %d\n",udp_size);
        return NSAPI_ERROR_WOULD_BLOCK;
    }
    return eth->recv(socket->id, data, udp_size);
    /*
    uint8_t info[8];
    int length = eth->wait_readable(_sock_fd, _blocking ? -1 : _timeout, sizeof(info));
    if (length < 0) {
        return -1;
    }
    eth->recv(_sock_fd, (char*)info, sizeof(info));
    readEndpoint(remote, info);
    int udp_size = info[6]<<8|info[7];
    //TEST_ASSERT(udp_size <= (size-sizeof(info)));
    if (udp_size > (size-sizeof(info))) {
        return -1;
    }

    // Perform Length check here to prevent buffer overrun 
    // fixed by Sean Newton (https://developer.mbed.org/users/SeanNewton/) 
    if (udp_size > length) {
        //printf("udp_size: %d\n",udp_size);
        return -1;
    }
    return eth->recv(_sock_fd, buffer, udp_size);
    */
}

void WIZnetInterface::socket_attach(void *handle, void (*callback)(void *), void *data)
{
    struct wiznet_socket *socket = (struct wiznet_socket *)handle;    
    _cbs[socket->id].callback = callback;
    _cbs[socket->id].data = data;
}

void WIZnetInterface::event() {
    for (int i = 0; i < WIZNET_SOCKET_COUNT; i++) {
        if (_cbs[i].callback) {
            _cbs[i].callback(_cbs[i].data);
        }
    }
}

void WIZnetInterface::confEndpoint(Endpoint & ep)
{    
    char * host = ep.get_address();
    // set remote host
    eth->sreg_ip(_sock_fd, Sn_DIPR, host);
    // set remote port
    eth->sreg<uint16_t>(_sock_fd, Sn_DPORT, ep.get_port());
}

void WIZnetInterface::readEndpoint(Endpoint & ep, uint8_t info[])
{
    char addr[17];
    snprintf(addr, sizeof(addr), "%d.%d.%d.%d", info[0], info[1], info[2], info[3]);
    uint16_t port = info[4]<<8|info[5];
    ep.set_address(addr, port);
}

