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
#ifndef WIZNET_INTERFACE_H
#define WIZNET_INTERFACE_H

#include "mbed.h"
#include "eth_arch.h"

#include "Endpoint.h"

#define WIZNET_SOCKET_COUNT 4

class WIZnetInterface : public NetworkStack, public EthInterface, public Endpoint, public WIZnet_Chip
{
public:

#if (not defined TARGET_WIZwiki_W7500) && (not defined TARGET_WIZwiki_W7500P) && (not defined TARGET_WIZwiki_W7500ECO)

    /**
    * Constructor
    *
    * \param mosi mbed pin to use for SPI
    * \param miso mbed pin to use for SPI
    * \param sclk mbed pin to use for SPI
    * \param cs chip select of the WIZnet_Chip
    * \param reset reset pin of the WIZnet_Chip
    */
    WIZnetInterface(PinName mosi, PinName miso, PinName sclk, PinName cs, PinName reset);
    WIZnetInterface(SPI* spi, PinName cs, PinName reset);
#endif

     /** Set a static IP address
     *
     *  Configures this network interface to use a static IP address.
     *  Implicitly disables DHCP, which can be enabled in set_dhcp.
     *  Requires that the network is disconnected.
     *
     *  @param address  Null-terminated representation of the local IP address
     *  @param netmask  Null-terminated representation of the local network mask
     *  @param gateway  Null-terminated representation of the local gateway
     *  @return         0 on success, negative error code on failure
     */
    virtual int init(uint8_t * mac);

    /** Enable or disable DHCP on the network
     *
     *  Requires that the network is disconnected
     *
     *  @param dhcp     False to disable dhcp (defaults to enabled)
     *  @return         0 on success, negative error code on failure
     */
    virtual int init(uint8_t * mac, const char* ip, const char* mask, const char* gateway);

    /** Start the interface
     *  @return             0 on success, negative on failure
     */
    virtual int connect();

    /** Stop the interface
     *  @return             0 on success, negative on failure
     */
    virtual int disconnect();

    /** Get the local MAC address
     *
     *  Provided MAC address is intended for info or debug purposes and
     *  may not be provided if the underlying network interface does not
     *  provide a MAC address
     *  
     *  @return         Null-terminated representation of the local MAC address
     *                  or null if no MAC address is available
     */
    virtual const char *get_mac_address();

    /** Get the local IP address
     *
     *  @return         Null-terminated representation of the local IP address
     *                  or null if no IP address has been recieved
     */
    virtual const char *get_ip_address();

    /** Get the local network mask
     *
     *  @return         Null-terminated representation of the local network mask 
     *                  or null if no network mask has been recieved
     */
    virtual const char *get_netmask();

    /** Get the local gateways
     *
     *  @return         Null-terminated representation of the local gateway
     *                  or null if no network mask has been recieved
     */
    virtual const char *get_gateway();

//    virtual int IPrenew(int timeout_ms = 15 * 1000);
    /** Translates a hostname to an IP address with specific version
     *
     *  The hostname may be either a domain name or an IP address. If the
     *  hostname is an IP address, no network transactions will be performed.
     *
     *  If no stack-specific DNS resolution is provided, the hostname
     *  will be resolve using a UDP socket on the stack.
     *
     *  @param address  Destination for the host SocketAddress
     *  @param host     Hostname to resolve
     *  @param version  IP version of address to resolve, NSAPI_UNSPEC indicates
     *                  version is chosen by the stack (defaults to NSAPI_UNSPEC)
     *  @return         0 on success, negative error code on failure
     */
    using NetworkInterface::gethostbyname;

    /** Add a domain name server to list of servers to query
     *
     *  @param addr     Destination for the host address
     *  @return         0 on success, negative error code on failure
     */
    using NetworkInterface::add_dns_server;

protected:
    /** Provide access to the underlying stack
     *
     *  @return The underlying network stack 
     */

/*
    virtual nsapi_error_t wiznet_gethostbyname(nsapi_stack_t *stack, const char *name, SocketAddress *address, nsapi_version_t version);
    virtual nsapi_error_t wiznet_add_dns_server(nsapi_stack_t *stack, const SocketAddress &address);
    virtual nsapi_error_t wiznet_socket_open(nsapi_stack_t *stack, nsapi_socket_t *socket, nsapi_protocol_t proto);
    virtual nsapi_error_t wiznet_socket_close(nsapi_stack_t *stack, nsapi_socket_t *socket);
    virtual nsapi_error_t wiznet_socket_bind(nsapi_stack_t *stack, nsapi_socket_t socket, const SocketAddress &address);
    virtual nsapi_error_t wiznet_socket_listen(nsapi_stack_t *stack, nsapi_socket_t socket, int backlog);
    virtual nsapi_error_t wiznet_socket_connect(nsapi_stack_t *stack, nsapi_socket_t socket, const SocketAddress &address);
    virtual nsapi_error_t wiznet_socket_accept(nsapi_stack_t *stack, nsapi_socket_t server, nsapi_socket_t *socket, SocketAddress *address);
    virtual nsapi_error_t wiznet_socket_send(nsapi_stack_t *stack, const void *data, nsapi_size_t size);
    virtual nsapi_error_t wiznet_socket_recv(nsapi_stack_t *stack, void *data, nsapi_size_t size);
    virtual nsapi_error_t wiznet_socket_sendto(nsapi_stack_t *stack, const SocketAddress &address, const void *data, nsapi_size_t size);
    virtual nsapi_error_t wiznet_socket_recvfrom(nsapi_stack_t *stack,  SocketAddress *address, void *data, nsapi_size_t size);
*/
/*    
    virtual const char wiznet_gethostbyname(nsapi_stack_t *stack, const char *host, nsapi_addr_t *addr, nsapi_version_t version);
    virtual void set_blocking(bool blocking, unsigned int timeout);
    virtual int wiznet_socket_open(nsapi_stack_t *stack, int *_sock_fd, nsapi_protocol_t proto);
    virtual int wiznet_socket_close(nsapi_stack_t *stack, int _sock_fd);
    virtual int wiznet_socket_bind(nsapi_stack_t *stack, int _sock_fd, nsapi_addr_t addr, uint16_t port);
    virtual int wiznet_socket_listen(nsapi_stack_t *stack, int backlog);
    virtual int wiznet_socket_connect(nsapi_stack_t *stack, const char* host, uint16_t port);
    virtual int is_connected(void);
    virtual int wiznet_socket_accept(nsapi_stack_t *stack, TCPSocket& connection);
    virtual int wiznet_socket_send(nsapi_stack_t *stack, char* data, int length);
    virtual int wiznet_socket_recv(nsapi_stack_t *stack, char* data, int length);
    virtual int wiznet_socket_sendto(nsapi_stack_t *stack, Endpoint &remote, char *packet, int length);
    virtual int wiznet_socket_recvfrom(nsapi_stack_t *stack, Endpoint &remote, char *buffer, int length);
*/
    /** Open a socket
     *  @param handle       Handle in which to store new socket
     *  @param proto        Type of socket to open, NSAPI_TCP or NSAPI_UDP
     *  @return             0 on success, negative on failure
     */
    virtual int socket_open(void **handle, nsapi_protocol_t proto);

    /** Close the socket
     *  @param handle       Socket handle
     *  @return             0 on success, negative on failure
     *  @note On failure, any memory associated with the socket must still
     *        be cleaned up
     */
    virtual int socket_close(void *handle);

    /** Bind a server socket to a specific port
     *  @param handle       Socket handle
     *  @param address      Local address to listen for incoming connections on
     *  @return             0 on success, negative on failure.
     */
    virtual int socket_bind(void *handle, const SocketAddress &address);

    /** Start listening for incoming connections
     *  @param handle       Socket handle
     *  @param backlog      Number of pending connections that can be queued up at any
     *                      one time [Default: 1]
     *  @return             0 on success, negative on failure
     */
    virtual int socket_listen(void *handle, int backlog);

    /** Connects this TCP socket to the server
     *  @param handle       Socket handle
     *  @param address      SocketAddress to connect to
     *  @return             0 on success, negative on failure
     */
    virtual int socket_connect(void *handle, const SocketAddress &address);

    /** Accept a new connection.
     *  @param handle       Handle in which to store new socket
     *  @param server       Socket handle to server to accept from
     *  @return             0 on success, negative on failure
     *  @note This call is not-blocking, if this call would block, must
     *        immediately return NSAPI_ERROR_WOULD_WAIT
     */
    virtual int socket_accept(void *handle, void **socket, SocketAddress *address);

    /** Send data to the remote host
     *  @param handle       Socket handle
     *  @param data         The buffer to send to the host
     *  @param size         The length of the buffer to send
     *  @return             Number of written bytes on success, negative on failure
     *  @note This call is not-blocking, if this call would block, must
     *        immediately return NSAPI_ERROR_WOULD_WAIT
     */
    virtual int socket_send(void *handle, const void *data, unsigned length);

    /** Receive data from the remote host
     *  @param handle       Socket handle
     *  @param data         The buffer in which to store the data received from the host
     *  @param size         The maximum length of the buffer
     *  @return             Number of received bytes on success, negative on failure
     *  @note This call is not-blocking, if this call would block, must
     *        immediately return NSAPI_ERROR_WOULD_WAIT
     */
    virtual int socket_recv(void *handle, void *data, unsigned length);

    /** Send a packet to a remote endpoint
     *  @param handle       Socket handle
     *  @param address      The remote SocketAddress
     *  @param data         The packet to be sent
     *  @param size         The length of the packet to be sent
     *  @return             The number of written bytes on success, negative on failure
     *  @note This call is not-blocking, if this call would block, must
     *        immediately return NSAPI_ERROR_WOULD_WAIT
     */
    virtual int socket_sendto(void *handle, const SocketAddress &addr, const void *data, unsigned length);

    /** Receive a packet from a remote endpoint
     *  @param handle       Socket handle
     *  @param address      Destination for the remote SocketAddress or null
     *  @param buffer       The buffer for storing the incoming packet data
     *                      If a packet is too long to fit in the supplied buffer,
     *                      excess bytes are discarded
     *  @param size         The length of the buffer
     *  @return             The number of received bytes on success, negative on failure
     *  @note This call is not-blocking, if this call would block, must
     *        immediately return NSAPI_ERROR_WOULD_WAIT
     */
    virtual int socket_recvfrom(void *handle, SocketAddress *address, void *data, unsigned length);

    /** Register a callback on state change of the socket
     *  @param handle       Socket handle
     *  @param callback     Function to call on state change
     *  @param data         Argument to pass to callback
     *  @note Callback may be called in an interrupt context.
     */
    virtual void socket_attach(void *handle, void (*callback)(void *), void *data);

    /** Provide access to the NetworkStack object
     *
     *  @return The underlying NetworkStack object
     */
    virtual NetworkStack *get_stack()
    {
        return this;
    }

    int _sock_fd;
    bool _blocking;
    int _timeout;
    //uint8_t mac[6];
    uint32_t ip;
    uint32_t netmask;
    uint32_t gateway;
    uint32_t dnsaddr;
    bool dhcp;

private:
    WIZnet_Chip* eth;
    Endpoint remote;
    bool _ids[WIZNET_SOCKET_COUNT];

    char ip_string[20];
    char mask_string[20];
    char gw_string[20];
    char mac_string[20];
    bool ip_set;
    int listen_port;
    

    virtual void confEndpoint(Endpoint & ep);
    virtual void readEndpoint(Endpoint & ep, uint8_t info[]);

    void event();

    struct {
        void (*callback)(void *);
        void *data;
    } _cbs[WIZNET_SOCKET_COUNT];
};

#endif
