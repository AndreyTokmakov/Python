#============================================================================
# Name        : SSLSocketServer.py
# Created on  : June 01, 2020
# Author      : Tokmakov Andrey
# Version     : 1.0
# Copyright   : Your copyright notice
# Description : SSLSocketServer class. 
#============================================================================

import asyncio
import socket
import ssl

def make_header():
    return b"{\"UrlLoadInstaller\": \"https://test.fileserver.mail.ru//atom_setup_next.exe\", \"Hash\": \"b8d4d2a5e9c87d629032bfb1f50fa00d858a82d6265812d785f82c0d63bf98c6\", \"Version\": \"1000500.1.0.81\"}";

''' SSLSocketServer class : '''
class SSLSocketServer(object):
    # Service host name/IP address:
    __SERVER_HOST_NAME = 'data.browser.mail.ru';
    # Service port:
    __SERVER_LISTEN_PORT = 443;
    # Service port:
    __LISTEN_BACKLOG = 10;
    # Max receive buffer size:
    __MAX_RECEIVE_BUFFER_SIZE = 1024;
    
    # SSLSocketServer constructor:
    def __init__(self) -> None:
        self.__server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        self.__server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.__server_socket.setblocking(False)
        self.__server_socket.bind((self.__SERVER_HOST_NAME, 
                                   self.__SERVER_LISTEN_PORT))
        self.__server_socket.listen(self.__LISTEN_BACKLOG)
        
    # Initialize the SSL protocol context:
    def __InitializeSSLContext(self,
                               sslContext= ssl.PROTOCOL_SSLv23)-> bool:
        try:
            self.__sslctx = ssl.SSLContext(sslContext)
            self.__sslctx.load_cert_chain(certfile = 'R:\\Projects\\Python\\AtomUpdaterAutotests_Refactor3\\certs\\data.browser.mail.ru.crt', 
                                          keyfile = 'R:\\Projects\\Python\\AtomUpdaterAutotests_Refactor3\\certs\\data.browser.key');
        except Exception as exc:
            print(exc);
            return False;
        
        return True;
        
    # Handle the TCP and SSL handshakes: 
    def __handleHandshake(self, 
                          loop,
                          socket: ssl.SSLSocket,
                          waiter: asyncio.futures.Future):
        print("__handleHandshake");
        sock_fd = socket.fileno()
        try:
            # Do TCP and SSL handshakes in asynch way:
            socket.do_handshake(block= False);
        except ssl.SSLWantReadError:
            loop.remove_reader(sock_fd)
            loop.add_reader(sock_fd, self.__handleHandshake, loop, socket, waiter);
            return
        except ssl.SSLWantWriteError:
            loop.remove_writer(sock_fd)
            loop.add_writer(sock_fd, self.__handleHandshake, loop, socket, waiter);
            return
    
        loop.remove_reader(sock_fd)
        loop.remove_writer(sock_fd)
        waiter.set_result(None)

    # Read input bytes from client socket: 
    def __read(self,
               loop, 
               socket: ssl.SSLSocket,
               waiter: asyncio.futures.Future):
        print("__handleRead");
        try:
            req = socket.recv(self.__MAX_RECEIVE_BUFFER_SIZE);
        except ssl.SSLWantReadError:
            loop.remove_reader(socket.fileno())
            loop.add_reader(socket.fileno(), self.__read, loop, socket, waiter);
            return
        
        loop.remove_reader(socket.fileno());
        waiter.set_result(req);

    # Write bytes to client socket: 
    def __write(self,
                loop, msg, 
                socket: ssl.SSLSocket,
                waiter: asyncio.futures.Future):
        print("__write");
        try:
            resp = make_header()
            ret = socket.send(resp)
        except ssl.SSLWantReadError:
            loop.remove_writer(socket.fileno())
            loop.add_writer(socket.fileno(), self.__write, loop, socket, waiter);
            return
        
        loop.remove_writer(socket.fileno())
        socket.close()
        waiter.set_result(None)

    # Write bytes to client socket: 
    async def server(self, loop):
        while True:
            # Accept incoming connection:
            connection, addr = await loop.sock_accept(self.__server_socket)
            # Set connection to NonBlocking mode:
            connection.setblocking(False);
            sslconn = self.__sslctx.wrap_socket(connection,
                                                server_side = True,
                                                do_handshake_on_connect = False);
            # wait SSL handshake
            waiter = loop.create_future();
            self.__handleHandshake(loop, sslconn, waiter);
            await waiter
    
            # wait read request
            waiter = loop.create_future()
            self.__read(loop, sslconn, waiter);
            msg = await waiter
    
            # wait write response
            waiter = loop.create_future()
            self.__write(loop, msg, sslconn, waiter);
            await waiter
       
    # RunServer:  
    def RunServer(self)-> None:
        if (False == self.__InitializeSSLContext()):
            return;
        loop = asyncio.get_event_loop();
        try:
            loop.run_until_complete(self.server(loop));
        finally:
            loop.close();

if __name__ == '__main__':
    server = SSLSocketServer();
    server.RunServer();


