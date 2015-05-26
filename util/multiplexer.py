#!/usr/bin/python2

import datetime
import threading
import time
import termios
import signal
import sys

from twisted.internet.error import ConnectError, CannotListenError
from twisted.internet.defer import CancelledError
from twisted.internet.endpoints import TCP4ClientEndpoint, TCP4ServerEndpoint
from twisted.conch.telnet import TelnetTransport, TelnetProtocol, Telnet, SGA, ECHO, LINEMODE
from twisted.internet.protocol import Factory, Protocol, ClientFactory
from twisted.protocols.basic import LineReceiver
from twisted.internet import reactor

import controller


CLIENT_PORT = 8998

class TelnetClient(TelnetProtocol):
    def __init__(self):
        self.connected = False
        self.sender = None
        self.last_comm_time = 0

        self.timeout = 1500
        self.clients = []

        self.lock = threading.Lock()

    def connectionMade(self):
        controller.getInstance().log().log_debug("Established connection to telnet Server...")
        self.connected = True

    def connectionLost(self, reason):
        controller.getInstance().log().log_debug("Closed connection to telnet Server...")
        self.connected = False

        # Notify Clients
        for client in self.clients:
            client.abortConnection()

    def loseConnection(self):
        self.transport.loseConnection()

        for client in self.clients:
            client.loseConnection()

    def abortConnection(self):
        self.transport.abortConnection()

        for client in self.clients:
            client.abortConnection()

    def register(self, client):
        self.clients.append(client)

    def unregister(self, client):
        self.clients.remove(client)

    def send(self, sender, data):
        with self.lock:
            n = int(round(time.time() * 1000))

            # Only allow sending if we currently own the connection or
            # If the last sender has timeout
            if n - self.last_comm_time > self.timeout or self.sender == sender:
                self.sender = sender
                self.last_comm_time = int(round(time.time() * 1000))

                self.transport.write(data)

                # Echo to all clients
                #for client in self.clients:
                #    if client != sender:
                #        client.response(data)

                return True
            else:
                return False

    def dataReceived(self, data):
        for client in self.clients:
            client.response(data)


class TelnetClientFactory(ClientFactory):
    def __init__(self, multiplexer):
        self.multiplexer = multiplexer

    def buildProtocol(self, address):
        return TelnetClient()

    def clientConnectionLost(self, connection, reason):
        self.multiplexer.stop()


class TelnetMultiplexHandler(Telnet):
    def __init__(self, connection):
        Telnet.__init__(self)

        self.connection = connection

        if self.connection and self.connection.connected:
            self.connection.register(self)

        else:
            self.abortConnection()

    def connectionMade(self):
        self.will(ECHO).addErrback(self.handleError)
        self.will(SGA).addErrback(self.handleError)
        #self.wont(LINEMODE).addErrback(self.handleError)

    def enableLocal(self, option):
        return option in (ECHO, SGA)

    def dataReceived(self, data):
        while not self.connection.send(self, data):
            time.sleep(0.5)

    def loseConnection(self):
        self.transport.loseConnection()

    def abortConnection(self):
        self.transport.abortConnection()

    def response(self, data):
        self.transport.write(data)

    def connectionLost(self, reason):
        self.connection.unregister(self)

    def handleError(self, error):
        controller.getInstance().log().log_error(str(error))


class TelnetMultiplexFactory(Factory):
    def __init__(self, client):
        self.client = client

    def buildProtocol(self, address):
        return TelnetMultiplexHandler(self.client)

class Multiplexer:
    def __init__(self, host, port, wait_condition=None):
        self.port = port
        self.host = host

        self.reactor_thread = None
        self.client = None
        self.client_deferred = None
        self.client_delayed = None
        self.server = None
        self.server_deferred = None

        self.wait_condition = wait_condition

        self.lock = threading.Lock()

    def start(self):
        controller.getInstance().log().log_info("Starting multiplex server...")

        self.start_client()

        if not reactor.running:
            self.reactor_thread = ReactorThread()
            self.reactor_thread.start()

    def start_client(self):
        factory = TelnetClientFactory(self)

        # Connect
        endpoint = TCP4ClientEndpoint(reactor, self.host, self.port)
        self.client_deferred = endpoint.connect(factory)

        # Notify us when the client has started
        self.client_deferred.addCallback(self.client_started)
        self.client_deferred.addErrback(self.client_start_error)

        # Set a timeout for the connection attempt
        self.client_delayed = reactor.callLater(30, self.client_check_start_error)

    def client_started(self, client):
        self.client = client

        # Go for the server
        self.start_server()

    def notify_waiting_threads(self):
        if self.wait_condition:
            self.wait_condition.acquire()
            self.wait_condition.notify_all()
            self.wait_condition.release()

    def client_start_error(self, failure):
        with self.lock:
            controller.getInstance().log().log_error("Could not connect to QEMU Monitor!")

            # Reset
            if self.client_delayed and self.client_delayed.active():
                self.client_delayed.cancel()

            self.client = None
            self.client_deferred = None
            self.client_delayed = None

            # Notify
            self.notify_waiting_threads()

            failure.trap(ConnectError, CancelledError)

    def client_check_start_error(self):
        with self.lock:
            # No connection?
            if (not self.client and self.client_deferred and
                not self.client_deferred.called):
                self.client_deferred.cancel()
                return

            # Client lost connection?
            if self.client and not self.client.connected:
                self.client = None
                self.client_deferred = None
                self.client_delayed = None

                self.notify_waiting_threads()

                return

    def start_server(self):
        factory = TelnetMultiplexFactory(self.client)

        # Listen, 0 for finding any available port
        endpoint = TCP4ServerEndpoint(reactor, CLIENT_PORT, interface="localhost")

        # Deferred
        self.server_deferred = endpoint.listen(factory)
        self.server_deferred.addCallback(self.server_started)
        self.server_deferred.addErrback(self.server_start_error)

    def server_start_error(self, failure):
        controller.getInstance().log().log_error("Could not start multiplex server!")

        # Stop
        self.stop()

        failure.trap(CannotListenError)

    def server_started(self, port):
        self.server = port
        self.notify_waiting_threads()

    def get_address(self):
        if self.client and self.server:
            return self.server.getHost()

        return None

    def stop(self):
        with self.lock:
            controller.getInstance().log().log_info("Stopping multiplex server...")

            if self.client:
                self.client.abortConnection()

            if self.client_delayed and self.client_delayed.active():
                self.client_delayed.cancel()

            self.client = None
            self.client_deferred = None
            self.client_delayed = None

            if self.server:
                self.server.stopListening()

            self.server = None
            self.server_deferred = None

            self.notify_waiting_threads()

    def exit(self):
        self.stop()

        if self.reactor_thread:
            self.reactor_thread.stop()

class ReactorThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        if not reactor.running:
            reactor.run(installSignalHandlers=0)

    def stop(self):
        if reactor.running:
            #reactor.stop()
            reactor.sigTerm()
            #reactor.crash()

if __name__ == "__main__":
    #factory = TelnetMultiplexFactory("127.0.0.1", 3333)
    #reactor.listenTCP(33333, factory)
    #reactor.run()

    def signal_handler(signal, frame):
        print('exiting...')
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    desthost, destport = ("localhost", 8999)

    print("running telnet multiplexer for %s on port %d" % (desthost, destport))

    m = Multiplexer(desthost, destport)
    m.start()

    print("Multiplexing on port %d" % CLIENT_PORT) #m.get_address().port)

