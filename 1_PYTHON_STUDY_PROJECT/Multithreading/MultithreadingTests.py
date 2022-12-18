import ssl
import time
import json
import logging
import threading
from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer
from http.server import SimpleHTTPRequestHandler
from io import BytesIO
from bottle import response


def writer(x, event_for_wait, event_for_set):
    for i in range(10):
        event_for_wait.wait()  # wait for event
        event_for_wait.clear()  # clean event for future
        print(x);
        event_for_set.set()  # set event for neighbor thread


def Start2Theads():
    # init events
    event1 = threading.Event()
    event2 = threading.Event()

    # init threads
    t1 = threading.Thread(target=writer, args=(0, event1, event2))
    t2 = threading.Thread(target=writer, args=(1, event2, event1))

    # start threads
    t1.start()
    t2.start()

    event1.set()  # initiate the first event

    # join threads to the main thread
    t1.join()
    t2.join()


def Start3Theads():
    # init events
    event1 = threading.Event()
    event2 = threading.Event()
    event3 = threading.Event()

    # init threads
    t1 = threading.Thread(target=writer, args=(0, event1, event2))
    t2 = threading.Thread(target=writer, args=(1, event2, event3))
    t3 = threading.Thread(target=writer, args=(2, event3, event1))

    # start threads
    t1.start()
    t2.start()
    t3.start()

    event1.set()  # initiate the first event

    # join threads to the main thread
    t1.join()
    t2.join()
    t3.join()


####################################################################################

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        response = {'status': 'ok'}
        self.send_response(200);
        self.send_header('Content-Type', 'application/json')
        self.end_headers();
        self.wfile.write(bytes(json.dumps(response), 'UTF-8'))

    # def log_message(self, format, *args):
    #   logger.debug("Healthcheck from %s %s" % (self.address_string(), format % args))


def RunHTTPSServer():
    logging.basicConfig(level=logging.DEBUG)
    httpd = HTTPServer(("data.browser.mail.ru", 443), SimpleHTTPRequestHandler)
    httpd.socket = ssl.wrap_socket(httpd.socket, keyfile="R:\\Temp\\SSL\\RootAndLocalCert\\private.key",
                                   certfile="R:\\Temp\\SSL\\RootAndLocalCert\\data.browser.mail.ru.crt",
                                   server_side=True);
    httpd.serve_forever()


def RunTestServer():
    thread = threading.Thread(target=RunHTTPSServer);
    thread.start();
    thread.join();


###########################################################################################

class Server(threading.Thread):
    ''' Static Server class instance : '''
    __instance = None

    class __PrivateSingleton:
        def __init__(self):
            self.val1 = None

        def __str__(self):
            return "Value : " + self.val1

    def __new__(cls):  # __new__ always a classmethod
        if not Server.__instance:
            Server.__instance = Server.__PrivateSingleton()
        return Server.__instance

    def __getattr__(self, name):
        return getattr(self.instance, name)

    def __setattr__(self, name):
        return setattr(self.instance, name)


''' Server '''


class ServerOld(threading.Thread):
    instance = None

    class __PrivateSingleton:
        def __init__(self):
            self.val1 = None
            self.val2 = None

        def __str__(self):
            return "Value : " + self.val1

    def __new__(cls):  # __new__ always a classmethod
        if not Server.instance:
            Server.instance = Server.__PrivateSingleton()
        return Server.instance

    def __getattr__(self, name):
        return getattr(self.instance, name)

    def __setattr__(self, name):
        return setattr(self.instance, name)

    '''
    def __init__(self):
        super(Server, self).__init__()
        logging.basicConfig(level = logging.DEBUG)
        self.__host = "data.browser.mail.ru";
        self.__port = 443;
        #self.__handler = self.SimpleHTTPSRequestHandler;
        self.__handler = self.SimpleHTTPRequestHandlerTest;
    '''
    '''

    def run(self):
        try:
            self.runServer();
        finally:
            pass
        
    def getCounter(self):
        return 1;#self.SimpleHTTPRequestHandlerTest.__counter;
            
    def runServer(self):
        self.__httpd = HTTPServer((self.__host, self.__port), self.__handler)
        self.__httpd.socket = ssl.wrap_socket (self.__httpd.socket, 
                                               keyfile  = "R:\\Temp\\SSL\\RootAndLocalCert\\private.key",
                                               certfile = "R:\\Temp\\SSL\\RootAndLocalCert\\data.browser.mail.ru.crt",
                                               server_side = True);                        
        self.__httpd.serve_forever()
    '''

    class SimpleHTTPSRequestHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200);
            self.end_headers();
            self.wfile.write(b'Hello, world!');

    ''' SimpleHTTPRequestHandlerTest '''

    class SimpleHTTPRequestHandlerTest(BaseHTTPRequestHandler):
        '''
        def __init__(self):
            super(SimpleHTTPRequestHandlerTest, self).__init__()
        '''

        def do_GET(self):
            self.send_response(200);
            # self.send_header('Content-type', 'text/html')
            self.end_headers();
            self.wfile.write(b'Hello, world!');
            # self.counter = self.__counter + 1;

        def do_POST(self):
            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length)
            self.send_response(200)
            self.end_headers()
            response = BytesIO()
            response.write(b'This is POST request. ')
            response.write(b'Received: ')
            response.write(body)
            self.wfile.write(response.getvalue())


###########################################################################################

if __name__ == '__main__':
    Start2Theads();
    # Start3Theads();

    # RunTestServer();



    ''' 
    x = Server()
    x.val1 = 'sausage1'

    print(x)

    y = Server()
    y.val1 = 'eggs1'

    print(x)
    '''




    '''
    server1.start()
    #server.join();

    start = time.time()
    while True:
        time.sleep(5)
        print ("server1 counter value : ", server1.getCounter());
    '''
