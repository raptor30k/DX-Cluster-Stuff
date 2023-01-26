
import re
import sys
import time
import socket
import threading
from queue import Queue
from datetime import datetime
from telnetserver import TelnetServer
from TCPsocket_server import ThreadedTCPRequestHandler, ThreadedTCPServer

clients = []

callsign = ""
# callsign_pattern = re.compile("([a-z|0-9|/]+)", re.IGNORECASE)
callsign_pattern = re.compile('^([a-zA-Z0-9]{1,2}\d{1,2}[a-zA-Z]{1,3}(/[pP])?)$', re.IGNORECASE)
frequency_pattern = "([0-9|.]+)"
# pattern = re.compile("^DX de "+callsign_pattern+":\s+"+frequency_pattern+"\s+"+callsign_pattern+"\s+(.*)\s+(\d{4}Z)", re.IGNORECASE)


# Port 0 means to select an arbitrary unused port
TCPHOST, TCPPORT = "localhost", 7777
TCPserver = any
login = False
lineList = any
# data_file = "skimmerMsgs_20221218_073721Z_1900kHz.txt"
data_file = "skimmer_msgs.txt"


class TcpClient():
    pass


def readFile(file):
    with open(file) as f:
        lineList = f.read().splitlines()
    return lineList
    

def processFile(client,file):
    global telnetServer
    for line in readFile(file):
        time.sleep(1)
        timeNow = datetime.utcnow().strftime("%H%M")+'Z'
        newLine = line[:-5] + timeNow
        telnetServer.send_message(client, newLine)
        print(newLine)
    

def valid_callsign(call):
    valid = re.match('^[a-zA-Z0-9]{1,2}\d{1,2}[a-zA-Z]{1,3}(/[pP])?$', call, re.DOTALL)
    if valid:
        return True
    else:
        return False

def get_loginDate():
    return datetime.utcnow().strftime("%d-%b %H%M")+'Z'


def process_userInput(client, message):
    global callsign, login
    match = callsign_pattern.match(message)
    if valid_callsign(message) and login:
        callsign = message # match.group(1)
        dateStr = get_loginDate()
        reply = callsign + " de K7UOP "+dateStr+" arc >"
        telnetServer.send_message(client, reply)
        print("sent to Client {}: {}".format(client, reply))
        login = False
        # processFile(client)
    elif  message.lower() == "bye":
        pass
        # telnetServer.shutdown()
        # TCPserver.shutdown()
        # quit()
    elif message.lower() == "sendfile":
        processFile(client,data_file)

def run_main_loop(tcpInput):
    global login, tcpServer
    while True:
        # Make the telnetServer parse all the new events
        telnetServer.update()

        # For each newly connected client
        for new_client in telnetServer.get_new_clients():
            # Add them to the client list 
            clients.append(new_client)
            # Send a welcome message
            telnetServer.send_message(new_client, 'Please enter your call:')
            telnetServer.send_message(new_client, 'login: ') #SDRuno DX Cluster plug-in
            login = True
            print("Client {} Connected.".format(new_client))
            

        # For each client that has recently disconnected
        for disconnected_client in telnetServer.get_disconnected_clients():
            if disconnected_client not in clients:
                continue

            # Remove him from the clients list
            clients.remove(disconnected_client)

            print("Client {} disconnected. {} Clients remaining.".format(disconnected_client, len(clients)))
        
        
        # For each message a client has sent
        for sender_client, message in telnetServer.get_messages(): 
            if sender_client not in clients:
                continue
            
            process_userInput(sender_client, message)
            print("Client {} sent: {}".format(sender_client, message))
        
        """ 
        NOTE: If 0 clients, the tcpInput Queue would fill up and creates multiple new Threads.
        Should figure out a way to disable / turn off TCP server when no clients.
        Temporarily just emptying the queue while no clients.
        Checking "login" prevents disruption of the log on process.
        """
        if login or (len(clients) == 0 and not tcpInput.empty()):
            tcpInput.queue.clear()
            continue
        
        # check Queue for TCP input messages and send to telnet clients
        msg = get_q(tcpInput).strip()
        if len(msg) > 0 and msg.startswith("DX de"):
            print(msg) #.rstrip())
            for client in clients:
                telnetServer.send_message(client, msg)

def get_q(que):
    try:
        inputmsg = que.get(False) # make it non-blocking
        return inputmsg.decode()
    except Exception as e: #Queue.Empty:
        pass
    return ''

def TCPclient(ip, port, message):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((ip, port))
        sock.sendall(bytes(message, 'ascii'))
        response = str(sock.recv(1024), 'ascii')
        print("Received: {}".format(response))

def startTCP_server(TCPHOST, TCPPORT, que):
    TCPserver = ThreadedTCPServer((TCPHOST, TCPPORT), ThreadedTCPRequestHandler, input_q=que)
    TCPserver_thread = threading.Thread(target=TCPserver.serve_forever)
    TCPserver_thread.daemon = True
    TCPserver_thread.start()
    print("TCPserver loop running in thread:", TCPserver_thread.name, TCPPORT)
    return TCPserver

def main(args):
    global telnetServer, tcpServer
    telnetServer = TelnetServer(port=8888)
    
    input_q = Queue() #(maxsize=5)
    tcpServer = startTCP_server(TCPHOST, 7772, input_q)

    run_main_loop(input_q)
    

if __name__ == "__main__":
    try:
        main(sys.argv)
    except KeyboardInterrupt:
        print('Caught CTRL-C')
        sys.exit

