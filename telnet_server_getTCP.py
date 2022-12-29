
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
data_file = "skimmer/skimmerMsgs_20221218_073721Z_1900kHz"



def readFile():
    global lineList
    with open(data_file) as f:
        lineList = f.read().splitlines()
    

def processFile(client):
    readFile()
    for line in lineList:
        # 0.........1.........2.........3.........4.........5.........6.........7.........
        # 01234567890123456789012345678901234567890123456789012345678901234567890123456789
        # DX de RW7F:		21190.0  R3UG         TNX                            0849Z
        # DX de SV3GLL:	24915.0  UT8IA        FT8 - 03dB from KN29 1414Hz    0849Z KM17
        # DX de DJ9YE:     50313.0  OH6OKSA      JO43HV<ES>KP32EQ FT8 mni tnx Q 0849Z JO43
        # DX de DL4CH:  10489710.0  DF7DQ        qo 100                         0853Z
        # DX de K6YR:       1828.5  W7CXX        CW                             2202Z
        # DX de K7UOP-#:    1836.5  VA7MM          32 dB  20 WPM                1812Z
        time.sleep(1)
        timeNow = datetime.utcnow().strftime("%H%M")+'Z'
        newLine = line[:-5] + timeNow
        telnetServer.send_message(client, newLine)
        print(newLine)
    

def valid_callsign(call):
    import re
    valid = re.match('^[a-zA-Z0-9]{1,2}\d{1,2}[a-zA-Z]{1,3}(/[pP])?$', call, re.DOTALL)
    if valid:
        return True
    else:
        return False

def process_userInput(client, message):
    global callsign, login
    match = callsign_pattern.match(message)
    if valid_callsign(message) and login:
        callsign = message # match.group(1)
        # reply = 'Hello  ' + callsign
        reply = callsign + " de K7UOP arc>"
        telnetServer.send_message(client, reply)
        print(reply)
        login = False
        # processFile(client)
    elif  message.lower() == "bye":
        telnetServer.shutdown()
        # TCPserver.shutdown()
        quit()
    elif message.lower() == "sendfile":
        processFile(client)

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
            if len(clients) == 0:
                print("Client {} disconnected. {} Clients remaining.".format(disconnected_client, len(clients)))
                

            # Send every client a message saying "Client X disconnected"
            for client in clients:
                telnetServer.send_message(client, "Client {} disconnected.".format(disconnected_client))
                print("Client {} disconnected. {} Clients remaining.".format(disconnected_client, len(clients)))

        # For each message a client has sent
        for sender_client, message in telnetServer.get_messages(): 
            if sender_client not in clients:
                continue

            print("Client {} sent: {}".format(sender_client, message))

            # Send every client a message reading: "I received "[MESSAGE]" from client [ID OF THE SENDER CLIENT]"
            for client in clients:
                # telnetServer.send_message(client, 'I received "{}" from client {}'.format(message, sender_client))
                process_userInput(client, message)
        
        # check for TCP input messages and send to telnet clients
        if len(clients) > 0:
            msg = get_q(tcpInput).rstrip()
            if len(msg) > 0:
                print(msg) #.rstrip())
                for client in clients:
                    telnetServer.send_message(client, msg)


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

def get_q(que):
    try:
        inputmsg = que.get(False) # make it non-blocking
        return inputmsg.decode()
    except Exception as e: #Queue.Empty:
        pass
    return ''

def main():
    global telnetServer, tcpServer
    telnetServer = TelnetServer(port=8888)
    
    input_q = Queue(maxsize=5)
    tcpServer = startTCP_server(TCPHOST, 7772, input_q)

    run_main_loop(input_q)

if __name__ == "__main__":
    main()

