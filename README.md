# DX-Cluster-Stuff

Very simplistic functional programming, only using Objects where necessary. 

Python programs to connect to a DX Cluster Telnet server and either:
  1. write_telnet_tofile.py - logs in and then writes DX de lines to a file.
  2. telnet_client_sendTCP.py - logs in and sends DX de messages to a TCP connection at Host, Port.

A program, telnet_server_getTCP.py - Waits for Telnet clients (e.g. Spot Collector, SDRuno plug-in DX Cluster, etc.)
to log in. It then sends them spots read from a file or received from another program via TCP connection.

The program TCPsocket_server.py - serves threaded classes (for import) using Queues to communicate with main thread. 

