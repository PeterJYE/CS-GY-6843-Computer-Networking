# import socket module
from socket import *
# In order to terminate the program
import sys


def webServer(port=13331):
    serverSocket = socket(AF_INET, SOCK_STREAM)

    # Prepare a server socket
    serverSocket.bind(("", port))

    # Fill in start
    serverSocket.listen(1)
    # Fill in end

    while True:
        # Establish the connection

        print('Ready to serve...')
        connectionSocket, addr = serverSocket.accept() # Fill in start -are you accepting connections? 
        # Fill in end

        try:
            message =  connectionSocket.recv(1024).decode() # Fill in start -a client is sending you a message
            # Fill in end 
            filename = message.split()[1]

            # opens the client requested file. 
            # Plenty of guidance online on how to open and read a file in python. How should you read it though if you plan on sending it through a socket?
            f = open(filename[1:],  # fill in start
                     'rb')
            # fill in end

            # This variable can store the headers you want to send for any valid or invalid request.   What header should be sent for a response that is ok?    
            # Fill in start 
            header = b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nServer: PythonSocketServer\r\nConnection: close\r\n\r\n"
            # Fill in end

            # Fill in start - append your html file contents
            outputdata = f.read()
            # Fill in end 

            # Send the content of the requested file to the client (don't forget the headers you created)!
            # Send everything as one send command, do not send one line/item at a time!

            # Fill in start
            connectionSocket.send(header + outputdata)
            # Fill in end

            connectionSocket.close()  # closing the connection socket

        except Exception as e:
            # Send response message for invalid request due to the file not being found (404)
            # Remember the format you used in the try: block!
            # Fill in start
            header = b"HTTP/1.1 404 Not Found\r\nContent-Type: text/html; charset=UTF-8\r\nServer: PythonSocketServer\r\nConnection: close\r\n\r\n"
            outputdata = b"<html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>"
            connectionSocket.send(header + outputdata)
            # Fill in end

            # Close client socket
            # Fill in start
            connectionSocket.close()
            # Fill in end

    # Commenting out the below (some use it for local testing). It is not required for Gradescope, and some students have moved it erroneously in the While loop. 
    # DO NOT PLACE ANYWHERE ELSE AND DO NOT UNCOMMENT WHEN SUBMITTING, YOU ARE GONNA HAVE A BAD TIME
    # serverSocket.close()
    # sys.exit()  # Terminate the program after sending the corresponding data


if __name__ == "__main__":
    webServer(13331)
