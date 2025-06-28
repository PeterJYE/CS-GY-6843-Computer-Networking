from socket import *

def smtp_client(port=1025, mailserver='127.0.0.1'):
    msg = "\r\n My message"
    endmsg = "\r\n.\r\n"

    # Create socket called clientSocket and establish a TCP connection with mailserver and port
    clientSocket = socket(AF_INET, SOCK_STREAM)
    clientSocket.connect((mailserver, port))

    # Receive server greeting
    recv = clientSocket.recv(1024).decode()
    # if recv[:3] != '220':
    #     print('220 reply not received from server.')

    # Send HELO command and receive server response
    heloCommand = 'HELO Alice\r\n'
    clientSocket.send(heloCommand.encode())
    recv1 = clientSocket.recv(1024).decode()
    # if recv1[:3] != '250':
    #     print('250 reply not received from server.')

    # Send MAIL FROM command and receive server response
    mailFrom = 'MAIL FROM:<jy3991@nyu.edu>\r\n'
    clientSocket.send(mailFrom.encode())
    recv2 = clientSocket.recv(1024).decode()
    # if recv2[:3] != '250':
    #     print('250 reply not received from server.')

    # Send RCPT TO command and receive server response
    rcptTo = 'RCPT TO:<jingtaoye03@gmail.com>\r\n'
    clientSocket.send(rcptTo.encode())
    recv3 = clientSocket.recv(1024).decode()
    # if recv3[:3] != '250':
    #     print('250 reply not received from server.')

    # Send DATA command and receive server response
    data = 'DATA\r\n'
    clientSocket.send(data.encode())
    recv4 = clientSocket.recv(1024).decode()
    # if recv4[:3] != '354':
    #     print('354 reply not received from server.')

    # Send message data
    clientSocket.send(msg.encode())

    # Message ends with a single period
    clientSocket.send(endmsg.encode())
    recv5 = clientSocket.recv(1024).decode()
    # if recv5[:3] != '250':
    #     print('250 reply not received from server.')

    # Send QUIT command and receive server response
    quitCmd = 'QUIT\r\n'
    clientSocket.send(quitCmd.encode())
    recv6 = clientSocket.recv(1024).decode()
    # if recv6[:3] != '221':
    #     print('221 reply not received from server.')

    clientSocket.close()

if __name__ == '__main__':
    smtp_client(1025, '127.0.0.1')
