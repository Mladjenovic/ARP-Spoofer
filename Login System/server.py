import socket
import time

print("Login system v0.1")
print('-' * 79)
print("")

message = "Try to login into our system"
usernamepassword = "Konda|1234"
login_success = "Uspeh"
login_failure = "Neuspeh"
# message = input("message to be sent: ")

# Info about the local machine (server itself)
# host = input("Local ip: ")
# port = int(input("Port: "))
host = "192.168.1.8"
port = 12345

# Geting the connection ready
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, port))

#Listening
s.listen(5)

connection, address = s.accept()
print("Connection with: ", address)
print("Sending message: ")
connection.sendall(message.encode())

while True:
    received = connection.recv(1024)
    print("Received message: " + received.decode())

    received_string = received.decode()
    #recv_username = received_string[0]
    #recv_password = received_string[1]

    print(received_string)
    
    if received_string == usernamepassword:
        print(login_success)
        connection.sendall(login_success.encode())
        break
    else: 
        print(login_failure)
        connection.sendall(login_failure.encode())

time.sleep(0.00000000000000000000000000000000000000000000001)

message2 = 'Mozeti poceti dopisivanje'
connection.sendall(message2.encode())

while True:
    received = connection.recv(1024)
    if received.decode() == 'end':
        print("Closing server")
        s.close()
        break

    print(received.decode())

    inp = input(">>")
    if inp == 'end':
        print("Closing server")
        connection.sendall(("end").encode())
        s.close()
        break

    connection.sendall(inp.encode())

    


