import socket

print("CHAT Server v0.1")
print('-' * 79)
print("")

message = "IT Department"
# message = input("message to be sent: ")

# Info about the local machine (server itself)
# host = input("Local ip: ")
# port = int(input("Port: "))
host = "192.168.1.6"
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

    


