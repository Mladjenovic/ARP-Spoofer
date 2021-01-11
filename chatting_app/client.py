import socket

# Info about the server that we want to connect to
host = "10.0.2.15"
port = 12345

# Getting the connection ready
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#Connection
s.connect((host, port))

#Data from server
while True:
    server_data = s.recv(1024)
    if server_data.decode() == 'end':
        print("Closing client")
        s.close()
        break

    print('-'*40)
    print("Received: ", server_data.decode())

    inp = input(">>")
    s.sendall(inp.encode())

    if inp == 'end':
        print("Closing client")
        s.close()
        break




