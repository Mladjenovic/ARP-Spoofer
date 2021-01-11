import socket

# Info about the server that we want to connect to
host = "192.168.1.6"
port = 12345

login_success = "Uspeh"
login_failure = "Neuspeh"

# Getting the connection ready
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#Connection
s.connect((host, port))

server_data = s.recv(1024)
print(server_data.decode())



while True:
    username = input("Enter username")
    password = input("Enter password")
    sending_message = username + '|' + password
    s.sendall(sending_message.encode())

    server_data = s.recv(1024)
    
    if server_data.decode() == login_success:
        print(login_success)
        print('-'*79)
        break
    elif server_data.decode() == login_failure:
        print(login_failure)
        continue

#Data from server
while True:
    server_data = s.recv(1024)

    if server_data.decode() == 'end':
        print("Closing client")
        s.close()
        break

    print('-'*40)
    print("Received: ", server_data.decode())

    inp = input(">>") #user|pass
    s.sendall(inp.encode())

    if inp == 'end':
        print("Closing client")
        s.close()
        break




