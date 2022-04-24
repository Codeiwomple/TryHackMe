## Python scripting challenge from tryhackme.com 
Found here: https://tryhackme.com/room/scripting

### Task 1: Base64

Pretty straight forward fist task:
- Read the file in `msg` variable
- Decode 50 times with a basic `for` loop

```python
import base64

#Open file
with open('b64.txt') as f:
    msg = f.read()

#Decode 50 times
for _ in range(50):
    msg = base64.b64decode(msg)

print(f"The flag is: {msg.decode('utf8')}")
```

### Task 2: Gotta Catch em All 

For me this was the most time consuming. The hardest part was getting the data in a usable format:
- Attempt to connect to the server until the port is live
- Once connected, request the data, in this case operation, number, next port 
- Receive the data and assign it so we can use it
- Perform the operation 
- Move onto next port
- Repeat this until we hit port 9867
- Display answer

```python 
import socket
import time
import re
import sys

def Main():
    serverIP = sys.argv[1] #Get ip from user input
    serverPort = 1337
    oldNum = 0 #Start at 0 as per instruction

    while serverPort != 9765:
        try: #try until port 1337 available
            if serverPort == 1337:
                print(f"Connecting to {serverIP} waiting for port {serverPort} to become available...")

            #Create socket and connect to server
            s = socket.socket()
            s.connect((serverIP,serverPort))

            #Send get request to server
            gRequest = f"GET / HTTP/1.0\r\nHost: {serverIP}:{serverPort}\r\n\r\n"
            s.send(gRequest.encode('utf8'))

            #Retrieve data from get request
            while True:
                response = s.recv(1024)
                if (len(response) < 1):
                    break
                data = response.decode("utf8")

            #Format and assign the data into usable variables
            op, newNum, nextPort = assignData(data)
            #Perform given calculations
            oldNum = doMath(op, oldNum, newNum)
            #Display output and move on
            print(f"Current number is {oldNum}, moving onto port {nextPort}")
            serverPort = nextPort

            s.close()

        except:
            s.close()
            time.sleep(3) #Ports update every 4 sec
            pass

    print(f"The final answer is {round(oldNum,2)}")

def doMath(op, oldNum, newNum):
    if op == 'add':
        return oldNum + newNum
    elif op == 'minus':
        return oldNum - newNum
    elif op == 'divide':
        return oldNum / newNum
    elif op == 'multiply':
        return oldNum * newNum
    else:
        return None

def assignData(data):
    dataArr = re.split(' |\*|\n', data) #Split data with multi delim
    dataArr = list(filter(None, dataArr)) #Filter null strings
    #Assign the last 3 values of the data
    op = dataArr[-3]
    newNum = float(dataArr[-2])
    nextPort = int(dataArr[-1])

    return op, newNum, nextPort

if __name__ == '__main__':
    Main()
```

Run with `python3 webClient.py <ip>`

### Task 3: Encrypted Server Chit Chat 

Had to visit the docs a few times for this one:
- Connect to server via UDP with `"hello"` payload to get the initial instructions.
- Connect again to receive the next set but with `"ready"` payload.
- Store key and iv (Hard coded for ease).
- Connect agin, and receive AES CGM cipher text and tags but with `"final"` payload.
- Decrypt.
- Hash the plain text and compare it to the given checksum.
- Repeat this until a match is found.

```python 
#!/usr/bin/env python3
import socket, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes

HOST = sys.argv[1]  # UDP server IP
PORT = 4000  # UDP server port
BUFFER_SIZE = 2048


def handle_UDP_conn(udp_sock, udp_payload):
    udp_sock.sendto(udp_payload, (HOST, PORT))
    (recvd_data, server_addr) = udp_sock.recvfrom(BUFFER_SIZE)
    return recvd_data


def main():
    with socket.socket(type=socket.SOCK_DGRAM) as s:
        recvd_data = handle_UDP_conn(s, b"hello")
        recvd_data = handle_UDP_conn(s, b"ready")
        server_response = recvd_data.split(b" ")
        key = server_response[0].split(b":")[1]
        iv = server_response[1].split(b":")[1]
        flag_checksum = server_response[14]

        cipher = AESGCM(key)
        while True:
            cipher_text = handle_UDP_conn(s, b"final")
            tag = handle_UDP_conn(s, b"final")
            cipher_text += tag
            plain_text_flag = cipher.decrypt(iv, cipher_text, None)

            hash_obj = hashes.Hash(hashes.SHA256())
            hash_obj.update(plain_text_flag)
            if hash_obj.finalize() == flag_checksum:
                print(f"Target Flag: {plain_text_flag}")
                break


if __name__ == "__main__":
    main()

```
Run like so:
```sh
chmod +x udpClient.py && ./udpClient.py <ip>
```
