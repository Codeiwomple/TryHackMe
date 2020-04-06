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
- Connect to server via UDP to get the initial instructions
- Connect again to receive the next set 
- Store key and iv (Hard coded for ease)
- Convert the checksum into a more usable/ readable format 

- Connect agin, and receive AES CGM cipher text and tags
- Decrypt 
- Hash the plain text and compare it to the given checksum
- Repeat this until a match is found

```python 
import socket
import hashlib
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

def Main():
    host = sys.argv[1] #Get ip from user input
    port = 4000
    server = (host, port)
    iv = b'secureivl337' #Hardcoded for ease
    key = b'thisisaverysecretkeyl337'

    #Create socket *No need to connect as using UDP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    #Get initial message
    s.sendto(b"hello", server)
    print(recv(s))
    #Get the rest of the information
    s.sendto(b"ready", server)
    data = recv(s)
    print(data)
    checksum = data[104:136].hex() #Convert to hex to make comparison easier

    #Loop flags until checksums match
    while True:
        #Get the cipher text
        s.sendto(b"final", server)
        cText = bytes(recv(s))
        #Get the tag
        s.sendto(b"final", server)
        tag = bytes(recv(s))
        #Decrypt
        pText = decrypt(key, iv, cText, tag)
        #Compare
        if hashlib.sha256(pText).hexdigest() != checksum:
            continue
        else:
            print(f"The flag is: {pText}")
            break

def recv(s):
    try:
        data = s.recv(1024)
        return data
    except Exception as e:
        print(str(e))

def decrypt(key, iv, cText, tag):
    #Create AES GCM decryptor object
    decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag),
    backend = default_backend()).decryptor()
    #Return decrypted text
    return decryptor.update(cText) + decryptor.finalize()

if __name__ == '__main__':
    Main()
```
