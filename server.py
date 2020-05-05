import socket
import ssl
import mysql.connector
import threading
import sys
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

file = open('key.txt','r')
privateKey = file.read()
privateKey = privateKey.encode()
file.close()

def userLoop(conn_addr):
    conn = conn_addr[0]
    addr = conn_addr[1]
    option = 0
    sqlconn = mysql.connector.connect(user='root',password='Swiffty@05631',host='localhost',database='message_system')
    crsr = sqlconn.cursor()
    createCommand = 'INSERT INTO user_info (Username,Pword,LoggedIn,Salt) VALUES(%s,%s,%s,%s)'
    loginCommand = 'SELECT Pword FROM user_info WHERE (Username = %s)'
    userExistCommand = 'SELECT COUNT(Username) FROM user_info WHERE (Username = %s)'
    getSalt = 'SELECT Salt FROM user_info WHERE (Username = %s)'
    try:
        while option != 2:
            '''0 for nothing, 1 for create account, 2 for logging in, -1 for quitting'''
            option = int.from_bytes(conn.recv(28),byteorder='big')
            print(option)
            if option == 1:#creating account
                sizeofuser = int.from_bytes(conn.recv(28),byteorder='big')
                user = conn.recv(sizeofuser)
                crsr.execute(userExistCommand,(user.decode(),))
                ans = crsr.fetchall()
                print(ans)
                print(ans[0][0])
                while ans[0][0] > 0:
                    conn.send((1).to_bytes(1,byteorder='big'))
                    sizeofuser = int.from_bytes(conn.recv(28),byteorder='big')
                    user = conn.recv(sizeofuser)
                    crsr.execute(userExistCommand,(user,))
                    ans = crsr.fetchall()
                conn.send((0).to_bytes(1,byteorder='big'))
                sizeofpword = int.from_bytes(conn.recv(28),byteorder='big')
                pword = conn.recv(sizeofpword)
                print("creating user "+user.decode()+" with password "+pword.decode())
                salt = os.urandom(16)
                kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000,backend=default_backend())
                key = base64.urlsafe_b64encode(kdf.derive(user))
                f = Fernet(key)
                encPword = f.encrypt(pword)
                print('salt is ')
                print(salt)
                crsr.execute(createCommand,(user.decode(),encPword,'OFFLINE',salt,))
                sqlconn.commit()
            if option == -1:
                break
        if option == 2:
            sizeofuser = int.from_bytes(conn.recv(28),byteorder='big')
            user = conn.recv(sizeofuser)
            sizeofpword = int.from_bytes(conn.recv(28),byteorder='big')
            pword = conn.recv(sizeofpword)
            #command = 'SELECT Pword FROM user_info WHERE (Username='+user+');'
            #print(command)
            crsr.execute(getSalt,(user.decode(),))
            salt = (crsr.fetchall())[0][0]
            salt = bytes(salt)
            print('the salt returned is')
            print(salt)
            print(type(salt))
            crsr.execute(loginCommand,(user.decode(),))
            ans = (crsr.fetchall())[0][0]
            print(ans)
            ans = bytes(ans)

            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000,backend=default_backend())
            key = base64.urlsafe_b64encode(kdf.derive(user))
            f = Fernet(key)
            ans = f.decrypt(ans)
            print(ans)
            while ans != pword:
                conn.send((1).to_bytes(1,byteorder='big'))
                sizeofpword = int.from_bytes(conn.recv(28),byteorder='big')
                pword = conn.recv(sizeofpword).decode()


    except ConnectionResetError:
        print('user disconnected')
    except KeyboardInterrupt:
        sock.close()
        sys.exit(0)
        print('closing')

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('certificate.pem', 'privkey.pem')
loop = True
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
except:
    print("could not create socket")
    sock.close()
    sys.exit(0)
try:
    sock.bind(('0.0.0.0', 8443))
except ConnectionResetError:
    print('bind failed')
    sock.close()
    sys.exit(0)
try:
    sock.listen(10)
except:
    print("listen broke")
    sock.close()
    sys.exit(0)
try:
    ssock = context.wrap_socket(sock,server_side=True)
except:
    print("ssock broke")
    sock.close()
    sys.exit(0)
while loop:
    print('number of threads is ')
    print(threading.active_count())
    try:
        threading.Thread(target=userLoop,args=(ssock.accept(),)).start()
        #conn,addr = ssock.accept()
    except KeyboardInterrupt:
        sock.close()
        sys.exit(0)
        print('closing')
    except:
        print("thread or wrapping broke")
'''with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.bind(('0.0.0.0', 8443))
    sock.listen(5)
    with context.wrap_socket(sock, server_side=True) as ssock:
        conn, addr = ssock.accept()
'''
