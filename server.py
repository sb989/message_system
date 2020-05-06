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
from queue import Queue


def createAccount(conn,crsr,sqlconn):
    createCommand = 'INSERT INTO user_info (Username,Pword,LoggedIn,Salt) VALUES(%s,%s,%s,%s)'
    userExistCommand = 'SELECT COUNT(Username) FROM user_info WHERE (Username = %s)'
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

def login(conn,crsr,sqlconn):
    updateLoggedIn = 'UPDATE user_info SET LoggedIn = %s WHERE (Username = %s)'
    retreivePwordCommand = 'SELECT Pword FROM user_info WHERE (Username = %s)'
    storePkey = 'UPDATE user_info SET PublicKey = %s WHERE (Username = %s) '
    getSalt = 'SELECT Salt FROM user_info WHERE (Username = %s)'
    userExistCommand = 'SELECT COUNT(Username) FROM user_info WHERE (Username = %s)'

    sizeofuser = int.from_bytes(conn.recv(28),byteorder='big')
    user = conn.recv(sizeofuser)
    crsr.execute(userExistCommand,(user,))
    ans = crsr.fetchall()
    print('the amount of usernames that match that are ')

    while ans[0][0] == 0:
        conn.send((1).to_bytes(1,byteorder='big'))
        sizeofuser = int.from_bytes(conn.recv(28),byteorder='big')
        user = conn.recv(sizeofuser)
        crsr.execute(userExistCommand,(user,))
        ans = crsr.fetchall()
    conn.send((0).to_bytes(1,byteorder='big'))

    sizeofpword = int.from_bytes(conn.recv(28),byteorder='big')
    pword = conn.recv(sizeofpword)

    crsr.execute(getSalt,(user.decode(),))
    salt = (crsr.fetchall())[0][0]
    salt = bytes(salt)
    print('the salt returned is')
    print(salt)
    print(type(salt))
    crsr.execute(retreivePwordCommand,(user.decode(),))
    ans = (crsr.fetchall())[0][0]
    ans = ans.encode()
    #print(ans)
    ans = bytes(ans)

    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000,backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(user))
    f = Fernet(key)
    ans = f.decrypt(ans)
    print(ans)
    while ans != pword:
        conn.send((1).to_bytes(1,byteorder='big'))
        sizeofpword = int.from_bytes(conn.recv(28),byteorder='big')
        pword = conn.recv(sizeofpword)
        print(pword)
    conn.send((0).to_bytes(1,byteorder='big'))
    sizeofpkey = int.from_bytes(conn.recv(28),byteorder='big')
    pkey = conn.recv(sizeofpkey)
    crsr.execute(storePkey,(pkey,user.decode(),))
    crsr.execute(updateLoggedIn,('ONLINE',user.decode(),))
    sqlconn.commit()
    return user.decode()

def returnOnlineUsers(conn,crsr,sqlconn):
    getUsersOnline = "SELECT Username FROM user_info WHERE (LoggedIn = 'ONLINE')"
    crsr.execute(getUsersOnline)
    users = crsr.fetchall()
    print(users)
    users = str(users)
    users = users.encode()
    sizeofusers = sys.getsizeof(users)
    conn.send(sizeofusers.to_bytes(3,byteorder='big'))
    conn.send(users)

def receiveMessage(conn,crsr,sqlconn,q,user):
    getOnlineUserPublicKey = "SELECT PublicKey FROM user_info WHERE (LoggedIn = 'ONLINE' AND Username = %s)"
    userExistCommand = 'SELECT COUNT(Username) FROM user_info WHERE (Username = %s)'
    sizeofreceiver = int.from_bytes(conn.recv(28),byteorder='big')
    receiver = conn.recv(sizeofreceiver)
    print(receiver.decode())
    crsr.execute(userExistCommand,(receiver.decode(),))
    amount = crsr.fetchall()
    if amount[0][0] == 0:
        print('user does not exist')
        conn.send((sys.getsizeof('1')).to_bytes(1,byteorder='big'))
        conn.send('1'.encode())
    crsr.execute(getOnlineUserPublicKey,(receiver,))
    key = crsr.fetchall()
    if not key[0]:
        print('user is not online')
        conn.send((sys.getsizeof('0')).to_bytes(1,byteorder='big'))
        conn.send('0'.encode())
    else:
        print('valid receiver')
        sizeofmess = int.from_bytes(conn.recv(28),byteorder='big')
        mess = conn.recv(sizeofmess)
        crsr.execute(getOnlineUserPublicKey,(user,))
        publickey = crsr.fetchall()
        publickey = publickey[0][0]
        l = []
        l.append(receiver)
        l.append(mess)
        l.append(publickey)
        q.put(l)

def sendMessage(conn,user,q):
    print('starting sendMessage thread')
    while True:
        try:
            if not q.empty():
                print('q is not empty rn')
                print(q.qsize())
                for i in range(q.qsize()):
                    x = q.get()
                    print(x)
                    if x[0] == user:
                        print('found a message for me')
                        pack = []
                        pack.append('message')
                        pack.append(x[1])
                        pack.append(x[2])
                        s = str(pack)
                        enc_s = s.encode()
                        sizeofenc_s = sys.getsizeof(enc_s)
                        conn.send((sizeofenc_s).to_bytes(3,byteorder='big'))
                        conn.send(enc_s)
                        break
                    q.put(x)
        except Exception as exc:
            print(type(exc))
            print(exc.args)
            break


def userLoop(conn_addr,q):
    conn = conn_addr[0]
    addr = conn_addr[1]
    option = 0
    sqlconn = mysql.connector.connect(user='root',password='Swiffty@05631',host='localhost',database='message_system')
    crsr = sqlconn.cursor()
    updateLoggedIn = 'UPDATE user_info SET LoggedIn = %s WHERE (Username = %s)'
    online = False
    user = ''
    try:
        while option != 2:
            '''0 for nothing, 1 for create account, 2 for logging in, -1 for quitting'''
            option = int.from_bytes(conn.recv(28),byteorder='big')
            print(option)
            if option == 1:#creating account
                createAccount(conn,crsr,sqlconn)
            if option == -1:
                break
        if option == 2:#logggin into an account
            user = login(conn,crsr,sqlconn)
            online = True
            print(online)
            useraction = -1
            threading.Thread(target=sendMessage,args=(conn,user,q,)).start()
            while online:
                useraction = int.from_bytes(conn.recv(28),byteorder='big')
                if useraction==0:
                    returnOnlineUsers(conn,crsr,sqlconn)
                    useraction=-1
                if useraction==1:
                    print('receiving message')
                    receiveMessage(conn,crsr,sqlconn,q,user)
                    useraction=-1

    except (ConnectionResetError,BrokenPipeError):
        print('user disconnected')
        if online:
            crsr.execute(updateLoggedIn,('OFFLINE',user,))
            sqlconn.commit()

    except KeyboardInterrupt:
        if online:
            crsr.execute(updateLoggedIn,('OFFLINE',user,))
            sqlconn.commit()
        sock.close()
        sys.exit(0)
        print('closing')
    except Exception as exc:
        print(type(exc))
        print(exc.args)
        if online:
            crsr.execute(updateLoggedIn,('OFFLINE',user,))
            sqlconn.commit()

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('certificate.pem', 'privkey.pem')
loop = True
q = Queue()
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
        threading.Thread(target=userLoop,args=(ssock.accept(),q)).start()
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
