import socket
import ssl
import sqlite3
import threading
import sys
def userLoop(conn_addr):
    conn = conn_addr[0]
    addr = conn_addr[1]
    option = 0
    sqlconn = sqlite3.connect("message_system.db")
    crsr = sqlconn.cursor()
    try:
        while option != 2:
            '''0 for nothing, 1 for create account, 2 for logging in, -1 for quitting'''
            option = conn.recv(28)
            if option == 1:
                sizeofuser = conn.recv(28)
                user = conn.recv(sizeofuser)
                sizeofpword = conn.recv(28)
                pword = conn.recv(sizeofpword)
                '''TO DO: check if the username is already taken'''
                print("creating user "+user+" with password "+pword)
                command = 'INSERT INTO user_info VALUES('+user+','+pword+',OFFLINE,NULL);'
                print(command)
                #crsr.execute(command)
            if option == -1:
                break
        if option == 2:
            sizeofuser = conn.recv(28)
            user = conn.recv(sizeofuser)
            sizeofpword = conn.recv(28)
            pword = conn.recv(sizeofpword)
            command = 'SELECT Pword FROM user_info WHERE (Username='+user+');'
            print(command)
    except ConnectionResetError:
        print('user disconnected')
        #crsr.execute(command)
        #ans = crsr.fetchall()

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
except:
    print('bind failed')
    sock.close()
    sys.exit(0)
while loop:
    try:
        sock.listen(10)
        try:
            ssock = context.wrap_socket(sock,server_side=True)
            threading.Thread(target=userLoop,args=(ssock.accept(),)).start()
            #conn,addr = ssock.accept()
        except:
            print("thread or wrapping broke")

    except KeyboardInterrupt:
        sock.close()
        sys.exit(0)
        print('closing')
    except:
        print("something broke")
'''with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.bind(('0.0.0.0', 8443))
    sock.listen(5)
    with context.wrap_socket(sock, server_side=True) as ssock:
        conn, addr = ssock.accept()
'''
