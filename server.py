import socket
import ssl
import mysql.connector
import threading
import sys
def userLoop(conn_addr):
    conn = conn_addr[0]
    addr = conn_addr[1]
    option = 0
    sqlconn = mysql.connector.connect(user='root',password='Swiffty@05631',host='127.0.0.1',database='message_system')
    crsr = sqlconn.cursor()
    createCommand = 'INSERT INTO user_info (Username,Pword,LoggedIn) VALUES(%s,%s,%s)'
    loginCommand = 'SELECT Pword FROM user_info WHERE (USERNAME = %s)'
    try:
        while option != 2:
            '''0 for nothing, 1 for create account, 2 for logging in, -1 for quitting'''
            option = int.from_bytes(conn.recv(28),byteorder='big')
            print(option)
            if option == 1:
                sizeofuser = int.from_bytes(conn.recv(28),byteorder='big')
                user = conn.recv(sizeofuser).decode()
                sizeofpword = int.from_bytes(conn.recv(28),byteorder='big')
                pword = conn.recv(sizeofpword).decode()
                '''TO DO: check if the username is already taken'''
                print("creating user "+user+" with password "+pword)
                #command = 'INSERT INTO user_info VALUES('+user+','+pword+',OFFLINE,NULL);'
                #print(command)
                crsr.execute(createCommand,(user,pword,'OFFLINE'))
            if option == -1:
                break
        if option == 2:
            sizeofuser = int.from_bytes(conn.recv(28),byteorder='big')
            user = conn.recv(sizeofuser).decode()
            sizeofpword = int.from_bytes(conn.recv(28),byteorder='big')
            pword = conn.recv(sizeofpword).decode()
            #command = 'SELECT Pword FROM user_info WHERE (Username='+user+');'
            #print(command)
            crsr.execute(loginCommand,(user))
            ans = crsr.fetchall()
            print(ans)
    except ConnectionResetError:
        print('user disconnected')


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
