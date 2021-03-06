import socket
import ssl
import sys
import nacl.utils
from nacl.public import PrivateKey, Box
from queue import Queue
import threading
from threading import Lock
from requests import get

lock = Lock()
class Client:
    privateKey = b''
    publicKey = b''
    q = Queue()
    username = ''
    def login(self,connection):
        connection.send((2).to_bytes(1,byteorder='big'))
        user = input("Enter your username.")
        sizeofuser = sys.getsizeof(user)
        connection.send((sizeofuser).to_bytes(3,byteorder='big'))
        connection.send(user.encode())
        response = int.from_bytes(connection.recv(28),byteorder='big')
        print(response)
        while response >0:
            user = input("You entered a user name that does not exist. Please re-enter your user name or press q to quit.")
            if user =='q':
                return True
            sizeofuser = sys.getsizeof(user)
            connection.send((sizeofuser).to_bytes(3,byteorder='big'))
            connection.send(user.encode())
            response = int.from_bytes(connection.recv(28),byteorder='big')

        password = input("Enter your password.")
        sizeofpword = sys.getsizeof(password)
        connection.send((sizeofpword).to_bytes(3,byteorder='big'))
        connection.send(password.encode())
        response = int.from_bytes(connection.recv(28),byteorder='big')
        while response >0:
            password = input("You entered the wrong password. Please re-enter your password or press q to quit.")
            if password == 'q':
                return True
            sizeofpword = sys.getsizeof(password)
            connection.send((sizeofpword).to_bytes(3,byteorder='big'))
            connection.send(password.encode())
            response = int.from_bytes(connection.recv(28),byteorder='big')
        skclient = PrivateKey.generate()
        pkclient = skclient.public_key
        pkclient = bytes(pkclient)
        sizeofpkclient = sys.getsizeof(pkclient)
        connection.send((sizeofpkclient).to_bytes(3,byteorder='big'))
        connection.send(pkclient)
        self.privateKey = bytes(skclient)
        self.publicKey = pkclient
        print('the public key i sent to the server is ',pkclient)
        self.username = user
        return False

    def createAccount(self,connection):
        connection.send((1).to_bytes(1,byteorder='big'))
        user = input("Enter the user name. It must be between 8 and 40 characters.")
        while len(user)<8 or len(user)>40:
            user = input("The user name entered does not meet the length requirements. Please enter a user name between 8 and 40 characters.")
        sizeofuser = sys.getsizeof(user)
        connection.send((sizeofuser).to_bytes(3,byteorder='big'))
        connection.send(user.encode())
        response = int.from_bytes(connection.recv(28),byteorder='big')
        while response >0:
            user = input("That user name is already taken. Please enter a new one.")
            sizeofuser = sys.getsizeof(user)
            connection.send((sizeofuser).to_bytes(3,byteorder='big'))
            connection.send(user.encode())
            response = int.from_bytes(connection.recv(28),byteorder='big')
        password = input("Enter your password. It must be between 8 and 40 characters and contain uppercase letters, lowercase letters, numbers, and special characters (!,@,#,%, etc.). It cannot contain spaces.")
        while len(password)<8 or len(password)>40 or not any(str.isdigit(c) for c in password) or not any(str.islower(c) for c in password) or not any(str.isupper(c) for c in password) or not any(c for c in password if (not c.isalnum() and not c.isspace())) or any(c for c in password if(c.isspace())):
            password = input("The password entered did not meet the requirements. Please enter a new password.")
        confirm = input("Confirm the password by entering it again.")
        while confirm != password:
            print('password is '+password+'confirm is '+confirm)
            confirm = input("That did not match the password entered. Please re-enter the password.")

        sizeofpword = sys.getsizeof(password)
        connection.send((sizeofpword).to_bytes(3,byteorder='big'))
        connection.send(password.encode())
        print("You have created an account.")

    def connectToServer(self,hostname,port,ca_name,ca_file):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_verify_locations(ca_file)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        #with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        try:
            sock.settimeout(10)
            sock.connect((hostname,port))
            ssock = context.wrap_socket(sock,server_hostname = ca_name)
            #with context.wrap_socket(sock,server_hostname = ca_name) as ssock:
            try:
                print(ssock.server_hostname)
                print(ssock.version())
                cert = ssock.getpeercert()
                #print(cert)
                #print(ca_name)
                ssl.match_hostname(cert,ca_name)
                return ssock
            except:
                print('something broke')#ssock.unwrap()
        except:
            sock.close()


    def connectionPrompt(self,hostname,port,ca_name,ca_file):
        connection = self.connectToServer(hostname,port,ca_name,ca_file)
        while connection == None:
            again = input('Failed to connect. Try again? Y/N')
            if again.lower() == 'y':
                connection = self.connectToServer(hostname,port,'NADGE','certificate.pem')
            elif again.lower() == 'n':
                #quit = True
                break
            else:
                print("Invalid input.")
        return connection

    def loginOrCreateAccountPrompt(self,connection):
        quit = False
        option = input("Press l to log in, r to create an account, or q to quit.")
        while not quit:
            if option.lower() == 'l':
                quit = self.login(connection)
                break
            elif option.lower() == 'r':
                self.createAccount(connection)
                option = input("Press l to log in, r to create an account, or q to quit.")
            elif option.lower() == 'q':
                quit = True
            else:
                option = input("That is not a valid input. Please press l to log in, r to create an account, or q to quit.")
        return quit

    def printOnlineList(self,connection):
        connection.send((0).to_bytes(1,byteorder='big'))

        while(self.q.empty()):
            i = 1
            #print('q is empty. waiting...')
        users = self.q.get().decode()

        users = eval(users)
        print("The users online are :")
        for user in users:
            print(user[0])


    def messageReceiver(self,connection,q):
        done = False
        while not done:
            try:
                sizeofmessage = int.from_bytes(connection.recv(28),byteorder='big')
                #print(sizeofmessage)
                message = connection.recv(sizeofmessage)
                #print(message)
                if len(message.decode()) > 10 and (message.decode())[0:10] == "['message'":
                    lock.acquire()
                    print('\nreceived a message\n')
                    print('The message in byte form is ',message,'\n')
                    print('\nThe message in string form is ',message.decode(),'\n')
                    l = eval(message.decode())
                    #print(l,'\n')
                    #l = l.decode()
                    #print(l)
                    key = l[2]
                    mess = l[1]

                    print('\nThe encrypted message is ',mess,'\n')
                    key = bytes(key)
                    print('\nThe senders public key is ',key,'\n')
                    prkey = nacl.public.PrivateKey(self.privateKey)
                    pukey = nacl.public.PublicKey(key)
                    box = Box(prkey,pukey)
                    plaintext = box.decrypt(mess)
                    plaintext = plaintext.decode()
                    print('The plaintext is ',plaintext)
                    lock.release()
                else:
                    #print(message)
                    self.q.put(message)
            except UnicodeDecodeError:
                #print(message)
                self.q.put(message)
            except socket.timeout:
                timeouttt =1
            except KeyboardInterrupt:
                done = True
            except Exception as exc:
                done = True
                print(type(exc))
                print(exc.args)
                print('messageReceiver')
                #print('read time out. retrying.')
    def sendMessage(self,connection,receiver,message):
        try:
            connection.send((1).to_bytes(1,byteorder='big'))
            sizeofreceiver = sys.getsizeof(receiver)
            connection.send((sizeofreceiver).to_bytes(3,byteorder='big'))
            connection.send(receiver.encode())
            #sizeofresponse = int.from_bytes(connection.recv(28),byteorder='big')
            #if(self.q.empty()):
            #    print('q is empty. waiting...')
            while(self.q.empty()):
                waiting = 1
            response = self.q.get()
            #response = connection.recv(sizeofresponse)
            #print('response is')
            #print(response)
            try:
                if(response.decode() == '0'):
                    print('The receiver entered is not online')
                    return
                elif(response.decode() =='1'):
                    print('The receiver entered does not exist')
                    return
            except UnicodeDecodeError:
                pass
            finally:
                try:
                    #print('encrypting the message to send it')
                    format = self.username+':'
                    message = format+message
                    prkey = nacl.public.PrivateKey(self.privateKey)
                    pukey = nacl.public.PublicKey(response)
                    box = Box(prkey,pukey)
                    enc = box.encrypt(message.encode())
                    enc = bytes(enc)
                    sizeofenc = sys.getsizeof(enc)
                    connection.send((sizeofenc).to_bytes(3,byteorder='big'))
                    connection.send(enc)
                    #print('finisehd sending message')
                except Exception as exc:
                    print(type(exc))
                    print(exc.args)
                    print('innersendMessage')
        except Exception as exc:
            print(type(exc))
            print(exc.args)
            print('outersendMessage')
    def messagePrompt(self,connection):
        quit = False
        while lock.locked():
            wait = 1
        option = input("To print a list of users online press l, to send a user a message enter their username followed by the message(eg. USERNAME MESSAGE), to quit press q.")
        while not quit:
            try:
                if option == 'l':
                    self.printOnlineList(connection)
                    while lock.locked():
                        wait = 1
                    option = input("To print a list of users online press l, to start chatting with a user online enter their user name, to quit press q.")
                elif option == 'q':
                    quit = True
                else:
                    s = option.split(" ",1)
                    if len(s) != 2:
                        print('Invalid Input.')
                        while lock.locked():
                            wait = 1
                        option = input("To print a list of users online press l, to start chatting with a user online enter their user name, to quit press q.")
                        continue
                    receiver = s[0]
                    message = s[1]
                    self.sendMessage(connection,receiver,message)
                    while lock.locked():
                        wait = 1
                    option = input("To print a list of users online press l, to start chatting with a user online enter their user name, to quit press q.")
            except KeyboardInterrupt:
                quit = True
            except Exception as exc:
                quit = True
                print(type(exc))
                print(exc.args)
                print('messagePrompt')



    def __init__(self):
        quit = False
        hostname = '71.255.90.82'
        ip = get('https://api.ipify.org').text
        if ip ==  hostname:
            hostname = '192.168.1.157'

        port = 8443

        connection = self.connectionPrompt(hostname,port,'NADGE','certificate.pem')
        if connection is None:
            quit = True

        if not quit:
            quit = self.loginOrCreateAccountPrompt(connection)

        if not quit:
            mr = threading.Thread(target=self.messageReceiver,args=(connection,self.q))
            mr.daemon = True
            mr.start()
            self.messagePrompt(connection)
            mr.join

Client()
