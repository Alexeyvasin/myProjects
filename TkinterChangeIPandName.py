import time
import re
import socket
import telnetlib
import tkinter as tk
from threading import Lock
from threading import Thread
from time import sleep
from tkinter import ttk

NEW_MASK = "255.0.0.0"
GATEWAY = "192.168.1.1"
ips_of_switches = ("10.100.2.2", "10.100.2.3")
ips_def = []  # [["def_ip", ip, mac], ...]
names_def = []
ips_for_change = []  # [[self.IP(sw), port, target_mac],...]
auth = "admin:admin"
changing_ip = []
changed_scsf = False


def start_thread_for_change_ip():
    tr_change_ip = Thread(target=change_ip, daemon=True)
    if button_change_ip["text"] == "Change IP":
        tr_change_ip.start()
        button_change_ip["bg"] = "red"
        button_change_ip["text"] = "Stop"
    else:
        button_change_ip["bg"] = "green"
        button_change_ip["text"] = "Change IP"


def change_ip():
    global changing_ip
    global changed_scsf
    global ips_def
    while button_change_ip["text"] == "Stop":
        if not ips_for_change:
            sleep(1)
            continue
        # lock.acquire()
        changing_ip = ips_for_change.pop()
        while True:
            request_for_change_ip()
            sleep(0.5)
            if changed_scsf:
                str_ch_ip = f"192.{changing_ip[0].split('.')[2]}.{changing_ip[0].split('.')[3]}.{changing_ip[1]}"
                changed_scsf = False
                for n, i in enumerate(ips_def):
                    if changing_ip and changing_ip[2] == i[2]:
                        ips_def[n][0] = "non_def_ip"
                        ips_def[n][1] = str_ch_ip
                        changing_ip = []

                break
            break
        sleep(0.1)


def request_for_change_ip():
    global auth
    ip = changing_ip[0]
    port = changing_ip[1]
    mac = changing_ip[2]
    ip_list = ip.split('.')
    new_ip = '192.' + ip_list[2] + '.' + ip_list[3] + '.' + str(port)
    prls = ['ðÞ¼ú‰Ãh\x03', 152, auth.split(':')[0], 64 - (len(auth.split(':')[0])),
            auth.split(':')[1],
            20 - (len(auth.split(':')[1])), mac, 7, '\x01', 7, new_ip, 16 - len(new_ip),
            NEW_MASK, 148 - len(NEW_MASK), GATEWAY, 440 - len(GATEWAY)]

    prl = ''
    for i, p in enumerate(prls):
        if i % 2 == 0:
            prl += p

        else:
            for n in range(p):
                prl += chr(0)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)  # UDP
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    for _ in range(3):
        payload_hex_string = prl.encode('cp1252').hex()
        payload = bytes.fromhex(payload_hex_string)
        sock.sendto(payload, ("255.255.255.255", 6011))
    sock.close()


def creator_sw():
    global ips_def
    global auth
    while True:
        for ip in ips_def:
            if "192.168.1.188" == ip[1]:
                if ip[2] in [i[2] for i in ips_for_change]:
                    continue
                for sw in ips_of_switches:
                    _ = Switch(sw, auth, ip[2])
            else:
                sleep(1)
        sleep(0.5)
    # sleep(1)


class Switch(Thread):
    def __init__(self, ip, auth_tion, target_mac):
        super().__init__()
        self.IP = ip
        self.AUTH_SW = auth_tion
        self.target_mac = target_mac
        self.run()

    global ips_for_change

    def run(self):
        for i in range(1):
            try:
                # self.search_mac(self.target_mac)
                self.search_mac_telnet(self.target_mac)
            except ConnectionError:
                pass

    def search_mac_telnet(self, target_mac):
        tn = telnetlib.Telnet(self.IP)
        tn.read_until(b"UserName:")
        user = self.AUTH_SW.strip().split(':')[0]
        password = self.AUTH_SW.strip().split(':')[1]
        tn.write(user.encode() + b"\n")
        tn.read_until(b"PassWord:")
        tn.write(password.encode() + b"\n")
        for p in range(1, 25):
            print("Здесь", target_mac)
            tn.write(('show fdb port ' + str(p)).encode() + b'\n')
            res = tn.read_until('Priori'.encode(), timeout=0.1)
            rsl_list = res.decode('ascii').split()
            for i, s in enumerate(rsl_list):
                r = re.search(r'F0-23-[0-9A-F][0-9A-F]-[0-9A-F][0-9A-F]-[0-9A-F][0-9A-F]-[0-9A-F][0-9A-F]', str(s))
                if r:
                    res2 = r
                    spl_mac = str(res2.group()).lower().split('-')
                    mac = spl_mac[0] + ':' + spl_mac[1] + ':' + spl_mac[2] + ':' + spl_mac[3] + ':' \
                          + spl_mac[4] + ':' + spl_mac[5]
                    port = rsl_list[i + 1]

                    if mac == target_mac:
                        # lock.acquire()
                        ips_for_change.append((self.IP, port, target_mac))
                        # lock.release()
                else:
                    continue
        tn.close()


def wiretapping():
    global ips_def
    global changing_ip
    global changed_scsf
    while True:
        while True:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            # чтобы на одной машине можно было слушать тотже порт
            sock.setsockopt(socket.SOL_SOCKET, 1, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            try:
                sock.bind(('', 6010))
                data, addr = sock.recvfrom(6000)
            except ConnectionError:
                pass
            if changing_ip:
                str_ch_ip = f"192.{changing_ip[0].split('.')[2]}.{changing_ip[0].split('.')[3]}.{changing_ip[1]}"
                if str_ch_ip in addr:
                    changed_scsf = True
            if '192.168.1.188' in addr:
                break
        s = ''
        for i in data:
            s += chr(i)
        mac = re.findall('.*TR-.+_(f0:23:..:..:..:..).+', s)
        lock.acquire()
        is_mac = 0
        for i in ips_def:
            if mac and i and i[2] == mac[0]:
                is_mac = 1
        if mac and is_mac == 0:
            ips_def.append(["def_ip", "192.168.1.188", mac[0]])
        lock.release()


def sender():
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)  # UDP
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        #  sock.set-timeout(2)
        for i in range(3):
            payload_hex_string = "f0debcfa88c30800"
            payload = bytes.fromhex(payload_hex_string)
            sock.sendto(payload, ("255.255.255.255", 6011))
        sock.close()
        sleep(1)


root = tk.Tk()
root.title("Change IP, Name")
# root.geometry("500x600")

frame_main = tk.Frame(root)
frame_main.pack()

tk.Label(
    frame_main,
    text="Change IP:"
).grid(row=0, column=0, )

tk.Label(
    frame_main,
    text="Change Name:"
).grid(row=0, column=1)

frame_IP = tk.Frame(
    frame_main,
    width=300,
    height=300,
    bg="green",

)
# frame_IP.pack_propagate(False)
frame_IP.grid(row=1, column=0, padx=20)
# list_var = tk.StringVar(value=ip, )
# list_box_IP = tk.Listbox(frame_IP)
# list_box_IP.pack(side=tk.LEFT, fill=tk.BOTH, expand=1)
# list_box_IP.insert(0, ["Hello", "By"])
table_IP = ttk.Treeview(frame_IP, columns=("ip", "mac", "name"), show="headings")
table_IP.heading("ip", text="IP")
table_IP.heading("mac", text="MAC")
table_IP.heading("name", text="NAME")
table_IP.pack(side=tk.LEFT, fill=tk.BOTH)

# table_IP.yview_scroll(number=1, what="units")
scroll_IP = tk.Scrollbar(frame_IP, orient=tk.VERTICAL, command=table_IP.yview)
scroll_IP.pack(side=tk.RIGHT, fill=tk.Y)

table_IP.configure(yscrollcommand=scroll_IP.set)

# scrol_IP = tk.Scrollbar(
#     frame_IP,
#     orient="vertical"
# )
# scrol_IP.pack(side="right", fill="y")

frame_Name = tk.Frame(
    frame_main,
    width=300,
    height=300,
    bg="red"
)
frame_Name.grid(row=1, column=1, padx=20)

frame_login = tk.Frame(
    frame_main,
    bg="brown"
)
frame_login.grid(row=3, column=0)

frame_pass = tk.Frame(
    frame_main,
    bg="brown"
)
frame_pass.grid(row=4, column=0)

label_login = tk.Label(
    frame_login,
    text="login: ",
    width=10
)
label_login.pack(side=tk.LEFT)

entry_log = tk.Entry(
    frame_login,
)
entry_log.pack(side=tk.RIGHT)

label_pass = tk.Label(
    frame_pass,
    text="password: ",
    width=10
)
label_pass.pack(side=tk.LEFT)

entry_pass = tk.Entry(
    frame_pass,
    show="*"
)
entry_pass.pack(side=tk.RIGHT)

button_change_ip = tk.Button(
    frame_main,
    text="Change IP",
    command=start_thread_for_change_ip,
    bg="green"
)
button_change_ip.grid(row=5, column=0)


def filler_of_table():
    while True:
        global ips_def
        global table_IP
        table_IP.delete(*table_IP.get_children())
        table_IP.tag_configure("def_ip", background="red")
        table_IP.tag_configure("non_def_ip", background="green")
        for row in ips_def:
            table_IP.insert(parent="", index=tk.END, values=(row[1], row[2]), tag=row[0])
        sleep(0.5)


lock = Lock()

tr1 = Thread(target=filler_of_table, daemon=True)
tr1.start()

tr_wiretapping = Thread(target=wiretapping, daemon=True)
tr_wiretapping.start()

tr_senderUDP = Thread(target=sender, daemon=True)
tr_senderUDP.start()
#
tr_create_Sw = Thread(target=creator_sw, daemon=True)
tr_create_Sw.start()

# tr_change_ip = Thread(target=change_ip, daemon=True)
# tr_change_ip.start()


# label_IP_ip = tk.Label(
#     frame_IP,
#     text = ip
# )
# label_IP_ip.grid()


root.mainloop()
