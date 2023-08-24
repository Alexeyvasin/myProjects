import re
import socket
from threading import Thread, Lock
from time import sleep
import requests

ips = set()
lock_thread = Lock()


class WiretappingUdp(Thread):
    def __init__(self):
        super().__init__(daemon=True)
        global ev_finded_ip
        global ips

    def run(self):
        all_cams = set()
        while True:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
                lock_thread.acquire()
                # чтобы на одной машине можно было слушать тотже порт
                sock.setsockopt(socket.SOL_SOCKET, 1, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.bind(('', 6010))
                data, addr = sock.recvfrom(1024)
                data_ = (data.decode('cp1252'))
                # data = str(data)
                nonamed = re.search(r'(TR-.*)', str(data_)[150:162])
                if nonamed and addr[0] not in ips:
                    ips.add(addr[0])
                lock_thread.release()


def senderUDP():
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:  # UDP
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            payload_hex_string = "f0debcfa88c30800"
            payload = bytes.fromhex(payload_hex_string)
            sock.sendto(payload, ("255.255.255.255", 6011))
        sleep(0.5)


def change_name():
    global ips
    ip = ips.pop()
    with requests.get(f'http://admin:admin@{ip}/action/get?subject=devpara') as req:
        # check status code for response received
        # success code - 200
        # print(r)
        if '200' in str(req):
            # print content of request
            resp = req.content.decode()
            old_name = re.search('<name>(TR-.+)</name>', resp).groups()[0]
            new_xml = resp.replace(old_name, ip[4:])

    url = f"http://admin:admin@{ip}/action/set"
    headers = {"Accept": "*/*", "Content-Type": "text/xml;charset=utf-8", "Content-Length": "203"}
    data = new_xml
    params = {"subject": "devpara"}
    res = requests.post(url=url, headers=headers, data=data, params=params)
    if res.status_code == 200:
        print(ip)


def main():
    # ev_finded_ip = Event()
    # создаем и запускаем поток, который  прослушивает UDP
    wiretapping = WiretappingUdp()
    wiretapping.start()
    # создаем и запускаем поток, который отправляет сигнал
    sender_udp = Thread(target=senderUDP, daemon=True)
    sender_udp.start()

    # запускаем бесконечный цикл по смене имени камеры, если в наборе есть элементы
    while True:
        lock_thread.acquire()
        if ips:
            change_name()
        lock_thread.release()
        sleep(0.5)


if __name__ == '__main__':
    main()
