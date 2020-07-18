#!/usr/bin/env python3
'''

Script Python 3 para el Control 1 de Redes,
Primer semestre 2020,
Creado por José Espina (joseguillermoespina@gmail.com)

**Ver el informe (control1.pdf) para hacerlo funcionar**
'''

# Usado para crear el server TCP
import socketserver
# Usados para el reenío de mensajes
import threading
import socket

# Constantes
BUFFER_ENTRADA = 256

def reenvio(host_destino, puerto_destino, mensaje) :
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host_destino, puerto_destino))
        s.send(mensaje)
        s.close()

class Control_dos_handler(socketserver.BaseRequestHandler):

    def handle(self):
        # Se recibe el mensaje
        host, puerto = self.server.server_address
        data = self.request.recv(BUFFER_ENTRADA)
        str_data = data.decode('utf-8').strip()
        array_data = str_data.split(",")
        
        # Se desempaca el destinatario (IP y puerto), y el mensaje
        host_destino = array_data[0]
        puerto_destino = array_data[1]
        mensaje = array_data[2]

        # Se revisa el mensaje que era para R1. Podría modificarse para
        # alguna actividad malciosa, o dejarlo intacto para pasar
        # desapercibido
        print('***sOy uN aTaCaNtE***. Mensaje:"{}"'.format(mensaje))

        hilo = threading.Thread(target=reenvio, args=(host_destino, int(puerto_destino), data,))
        hilo.start()
        self.request.send(str.encode("Reenviando...\n"))
        hilo.join()
                
if __name__ == '__main__':
    address = ('localhost', 10000)
    # Se configura el seridor y se pasa clase handler que
    # hereda de socketserver.BaseRequestHandler
    servidor = socketserver.TCPServer(address, Control_dos_handler)
    ip, port = servidor.server_address
    print('Servidor hackeando en {}:{}'.format(ip, port))
    # El servidor "servirá" para siempre, hasta que se le detenga
    # con un ctrl + c
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        servidor.shutdown()
        servidor.socket.close()