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
# Para permitir configurar el puerto desde la línea de comandos
import argparse
# Para calcular si la dirección IP de destino se encuentra dentro
# del rango declarado en cada entrada de la tabla de rutas
import ipaddress

# Constantes
BUFFER_ENTRADA = 256
INDICE_INDICES_RUTAS = 0
INDICE_CONTADOR_RUTA = 1
INDICE_CIDR = 0
INDICE_PUERTO_INICIAL = 1
INDICE_PUERTO_FINAL = 2
INDICE_HOST_DESTINO = 3
INDICE_HOST_PUERTO = 4

# Variables globales
# tabla_de_rutas almacena vectores de rutas con el formato indicado en la actividad del EOL
# de la semana 11-12, i.e: Red (CIDR) Puerto_Inicial Puerto_final IP_Para_llegar Puerto_para_llegar
tabla_de_rutas = []
# diccionario_de_rutas se va llenando a medida que el router se va utilizando. Por cada nuevo destino
# se crea un vector, donde el índice del diccionario es el host destinatario, cada elemento tendrá 
# los índices de las rutas por donde se puede llegar a ese destinatario (posicion 0 del vector), y 
# el índice de la última ruta usada (posicion 1). Esto permitirá la implementación de Round-Robin 
# para destinatarios con múltiples posibles rutas de llegada
diccionario_de_rutas = dict()

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

        # Se revisa si el mensaje es para el router actual
        if host == host_destino and str(puerto) == puerto_destino :
            print('Log de {}:{}, destino {}:{}. Mensaje:"{}"'.format(host,puerto,host_destino,puerto_destino,mensaje))
            self.request.send(str.encode("Recibido\n"))
        # Si el mensaje no es para el router actual: se aplica Round-Robin (RR) para si ya se envió
        # antes un frame a ese destinatario, si no, se crea una estructura de datos para poder realizar
        # RR en el futuro y se re-envía la comunicación a la primera ruta
        else :
            # Puerto y host seleccionados por algoritmo Round-Robin
            host_RR = None
            puerto_RR = None
            # Se revisa si el destino ya se usó antes. Si se usó, se aplica Round-Robin
            if host_destino in diccionario_de_rutas :
                indice = diccionario_de_rutas[host_destino][INDICE_CONTADOR_RUTA]
                indice += 1
                if indice >= len(diccionario_de_rutas[host_destino][INDICE_INDICES_RUTAS]) :
                     indice = 0
                host_RR = tabla_de_rutas[diccionario_de_rutas[host_destino][INDICE_INDICES_RUTAS][indice]][INDICE_HOST_DESTINO]
                puerto_RR = tabla_de_rutas[diccionario_de_rutas[host_destino][INDICE_INDICES_RUTAS][indice]][INDICE_HOST_PUERTO]
            # Si es primera vez que se tiene que re-enviar frames a ese host, se crea su
            # diccionario de posibles rutas y se re-envía la comunicación
            else :
                indice = 0
                vector_indice_rutas = []
                for entrada in tabla_de_rutas :
                    # Si el host y puerto están dentro de los rangos de la entrada actual de la tabla de
                    # rutas, se añade su indice al vector de indices de rutas para ese host y puerto
                    if ipaddress.IPv4Address(host_destino) in ipaddress.IPv4Network(entrada[INDICE_CIDR]) \
                        and (int(entrada[INDICE_PUERTO_INICIAL]) <= int(puerto_destino) <= int(entrada[INDICE_PUERTO_FINAL])):
                        vector_indice_rutas.append(indice)
                    indice += 1
                # Se valida de que, por lo menos, exista una ruta válida para el destintario solicitado
                if len(vector_indice_rutas) == 0 :
                    self.request.send(str.encode("No existe una ruta para el destino solicitado\n"))
                    return
                else :
                    # Se crea registro con índice en 0
                    diccionario_de_rutas[host_destino] = [vector_indice_rutas,0]
                    host_RR = tabla_de_rutas[diccionario_de_rutas[host_destino][INDICE_INDICES_RUTAS][0]][INDICE_HOST_DESTINO]
                    puerto_RR = tabla_de_rutas[diccionario_de_rutas[host_destino][INDICE_INDICES_RUTAS][0]][INDICE_HOST_PUERTO]

            # Se reenvía la comunicación al próximo router AS
            hilo = threading.Thread(target=reenvio, args=(host_RR, int(puerto_RR), data,))
            hilo.start()
            print(tabla_de_rutas)
            print("-------------")
            print(diccionario_de_rutas)
            self.request.send(str.encode("Reenviando de {} a {}\n".format(puerto, puerto_RR)))
            hilo.join()
                
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("puerto", help="Puerto de Valparaíso, con cerros y miradores (bis)", type=int)
    parser.add_argument("rutas", help="Archivo tablas de ruta para este router", type=str)
    args = parser.parse_args()
    puerto = args.puerto
    ruta_rutas = args.rutas
    # Se cargan las rutas
    with open(ruta_rutas) as file:
        for linea in file :
            arr_ruta = linea.strip().split(" ")

            # Simulando a los routers AS, nos quedamos siempre con el prefijo más específico
            # para una entrada repetida (misma ip base y rangos de puertos, pero máscara diferente)
            # Esta será la vulnerabilidad que permitirá hacer un ataque Man-In-The-Middle
            # usando la regla de CIDR con una máscara de subred más específica (ver detalles en el pdf)
            ip = arr_ruta[0].split("/")[0]
            mascara_subred = int(arr_ruta[0].split("/")[1])
            puerto_inicio = arr_ruta[1]
            puerto_fin = arr_ruta[2]
            for entrada in tabla_de_rutas :
                entrada_actual_ip = entrada[0].split("/")[0]
                entrada_actual_mascara_subred = int(entrada[0].split("/")[1])
                entrada_actual_puerto_inicio = entrada[1]
                entrada_actual_puerto_fin = entrada[2]
                if ip == entrada_actual_ip and \
                    mascara_subred > entrada_actual_mascara_subred and \
                    puerto_inicio == entrada_actual_puerto_inicio and \
                    puerto_fin == entrada_actual_puerto_fin :
                    tabla_de_rutas.remove(entrada)
            # Fin sección

            tabla_de_rutas.append(linea.strip().split(" "))

    address = ('localhost', puerto)
    # Se configura el seridor y se pasa clase handler que
    # hereda de socketserver.BaseRequestHandler
    servidor = socketserver.TCPServer(address, Control_dos_handler)
    ip, port = servidor.server_address
    print('Servidor escuchando en {}:{}'.format(ip, port))
    # El servidor "servirá" para siempre, hasta que se le detenga
    # con un ctrl + c
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        servidor.shutdown()
        servidor.socket.close()