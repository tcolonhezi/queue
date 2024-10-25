import socket
import threading
import queue
import sys
import time
import logging
import hashlib
from datetime import datetime, timedelta

# Configurando o logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Fila de clientes aguardando permissão
client_queue = queue.Queue()
# Flag para controlar a execução do servidor
server_running = True

# Lock e Condition para sincronização de clientes
client_condition = threading.Condition()

def verify_md5(received_hash, file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest() == received_hash

def receive_with_length(conn):
    length_bytes = conn.recv(4)
    if not length_bytes:
        logging.error("Conexão fechada antes de receber o comprimento.")
        return None

    length = int.from_bytes(length_bytes, 'big')
    data = b''
    
    while len(data) < length:
        packet = conn.recv(length - len(data))
        if not packet:
            logging.error("Conexão fechada antes de receber todos os dados.")
            return None
        data += packet

    logging.info(f"Dados recebidos: {data.decode()}")
    return data.decode()

def handle_client(conn, addr):
    global server_running

    if not server_running:
        conn.close()
        return

    logging.info(f"Cliente {addr} conectado. Adicionando à fila...")

    with client_condition:
        # Adiciona o cliente à fila e aguarda sua vez
        client_queue.put((conn, addr))
        while server_running and client_queue.queue[0][1] != addr:
            client_condition.wait()  # Aguarda notificação para continuar

        if server_running:
            conn.send(b'PERMITIDO')
            logging.info(f"Permissão concedida para o cliente {addr} iniciar a transferência")

    try:
        confirmation = conn.recv(1024)
        if confirmation == b'CONCLUIDO' and server_running:
            logging.info(f"Cliente {addr} confirmou a conclusão da transferência")
            # Recebe o hash MD5 do cliente
            received_md5 = receive_with_length(conn)
            logging.info(received_md5)
            file_path = receive_with_length(conn)  # Caminho onde o arquivo foi transferido (modifique conforme necessário)
            destination_path_cleaned = file_path.split(":")[-1]  # Pega a parte após ':'
            logging.info(destination_path_cleaned)
            if verify_md5(received_md5, destination_path_cleaned):
                logging.info(f"MD5 verificado com sucesso para o cliente {addr}.")
            else:
                logging.error(f"Verificação MD5 falhou para o cliente {addr}.")
        else:
            logging.warning(f"Cliente {addr} não confirmou a conclusão ou o servidor foi interrompido")
    except socket.error:
        logging.error(f"Erro de comunicação com o cliente {addr}")
    finally:
        with client_condition:
            client_queue.get()  # Remove o cliente da fila
            client_condition.notify_all()  # Notifica os próximos clientes
        conn.close()

def start_server():
    global server_running
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 5000))
    server.listen()
    logging.info("Servidor aguardando conexões...")

    while server_running:
        try:
            server.settimeout(1.0)
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()
        except socket.timeout:
            continue
        except Exception as e:
            logging.error(f"Erro ao aceitar conexão: {e}")

    server.close()
    logging.info("Servidor encerrado.")

    while server_running:
        try:
            server.settimeout(1.0)
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()
        except socket.timeout:
            continue
        except Exception as e:
            logging.error(f"Erro ao aceitar conexão: {e}")

    server.close()
    logging.info("Servidor encerrado.")

if __name__ == "__main__":
    try:
        server_thread = threading.Thread(target=start_server)
        server_thread.start()
        
        server_thread.join()
    except KeyboardInterrupt:
        server_running = False
        logging.info("Servidor encerrado por solicitação do usuário.")
    
    sys.exit("Aplicação encerrada.")
