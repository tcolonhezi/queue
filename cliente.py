import socket
import subprocess
import time
import hashlib
import argparse
import logging
import os
import sys

# Configurando o logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def calculate_md5(filepath):
    hash_md5 = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def send_with_length(sock, data):
    data_bytes = data.encode()
    length = len(data_bytes)
    sock.sendall(length.to_bytes(4, 'big'))  # Envia o tamanho como um inteiro de 4 bytes
    sock.sendall(data_bytes)  # Envia os dados

def handle_exception(str_erro, e):
    logging.error("{}: {}".format(str_erro, e))
    sys.exit(1)  # Finaliza com erro

def request_transfer(server_ip, file_path, destination_path):
    try:
        with socket.create_connection((server_ip, 5000)) as sock:
            logging.info("Conectado ao servidor. Aguardando permissao...")
            
            while True:
                response = sock.recv(1024)
                if response == b'PERMITIDO':
                    logging.info("Permissao concedida. Iniciando rsync...")
                    break
                time.sleep(1)

            result = subprocess.run(["rsync", "-avzhp", "-e", "ssh -p 2223", file_path, destination_path])
            
            if result.returncode == 0:
                file_name = os.path.basename(file_path)
                full_destination_path = os.path.join(destination_path, file_name)
                sock.send(b'CONCLUIDO')
                md5_hash = calculate_md5(file_path)
                send_with_length(sock, md5_hash)
                send_with_length(sock, full_destination_path)
                logging.info("Transferencia concluida com sucesso. Confirmando ao servidor.")
            else:
                logging.error("Falha na transferncia. Nenhuma confirmacao enviada ao servidor.")

    except socket.error as e:
        handle_exception("Erro de conexao:", e)
    except FileNotFoundError:
        handle_exception("O arquivo nao foi encontrado:", file_path)
    except Exception as e:
        handle_exception("Ocorreu um erro:", e)

def main():
    try:
        parser = argparse.ArgumentParser(description='Transferir arquivos usando rsync com autorizao de servidor.')
        parser.add_argument('--server_ip', type=str, default='127.0.0.1', help='IP do servidor')
        parser.add_argument('--file_path', type=str, required=True, help='Caminho do arquivo a ser transferido')
        parser.add_argument('--destination_path', type=str, required=True, help='Caminho de destino no servidor')

        args = parser.parse_args()

        request_transfer(args.server_ip, args.file_path, args.destination_path)

        sys.exit(0)
    except Exception as e:
        handle_exception("Ocorreu um erro de inicio:",e)

if __name__ == "__main__":
    main()
