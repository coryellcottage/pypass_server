# Data structure
# data /
#   client_addr /
#     Client user /
#       .passwords.json
#   data.json
# .passwords data structure

# service: {
#     username: {
#       "password": encrypted password
#       "key": Key used for Fernet encryption
#       }
#   }

import os
import time
import json
import pprint
import socket
import logging
import asyncio
import schedule
import datetime
import threading
import netifaces
import traceback
import json_repair
from pathlib import Path
import cryptography.fernet
from cryptography.fernet import Fernet

client = None
schedule_thread = None
client_connected = False
connected_clients: list = []
stop_event = threading.Event()
logger = logging.getLogger(__name__)

def stop_server():
    global client_connected, connected_clients
    stop_event.set()
    schedule_thread.join()

    if client_connected:
        logger.info("Client(s) still connected, closing connection")
        print("Client(s) connected, closing connection")

        for client in connected_clients:
            client.close()

        connected_clients = []
        client_connected = False

def start_server(interactive: bool = False, server_interface=None, server_port: int or None = None):
    global stop_event, client_connected, logger, schedule_thread

    if not os.path.exists("logs"):
        os.mkdir("logs")

    logging.basicConfig(
        level=logging.DEBUG,
        filename=f"logs/{datetime.date.today().strftime('%m-%d-%Y')}.log",
        format="%(asctime)s: %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M"
    )

    logger.debug(msg=f"INFORMATION: server_interface is set to {server_interface}, and is of type {type(server_interface)}")
    logger.debug(msg=f"INFORMATION: server_port is set to {server_port}, and is of type {type(server_port)}")

    schedule.every().monday.at("00:00")
    schedule_thread = threading.Thread(target=start_scheduled_tasks)
    schedule_thread.start()
    logger.info("Scheduler started")

    if interactive and not Path("data/data.json").exists():
        server_interface = netifaces.interfaces()[int(input(f"Enter the index of the interface you want to use. Eg, to use {netifaces.interfaces()[0]} enter 1\n{netifaces.interfaces()}\n")) - 1]
        server_port = input("What port do you want to user? Press enter for the default \n")

        if server_port == "":
            server_port = 9000

        else:
            server_port = int(server_port)

    elif interactive == False and (server_interface is None or server_port is None):

        if schedule_thread is not None:
            stop_server()
            return {
                "server_running": False,
                "server_pid": os.getpid(),
                "server_thread": schedule_thread,
                "message": "Failed to start server",
                "reason": "Server interface or server port is required, but not specified."
            }

        else:
            stop_server()
            return {
                "server_running": False,
                "server_pid": os.getpid(),
                "message": "Failed to start server",
                "reason": "Server interface or server port is required, but not specified."
            }

    if interactive:
        server_event_loop(interface=server_interface, port=server_port)

    else:
        threading.Thread(
            target=server_event_loop,
            kwargs={
                "interface": server_interface,
                "port": server_port
            }
        ).start()

    if schedule_thread is not None:
        return {
            "server_running": True,
            "server_pid": os.getpid(),
            "server_thread": schedule_thread,
            "message": "Successfully started server"
        }

    else:
        return {
            "server_running": True,
            "server_pid": os.getpid(),
            "message": "Successfully started server"
        }

def server_event_loop(interface, port: int):
    global client_connected, logger, client

    try:
        server_data = get_connection_data(interface, port)

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(server_data)
        server.settimeout(10.0)
        server.listen()

        logger.info("Server started and listening")

        print(f"Listening on address {server_data[0]} port {server_data[1]}...")

        while not stop_event.is_set():
            try:
                client, client_addr = server.accept()
                connected_clients.append(client)
                threading.Thread(target=Client, kwargs={"user_client": client, "client_address": client_addr}).start()

            except TimeoutError:
                continue

    except Exception as e:
        print(traceback.format_exc())

        logger.error(f"Error occurred: {e}. Shutting down")
        print("Exception, shutting down")

        stop_server()

    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received, shutting down")
        print("Keyboard interrupt, shutting down")

        stop_server()

def get_connection_data(interface, port: int) -> tuple:
    if os.path.exists("data/data.json"):
        connection_data = json_repair.from_file("data/data.json")
        connection_data[1] = int(connection_data[1])
        connection_data = tuple(connection_data)

    else:
        connection_data = (
            netifaces.ifaddresses(interface)[netifaces.AF_INET][0]["addr"],
            port
        )

        if not os.path.exists("data"):
            os.mkdir("data")

        with open("data/data.json", mode="w") as connection_file:
            json.dump(connection_data, connection_file, indent=4)

    return connection_data

def refresh_keys():
    logger.info("Running refresh_keys")

    data_folder = os.path.join(os.getcwd(), "data")

    for client_folder in os.listdir(data_folder):
        for username_folder in os.listdir(os.path.join(data_folder, client_folder)):
            if os.path.isdir(os.path.join(data_folder, client_folder)):
                user_folder_path = os.path.join(data_folder, client_folder, username_folder)
                saved_data = json_repair.from_file(user_folder_path + ".passwords.json")

                if isinstance(saved_data, dict) and saved_data != {}:
                    for saved_service in saved_data.keys():
                        for saved_username in saved_data[saved_service].keys():
                            last_refreshed = saved_data[saved_service][saved_username]["last-refresh"]
                            last_refreshed_date = datetime.date(
                                month=int(last_refreshed.split("-")[0]),
                                day=int(last_refreshed.split("-")[1]),
                                year=int(last_refreshed.split("-")[2])
                            )

                            today = datetime.date.today()
                            if last_refreshed_date.month - today.month == 0 and last_refreshed_date.day - today.day == 0 and last_refreshed_date.year - today.year == 0\
                                and last_refreshed_date.month != today.month and last_refreshed_date.day != today.day and last_refreshed_date.year != today.year:
                                print("Inside second if statement")
                                old_key = saved_data[saved_service][saved_username]["key"].encode()
                                old_cipher = Fernet(old_key)

                                new_key = Fernet.generate_key()
                                new_cipher = Fernet(new_key)
                                saved_data[saved_service][saved_username]["key"] = new_key.decode()
                                saved_data[saved_service][saved_username]["password"] = new_cipher.encrypt(
                                    old_cipher.decrypt(
                                        saved_data[saved_service][saved_username]["password"].encode()
                                    )
                                ).decode()

                    with open(f"data/{user_folder_path}/.passwords.json", mode="w") as passwords_file:
                        json.dump(saved_data, passwords_file, indent=4)

def start_scheduled_tasks():
    while not stop_event.is_set():
        schedule.run_pending()
        time.sleep(5)

class Client:
    def __init__(self, user_client: socket.socket, client_address: float):
        global client_connected
        client_connected = True

        logger.info("New client connected")

        print("Received new connection")
        self.client_user = client.recv(1024)
        print("Received client user")

        client_key = client.recv(1024)
        print("Received client key")
        print(client_key.decode())

        self.client_fernet = Fernet(client_key)

        self.client_addr = client_address[0]
        self.client = user_client


        logger.info("Collected client connection and address")

        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
        self.client.sendall(self.client_fernet.encrypt(self.key))
        print("Sent server key")

        logger.info("Set up server cipher")

        threading.Thread(target=asyncio.run, args=(self.receive_messages(),)).start()

        logger.info("Started message receiver")

    def encrypt_data(self, data: str) -> list[str] | bytes:
        # Check if data can be converted to dict
        try:
            data: dict = json.loads(data)
            logger.info("Successfully loaded data")

        except json.decoder.JSONDecodeError:
            # Assume can't be converted to dict, encrypt as message
            logger.warning("Couldn't load data, assuming data is a string, not a dictionary")

            encrypted_data = self.client_fernet.encrypt(self.cipher.encrypt(data.encode()))

            logger.info("Successfully encrypted data")
            return encrypted_data

        # Data can be converted into dict, converting as dict
        logger.info("Breaking down data and encrypting it")

        encrypted_data = []

        for broken_down_data in self.break_down_data(data):
            encrypted_data.append(
                self.client_fernet.encrypt(
                    self.cipher.encrypt(broken_down_data)
                )
            )

        logger.info("Successfully broke down and encrypted data")

        return encrypted_data

    def decrypt_data(self, data: bytes) -> dict | bytes:
        # Check if data can be converted to dict
        try:
            logger.info("Attempting to decrypt data and load into dictionary")
            decrypted_data_string = self.client_fernet.decrypt(self.cipher.decrypt(data))
            decrypted_data_dictionary: dict = json.loads(decrypted_data_string)

            logger.info("Successfully decrypted and loaded data to dictionary")
            return decrypted_data_dictionary

        except json.decoder.JSONDecodeError:
            # Assume data can't be converted to dict, decrypt message
            logger.warning("Data couldn't be loaded into dictionary. Assuming its a string")

            decrypted_data = self.client_fernet.decrypt(self.cipher.decrypt(data.decode()))

            logger.info("Successfully decrypted data")
            return decrypted_data

    async def receive_all(self) -> str:
        print("Receive_all called")

        encrypted_received_data: bytes = b""

        while True:
            print("Receiving new data")
            new_received_data: bytes = self.client.recv(1024)

            print(
                f"\n ------------------------------ \n    Total received data: {encrypted_received_data} \n ------------------------------ ")
            print(
                f"\n ------------------------------ \n    New data received: {new_received_data} \n ------------------------------ ")

            try:
                print("Trying to decrypt total received data")

                encrypted_received_data += new_received_data
                decrypted_received_data: str = self.client_fernet.decrypt(self.cipher.decrypt(encrypted_received_data)).decode()

            except cryptography.fernet.InvalidToken:
                print("Couldn't decrypt received data")

                print(type(new_received_data))
                print(new_received_data.decode() == "DONE" or new_received_data == b"DONE")

                if new_received_data.decode() == "":
                    break


                elif new_received_data.decode() == "DONE" or new_received_data == b"DONE":
                    print("DONE message received")
                    break

            else:
                print("Data was successfully decrypted, breaking out of while loop")
                # encrypted_received_data = b""
                break

        try:
            return decrypted_received_data

        except UnboundLocalError:
            return ""

    async def receive_messages(self):
        while not stop_event.is_set():
            decrypted_data: str = await self.receive_all()

            print("Received new message")

            logger.info("Received new message")

            if decrypted_data == "":
                logger.warning("Received empty message, returning")
                return

            # logger.info("Decrypting data")
            # print("Decrypting data")
            saved_data: dict = self.load_device_data()

            try:
                decrypted_data: dict = json.loads(decrypted_data)

            except json.decoder.JSONDecodeError:
                print(traceback.format_exc())

                logger.info("Received data was not a dictionary. Checking for data request")

                print("Decrypted data wasn't a dictionary")
                decrypted_user_data = {}

                print(decrypted_data)

                if decrypted_data == "DOWNLOAD_DATA":
                    logger.info("Client requested user data. Decrypting user data")
                    print(f"Saved data is: {saved_data}")
                    print(f"Saved data is of type: {type(saved_data)}")

                    if saved_data == {} or saved_data == "{}":
                        await asyncio.to_thread(self.client.sendall, self.cipher.encrypt(b"Failed to download passwords. No data saved"))

                    for service in saved_data.keys():
                        for username in saved_data[service].keys():
                            saved_key = self.client_fernet.decrypt(saved_data[service][username]["key"])
                            cipher = Fernet(saved_key)

                            if service not in decrypted_user_data.keys():
                                decrypted_user_data[service] = {
                                    username: {
                                        "password": cipher.decrypt(
                                            saved_data[service][username]["password"].encode()
                                        ).decode(),
                                        "key": saved_key.decode()
                                    }
                                }

                            else:
                                decrypted_user_data[service][username] = {
                                    "password": cipher.decrypt(
                                        saved_data[service][username]["password"].encode()
                                    ).decode(),
                                    "key": saved_key.decode()
                                }

                    logger.info("Successfully decrypted user data. Sending to client")

                    decrypted_user_data_bytes: bytes = json.dumps(decrypted_user_data).encode()
                    encrypted_data = self.client_fernet.encrypt(self.cipher.encrypt(decrypted_user_data_bytes))

                    print(
                        f"\n ------------------------------ \n    Total data sent: {encrypted_data} \n ------------------------------ ")

                    await asyncio.to_thread(self.client.sendall, encrypted_data)
                    await asyncio.to_thread(self.client.sendall, b"DONE")

                    logger.info("Successfully sent user data to client")

            else:
                print("Decrypted data was dictionary")
                print(decrypted_data)

                update_depth: str = await self.receive_all()

                while update_depth == "":
                    update_depth: str = await self.receive_all()

                try:
                    logger.info("Updating saved data with received data")

                    pprint.pprint(f"Update depth is: {update_depth}")

                    # Check update_depth to figure out if update should be recursive or not
                    if update_depth == "RECURSIVE":
                        # Loop through all the saved services. delete all services that are saved from decrypted_data

                        for saved_service in saved_data.keys():
                            for saved_username in saved_data[saved_service]:
                                del decrypted_data[saved_service][saved_username]


                        # Loop through all services in decrypted_data. If a service is empty, then all its usernames were deleted and no changes were made to that service, so you can remove it
                        for decrypted_service in decrypted_data.keys():
                            if decrypted_data[decrypted_service] is dict:
                                del decrypted_data[decrypted_service]

                        for decrypted_service in decrypted_data.keys():
                            for decrypted_username in decrypted_data[decrypted_service].keys():

                                # Check if the decrypted service is already saved. If so, add new username. If not, add new service
                                if decrypted_service in saved_data.keys():

                                    saved_data[decrypted_service][decrypted_username] = {
                                        "password": decrypted_data[decrypted_service][decrypted_username]["password"],
                                        "key": self.client_fernet.encrypt(self.key).decode()
                                    }

                                else:
                                    saved_data[decrypted_service] = {
                                        decrypted_username: {
                                            "password": decrypted_data[decrypted_service][decrypted_username]["password"],
                                            "key": self.client_fernet.encrypt(self.key).decode()
                                        }
                                    }

                        for saved_service in saved_data.keys():
                            for saved_username in saved_data[saved_service].keys():
                                print(saved_data[saved_service][saved_username]["password"])
                                # Check if the saved key matches the key saved for the current cipher. If so, encrypt it
                                # using current cipher. If not, create temporary cipher with saved key
                                if self.client_fernet.decrypt(saved_data[saved_service][saved_username]["key"]) == self.key:
                                    saved_data[saved_service][saved_username]["password"] = self.cipher.encrypt(
                                            saved_data[saved_service][saved_username]["password"].encode()
                                    ).decode()

                                    saved_data[saved_service][saved_username]["last-refresh"] = (datetime.datetime.now()
                                                                                                 .strftime(format="%m-%d-%Y"))

                                else:
                                    temp_cipher = Fernet(self.client_fernet.decrypt(saved_data[saved_service][saved_username]["key"]))
                                    saved_data[saved_service][saved_username]["password"] = temp_cipher.encrypt(
                                        saved_data[saved_service][saved_username]["password"].encode()).decode()

                                    saved_data[saved_service][saved_username]["last-refresh"] = (datetime.datetime.now()
                                                                                                 .strftime(format="%m-%d-%Y"))
                                    saved_data[saved_service][saved_username]["key"] = self.client_fernet.encrypt(saved_data[saved_service][saved_username]["key"].encode()).decode()

                        with open(f"data/{self.client_addr}/{self.client_user.decode()}/.passwords.json", mode="w") as passwords_file:

                            json.dump(saved_data, passwords_file, indent=4)

                    elif update_depth == "REPLACE":
                        saved_data = {}
                        for decrypted_service in decrypted_data.keys():
                            for decrypted_username in decrypted_data[decrypted_service].keys():
                                print(decrypted_data[decrypted_service][decrypted_username]["key"])
                                password = decrypted_data[decrypted_service][decrypted_username]["password"]
                                key = decrypted_data[decrypted_service][decrypted_username]["key"]

                                if decrypted_service in saved_data.keys() and decrypted_username in saved_data[decrypted_service].keys():
                                    saved_data[decrypted_service][decrypted_username]["password"] = Fernet(key).encrypt(password.encode()).decode()
                                    saved_data[decrypted_service][decrypted_username]["key"] = self.client_fernet.encrypt(key.encode()).decode()

                                elif decrypted_service in saved_data.keys():
                                    saved_data[decrypted_service][decrypted_username] = {
                                        "password": Fernet(key).encrypt(password.encode()).decode(),
                                        "key": self.client_fernet.encrypt(key.encode()).decode()
                                    }
                                    
                                else:
                                    saved_data[decrypted_service] = {
                                        decrypted_username: {
                                            "password": Fernet(key).encrypt(password.encode()).decode(),
                                            "key": self.client_fernet.encrypt(key.encode()).decode()
                                        }
                                    }

                        print(f"Saved data and decrypted data combined are: {saved_data}")

                        with open(f"data/{self.client_addr}/{self.client_user.decode()}/.passwords.json", mode="w") as passwords_file:
                            json.dump(json.dumps(saved_data), passwords_file, indent=4)

                    else:
                        client.sendall(b"Failed to update data. Invalid update_depth sent")
                        logger.error("Failed to update data. Invalid update_depth sent")

                except Exception:
                    print(traceback.format_exc())

                    client.sendall(b"Failed to update data. Invalid data")
                    logger.error("Failed to update data. Invalid data")

                else:
                    client.sendall(b"Successfully updated data")
                    logger.info("Successfully updated saved data")

                finally:
                    print(f"Saved data is: {saved_data}")

    def load_device_data(self) -> dict:
        logger.info("Checking if user already has data saved")

        # Check if user has data already saved
        if os.path.exists(f"data/{self.client_addr}/{self.client_user.decode()}/.passwords.json"):
            logger.info("User already has data saved, loading saved data")

            # User has data already saved, load it and return it
            saved_passwords: dict = json.loads(json_repair.from_file(f"data/{self.client_addr}/{self.client_user.decode()}/.passwords.json"))
            print(f"Saved passwords are: {saved_passwords} and are of type: {type(saved_passwords)}")

            # Check if data was successfully loaded
            if saved_passwords == "":
                logger.warning("The data that was saved was invalid, returning empty data")
                return {}

            else:
                logger.info("Successfully loaded saved data")

                return saved_passwords

        elif os.path.exists(f"data/{self.client_addr}"):
            logger.info("A device profile has been created, but no data has been saved")

            # User doesn't have any data saved, but profile already exists. Return empty dictionary
            return {}

        elif os.path.exists(f"data/{self.client_addr}/{self.client_user.decode()}"):
            logger.info("A user profile has been created, but no data has been saved")

            return {}

        else:
            logger.info("User doesn't have profile saved. Creating profile")

            # User doesn't have data already saved and doesn't have a profile saved, return empty dictionary and
            # create new folder for them
            os.mkdir(f"data/{self.client_addr}")
            os.mkdir(f"data/{self.client_addr}/{self.client_user.decode()}")

            print("Successfully created profile")
            return {}

    @staticmethod
    def break_down_data(data: dict) -> list:
        broken_down_data: list[dict] = []

        logger.info("Breaking down received data")

        for service in data.keys():
            for service_data in data.values():
                broken_down_data.append(
                    {
                        service: service_data
                    }
                )

        logger.info("Successfully broke down data")

        return broken_down_data

if __name__ == "__main__":
    server_result = start_server(interactive=True)
    print(server_result)
