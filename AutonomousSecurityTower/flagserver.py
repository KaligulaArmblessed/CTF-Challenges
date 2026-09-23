#!/bin/python3
import ast
import asyncio 
from enum import IntEnum

admin_write_key = "PLACEHOLDER"
admin_read_key = "PLACEHOLDER"
admin_lock = asyncio.Lock()

async def handle_admin_client(reader, writer):
    addr = writer.get_extra_info("peername")
    print(f"[+] TCP client connected: {addr}")

    try:
        data = await reader.read(1024)

        print("[+] Admin received:", data)
        writer.write(b"ACK\n")

        ## Handle received data
        ## Format: 1 -- write flag, 2 -- read flag
        ## 1:key:data:tick_num
        ## 2:key:tick_num

        data_arr = data.strip(b"\n").split(b":")

        async with admin_lock: 
            if (len(data_arr) == 4) and (data_arr[0] == b"1"): 
                if data_arr[1].decode('utf-8') == admin_write_key: 
                    print("write success") ## debug
                    new_secret = data_arr[2].decode('utf-8')
                    filename = "flag.txt." + data_arr[3].decode("utf-8")

                    ## Write new secret
                    with open(filename, "w") as file: 
                        file.write(new_secret)

                    ## Write new tick
                    with open("current_tick", "w") as file: 
                        file.write(data_arr[3].decode("utf-8"))
                else:
                    writer.write(b"INVALID REQUEST\n")
            elif (len(data_arr) == 3) and (data_arr[0] == b"2"): 
                if data_arr[1].decode('utf-8') == admin_read_key: 
                    print("read success") ## debug
                    requested_filename = "flag.txt." + data_arr[2].decode("utf-8")

                    ## Get current filename
                    with open("current_tick", "r") as file: 
                        tick = file.read().strip("\n")
                    current_filename = "flag.txt." + tick

                    try: 
                        with open(requested_filename, "r") as file: 
                            data = file.read()
                            writer.write(data.encode('utf-8'))
                        with open(current_filename, "r") as file: 
                            data = file.read()
                            writer.write(b",")
                            writer.write(data.encode('utf-8'))
                            writer.write(b"\n")
                    except: 
                            writer.write(b"INVALID REQUEST\n")
                else: 
                    writer.write(b"INVALID REQUEST\n")
            else: 
                writer.write(b"INVALID REQUEST\n")

        writer.write(b"REQUEST PROCESSING COMPLETE\n")
        try: 
            await writer.drain()
        except (BrokenPipeError, ConnectionResetError): 
            pass

    finally:
        print(f"[+] TCP client disconnected: {addr}")
        writer.close()
        try: 
            await writer.wait_closed()
        except (BrokenPipeError, ConnectionResetError): 
            pass

def setup(): 
    global admin_read_key
    global admin_write_key

    tick = str(0) 
    with open("current_tick", "w") as f:
        f.write(tick)

    ## Deal with admin read and write keys
    with open("admin_read_key", "r") as f: 
        admin_read_key = f.read().strip("\n")
    with open("admin_write_key", "r") as f: 
        admin_write_key = f.read().strip("\n")

async def run_admin_server(): 
    print("[+] STARTING ADMIN SERVER")
    print("    -> Address: 0.0.0.0:9000")
    tcp_server = await asyncio.start_server(handle_admin_client, host="0.0.0.0", port=9000)
    async with tcp_server: 
          await tcp_server.serve_forever()  

async def main():
    await asyncio.gather(
        run_admin_server(),
    )

if __name__ == "__main__":
    try:
        setup()
        asyncio.run(main())

    except KeyboardInterrupt:
        print("Stopping server...")
