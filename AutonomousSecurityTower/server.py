#!/bin/python3
import ast
import asyncio 
from enum import IntEnum
from pymodbus import ModbusDeviceIdentification
from pymodbus.server import ModbusTcpServer
from pymodbus.simulator import SimData, SimDevice, DataType

## COILS 
class BOOLVALUES(IntEnum): 
    LIGHTS_ON  = 0
    VENTILATION_ON = 1
    LIFT_ON = 2
    LOCKS_ON = 3
    CAMERAS_ON = 4
    MAINTENANCE_REQ = 5

coils_values = [True, True, True, True, True, False]
coils = [
    SimData(
        address=0, 
        values=coils_values, 
        datatype=DataType.BITS
    )
]

## DISCRETE INPUTS
discrete_values = [True, True, True, True, True, False]
discrete_inputs = [
    SimData(
        address=0, 
        values=discrete_values, 
        datatype=DataType.BITS, 
        readonly=True
    )
]

## INPUT REGISTERS
class INPUTREG(IntEnum): 
    VENTILATION_SPEED = 0
    LIFT_VOLTAGE = 1
    LIFT_FLOOR = 2
    BUILDING_TEMP = 3
    SERVER_ROOM_TEMP = 4
    MSG_LENGTH = 5

input_values = [65, 480, 1, 18, 10, 0] + [0] * 10000
input_registers = [
    SimData(
        address=0, 
        values=input_values, 
        datatype=DataType.REGISTERS,
        readonly=True
    )
]

## HOLDING REGISTERS
class HOLDINGREG(IntEnum): 
    VENTILATION_SPEED = 0
    LIFT_VOLTAGE = 1
    LIFT_FLOOR = 2
    BUILDING_TEMP = 3
    SERVER_ROOM_TEMP = 4
    COMMAND_LEN = 5

#holding_values = [0] * 1006
holding_registers = [
    SimData(
        address=0, 
        values=0,
        count=1006,
        datatype=DataType.REGISTERS, 
        readonly=False
    )
]

## GLOBALS
secret = "PLACEHOLDER"
admin_read_key = "PLACEHOLDER"
admin_write_key = "PLACEHOLDER"

## AST stuff
ALLOWED = {
    ast.Expression,
    ast.BoolOp,
    ast.BinOp,
    ast.UnaryOp,
    ast.Compare,
    ast.Name,
    ast.Load,
    ast.Constant,
    ast.And,
    ast.Or,
    ast.Add,
    ast.Sub,
    ast.Mult,
    ast.Div,
    ast.Gt,
    ast.GtE,
    ast.Lt,
    ast.LtE,
    ast.Eq,
    ast.NotEq,

    ast.Tuple, 
    ast.Subscript,

    ast.Call,
    ast.Attribute,       
}

def do_call(): 
    print("An administrator has been informed.")

env = {
    "ventilation_speed": 0, 
    "lift_voltage": 0, 
    "lift_floor": 0, 
    "building_temp": 0, 
    "server_room_temp": 0, 

    "max_ventilation": 100, 
    "max_voltage": 600,
    "max_floor": 19, 
    "max_temp": 25, 
    "max_server_temp": 20, 

    "key": secret, 
    "do_call": do_call
}

def contains_sanitized_call(expr):
    return any(
        isinstance(n, ast.Name) and n.id == "do_call"
        for n in ast.walk(expr)
    )

class SanitizedCall(ast.NodeTransformer):
    def visit_Call(self, node: ast.Call) -> ast.AST:
        self.generic_visit(node)

        if contains_sanitized_call(node.func):
            return node
        else: 
            return ast.Call(func=ast.Name(id='do_call', ctx=ast.Load()), args=[], keywords=[])

def validate_expression(source):
    tree = ast.parse(source, mode="eval")

    for node in ast.walk(tree):
        if type(node) not in ALLOWED:
            raise ValueError(f"unsupported node: {type(node).__name__}")
    return tree

def evaluate_expression(source):
    tree = validate_expression(source)
    tree = SanitizedCall().visit(tree)
    ast.fix_missing_locations(tree)

    return eval(
        compile(tree, "<rule>", "eval"),
        env
    )

## LOCK 
state_lock = asyncio.Lock()

## Set functions
def set_coil_register(device_id, address, value): 
    runtime = server.context.devices[device_id]
    start, count, registers, flags = runtime.block["c"]
    register_address = address // 16
    bit_number = address % 16
    offset = register_address - start
    if value:
        registers[offset] |= 1 << bit_number
    else:
        registers[offset] &= ~(1 << bit_number)

def set_discrete_register(device_id, address, value): 
    runtime = server.context.devices[device_id]
    start, count, registers, flags = runtime.block["d"]
    register_address = address // 16
    bit_number = address % 16
    offset = register_address - start
    if value:
        registers[offset] |= 1 << bit_number
    else:
        registers[offset] &= ~(1 << bit_number)

def set_input_register(device_id, address, value):
    runtime = server.context.devices[device_id]
    start_address, register_count, registers, flags = runtime.block["i"]
    offset = address - start_address
    registers[offset] = value

## Maintenance function
def do_request(device_id): 
    runtime = server.context.devices[device_id]
    start, count, registers, flags = runtime.block["h"]
    req_len = registers[HOLDINGREG.COMMAND_LEN]

    if req_len < 1000: 
        req_bytes = bytes(registers[6:6+req_len])
        req_str = req_bytes.decode("utf-8")
    else: 
        req_str = ""
    result = str(evaluate_expression(req_str))

    ## Write length
    set_input_register(1, INPUTREG.MSG_LENGTH, len(result))

    ## Write result
    result_dec = [ord(c) for c in result]
    idx = 6
    for d in result_dec: 
        if idx <= 10005: 
            set_input_register(1, idx, d)
            idx += 1
        else:
            break

## HANDLERS
async def modbus_action(function_code, start_address, address, count, registers, set_values): 

    async with state_lock: 
        if (function_code == 0x05 and address >= 0 and address < BOOLVALUES.MAINTENANCE_REQ and set_values != None): 
            print("Writing to discrete value")
            set_discrete_register(1, address, set_values[0])

        if (function_code == 0x06 and address >= 0 and address <= HOLDINGREG.SERVER_ROOM_TEMP and set_values != None): 
            print("Writing to input register")
            set_input_register(1, address, set_values[0])

        if (function_code == 0x05 and address == BOOLVALUES.MAINTENANCE_REQ and set_values == [True]): 
            print("Processing maintenance request")
            set_discrete_register(1, BOOLVALUES.MAINTENANCE_REQ, True)

            print("Doing maintenancy things")
            do_request(1)

            set_discrete_register(1, BOOLVALUES.MAINTENANCE_REQ, False)
            set_coil_register(1, BOOLVALUES.MAINTENANCE_REQ, False)
            print("Done!")

    return None

async def run_modbus_server(): 
    global server
    print("[+] MODBUS BUILDING MANAGEMENT SYSTEM RUNNING")
    print("    -> Address: 0.0.0.0:5020")
    print("    -> Device ID: 1")
    server = ModbusTcpServer(context=device,address=("0.0.0.0", 5020))
    await(server.serve_forever())

## DEVICE INFORMATION
device = SimDevice(
    id=1, 
    simdata=(coils, discrete_inputs, holding_registers, input_registers),
    action=modbus_action,
)
identity = ModbusDeviceIdentification(
    info_name={
        "VendorName": "Kaligula Armblessed Industries",
        "ProductCode": "BMS-68PM1",
        "VendorUrl": "https://kaligulaarmblessed.github.io/",
        "ProductName": "Building Management System",
        "ModelName": "BMS-68PM1",
        "MajorMinorRevision": "1.0"
    },
    info={
        0x80: admin_read_key,
    },
)

def setup(): 
    global secret
    global admin_read_key
    global admin_write_key

    tick = str(0) 
    with open("current_tick", "r") as f: 
        tick = f.read().strip("\n")       
    flagfile = "flag.txt." + str(tick)

    ## Deal with secret
    with open(flagfile, "r") as f: 
        secret = f.read().strip("\n")

    ## Deal with admin read and write keys
    with open("admin_read_key", "r") as f: 
        admin_read_key = f.read().strip("\n")
    with open("admin_write_key", "r") as f: 
        admin_write_key = f.read().strip("\n")


async def main():
    setup()
    await asyncio.gather(
        run_modbus_server(),
    )

if __name__ == "__main__":
    try:
        asyncio.run(main())

    except KeyboardInterrupt:
        print("Stopping server...")


