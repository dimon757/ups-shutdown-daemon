import socket
import time

# --- Configuration ---
TARGET_IP = '127.0.0.1'
TARGET_PORT = 162
COMMUNITY = b'public'

# --- ASN.1 BER Encoding Helpers ---
def encode_length(l):
    if l <= 127: return bytes([l])
    res = []
    while l > 0:
        res.append(l & 0xff)
        l >>= 8
    return bytes([0x80 | len(res)] + res[::-1])

def encode_octet_string(s):
    if isinstance(s, str): s = s.encode('utf-8')
    return b'\x04' + encode_length(len(s)) + s

def encode_oid(oid_str):
    parts = [int(x) for x in oid_str.strip('.').split('.')]
    res = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        if p == 0:
            res += b'\x00'
            continue
        buf = []
        while p > 0:
            buf.append(p & 0x7f)
            p >>= 7
        for i in range(len(buf)-1, 0, -1):
            res += bytes([buf[i] | 0x80])
        res += bytes([buf[0]])
    return b'\x06' + encode_length(len(res)) + res

def wrap_sequence(payload):
    return b'\x30' + encode_length(len(payload)) + payload

def build_trap_packet(trap_id, message):
    # The Trap OID: .1.3.6.1.4.1.935.0.X
    trap_oid_bytes = encode_oid(f"1.3.6.1.4.1.935.0.{trap_id}")
    
    # 1. Varbind: sysUpTime.0 (Value: TimeTicks 0)
    vb1 = wrap_sequence(encode_oid("1.3.6.1.2.1.1.3.0") + b'\x43\x01\x00')
    
    # 2. Varbind: snmpTrapOID.0 (Value: The Trap OID)
    vb2 = wrap_sequence(encode_oid("1.3.6.1.6.3.1.1.4.1.0") + trap_oid_bytes)
    
    # 3. Varbind: The Trap OID (Value: The description string)
    vb3 = wrap_sequence(trap_oid_bytes + encode_octet_string(message))

    # Varbind List
    vblist = wrap_sequence(vb1 + vb2 + vb3)
    
    # PDU Header: [Tag A7] [Length] [ReqID] [ErrStatus 0] [ErrIndex 0] [VarbindList]
    pdu_header = b'\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00'
    pdu = b'\xa7' + encode_length(len(pdu_header + vblist)) + pdu_header + vblist
    
    # Message: [Sequence] [Version 1 (v2c)] [Community] [PDU]
    packet = wrap_sequence(b'\x02\x01\x01' + encode_octet_string(COMMUNITY) + pdu)
    return packet

# --- Full Trap Dictionary ---
TRAPS = {
    1: "Communication to the UPS has been lost", 2: "UPS overload",
    3: "The UPS failed its internal diagnostic self-test", 4: "UPS runtime calibration discharge",
    5: "On battery", 6: "The UPS has enabled Boost",
    7: "The UPS batteries are low", 8: "Communication established",
    9: "Power Restored", 10: "Internal self-test passed",
    11: "Return from low battery", 12: "Turned off by management",
    13: "Entering sleep mode", 14: "Woke up from sleep mode",
    15: "Reboot sequence started", 16: "Temperature exceed normal",
    17: "Temperature normal", 18: "Humidity exceed normal",
    19: "Humidity normal", 20: "Smoke abnormal",
    21: "Water abnormal", 22: "Security abnormal", 24: "Water normal",
    26: "Gas Alarm", 27: "UPS Temperature Overrun", 28: "UPS Load Normal",
    29: "UPS temperature Normal", 30: "Temperature below normal",
    31: "Humidity below normal", 32: "Entering bypass mode",
    33: "Security1 Alarm", 34: "Security2 Alarm", 35: "Security3 Alarm",
    36: "Security4 Alarm", 37: "Security5 Alarm", 38: "Security6 Alarm",
    39: "Security7 Alarm", 47: "Rectifier Rotation Error",
    48: "Bypass Frequency Fail", 49: "Bypass AC Normal",
    50: "Bypass AC Abnormal", 51: "UPS Test", 52: "UPS Schedule Shutdown",
    53: "Return from Bypass Mode", 54: "UPS Short Circuit Shutdown",
    55: "Inverter Output Fail Shutdown", 56: "Manual Bypass Breaker on",
    57: "UPS High DC Shutdown", 58: "UPS Emergency Stop",
    59: "Static Switch in Inverter Mode", 60: "Static Switch in Bypass Mode",
    61: "Over Temperature Shutdown", 62: "Overload Shutdown",
    63: "UPS Capacity Underrun", 64: "UPS Capacity Normal",
    67: "Low Battery Shutdown", 68: "The UPS has enabled Buck",
    69: "The UPS has return from Buck", 70: "The UPS has return from Boost"
}

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print("\n" + "="*75)
    print("      UPSMATE (2).MIB - CORRECTED RAW TRAP SENDER")
    print("="*75)
    
    ids = sorted(TRAPS.keys())
    half = (len(ids) + 1) // 2
    for i in range(half):
        id1 = ids[i]
        line = f"{id1:2}) {TRAPS[id1][:30]:<30}"
        if i + half < len(ids):
            id2 = ids[i + half]
            line += f" | {id2:2}) {TRAPS[id2][:30]}"
        print(line)
    
    print("="*75)
    print(" 0) Send ALL Traps | q) Quit")
    
    while True:
        choice = input("\nSelect Trap ID: ").strip().lower()
        if choice == 'q': break
        if choice == '0':
            for tid, msg in TRAPS.items():
                pkt = build_trap_packet(tid, msg)
                sock.sendto(pkt, (TARGET_IP, TARGET_PORT))
                time.sleep(0.05)
            print("All 70 traps sent.")
        elif choice.isdigit() and int(choice) in TRAPS:
            tid = int(choice)
            pkt = build_trap_packet(tid, TRAPS[tid])
            sock.sendto(pkt, (TARGET_IP, TARGET_PORT))
            print(f"Sent Trap {tid}: {TRAPS[tid]}")

if __name__ == "__main__":
    main()
