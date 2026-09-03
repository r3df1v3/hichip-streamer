from __future__ import annotations
import struct

def packet_name(data: bytes)->str:
    if len(data)<2:return 'SHORT'
    return {
      b'\xf10':'LAN_DISCOVER', b'\xf1A':'LAN_HELLO', b'\xf1B':'LAN_HELLO_ACK', b'\xf1\xe0':'PUNCH',
      b'\xf1\xe1':'PUNCH_ACK', b'\xf1\xf0':'SESSION_READY', b'\xf1\xd0':'DATA',
      b'\xf1\xd1':'DATA_ACK'
    }.get(data[:2],f'UNKNOWN_{data[:2].hex()}')

def parse_f1d0(data: bytes):
    if len(data)<8 or data[:2]!=b'\xf1\xd0': return None
    plen=struct.unpack('>H',data[2:4])[0]
    return {'declared_len':plen,'session':data[4],'channel':data[5],'sequence':struct.unpack('>H',data[6:8])[0],'payload':data[8:]}

def decode_uid_hello(data: bytes)->str|None:
    if len(data)!=24 or data[:2] not in (b'\xf1A',b'\xf1B'): return None
    raw=data[4:24]
    # Observed wire form: first 4 chars, zero padding, then suffix with a small marker.
    left=raw[:4].rstrip(b'\0').decode('ascii','ignore')
    tail=raw[12:].rstrip(b'\0').decode('ascii','ignore')
    return left + ('-' if left and tail else '') + tail
