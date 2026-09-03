from __future__ import annotations
import socket, struct
from pathlib import Path
from typing import Iterator, Optional

def iter_pcapng(path: Path) -> Iterator[tuple[int, Optional[int], bytes]]:
    data=path.read_bytes(); off=0; endian='<'; ifaces=[]
    while off+12<=len(data):
        if data[off:off+4]==b'\x0a\x0d\x0d\x0a':
            bom=data[off+8:off+12]
            endian='<' if bom==b'\x4d\x3c\x2b\x1a' else '>' if bom==b'\x1a\x2b\x3c\x4d' else endian
        try: bt,bl=struct.unpack_from(endian+'II',data,off)
        except struct.error: break
        if bl<12 or off+bl>len(data): break
        body=data[off+8:off+bl-4]
        if bt==1 and len(body)>=8: ifaces.append(struct.unpack_from(endian+'H',body,0)[0])
        elif bt==6 and len(body)>=20:
            iid,_,_,caplen,_=struct.unpack_from(endian+'IIIII',body,0)
            yield iid, ifaces[iid] if iid<len(ifaces) else None, body[20:20+caplen]
        elif bt==3 and len(body)>=4: yield 0, ifaces[0] if ifaces else None, body[4:]
        off+=bl

def udp_from_frame(link: Optional[int], packet: bytes):
    if link==1:
        if len(packet)<14:return None
        et=struct.unpack('!H',packet[12:14])[0]; pos=14
        while et in (0x8100,0x88A8) and len(packet)>=pos+4:
            et=struct.unpack('!H',packet[pos+2:pos+4])[0]; pos+=4
        if et!=0x0800:return None
    elif link==113:
        if len(packet)<16 or struct.unpack('!H',packet[14:16])[0]!=0x0800:return None
        pos=16
    elif link==276:
        if len(packet)<20 or struct.unpack('!H',packet[0:2])[0]!=0x0800:return None
        pos=20
    else:return None
    if len(packet)<pos+20:return None
    ihl=(packet[pos]&15)*4
    if packet[pos]>>4!=4 or ihl<20 or packet[pos+9]!=17 or len(packet)<pos+ihl+8:return None
    src=socket.inet_ntoa(packet[pos+12:pos+16]); dst=socket.inet_ntoa(packet[pos+16:pos+20]); u=pos+ihl
    sp,dp,ul=struct.unpack('!HHH',packet[u:u+6]); payload=packet[u+8:min(len(packet),u+ul)]
    return src,dst,sp,dp,payload
