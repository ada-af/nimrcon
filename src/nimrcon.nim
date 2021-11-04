discard """
MIT License

Copyright (c) 2020 Ilya "mcilya" Tretyakov

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import net
import random
import struct
import json
import os
import strutils

type Packet = object
    size*: int
    id*: int
    pkt_type*: int
    body*: string
    empty: string

const
    ptRESPONSE_VALUE* = 0
    ptAUTH_RESPONSE* = 2
    ptEXECCMD* = 2
    ptAUTH* = 3

type RCONConnection* = object
    host: string
    port: int
    password: string
    sock: Socket

type AuthError* = object of Exception

proc toJSON*(packet: Packet): JsonNode =
    discard "Obviously converts Packet to JSON"
    %*{
        "size": packet.size,
        "id": packet.id,
        "type": packet.pkt_type,
        "body": packet.body
    }

proc sendpacket(conn: RCONConnection, packet: Packet): void = 
    discard "Used for sending packets"
    var data = pack("<ii", packet.id, packet.pkt_type) & packet.body & packet.empty
    data = pack("<i", data.len) & data
    conn.sock.send(data)

proc parsePacket(conn: RCONConnection): Packet =
    result.size = unpack("<i", conn.sock.recv(4))[0].getInt
    let resp = conn.sock.recv(result.size)
    let data = unpack("<ii$#s" % [$(result.size-10)], resp)
    result.id = data[0].getInt()
    result.pkt_type = data[1].getInt()
    result.body = data[2].getString()

proc newPacket(conn:RCONConnection, t: int): Packet =
    discard "Returns packet of type `t`"
    discard "Read docs or lookup consts"
    randomize()
    result.id = rand(int32.high) # using random packet id just because
    result.pkt_type = t.int32
    result.empty = "\x00\x00"

proc auth(conn: RCONConnection): bool =
    discard "Returns true if auth successfull"
    var pkt = conn.newPacket(ptAUTH)
    pkt.body = conn.password
    conn.sendpacket(pkt)
    let res = unpack("<iii", conn.sock.recv(14)) # probably sends '\x00\x00' with size, id and type
    res[1].getInt == pkt.id
    
proc exec*(conn: RCONConnection, cmd: string): Packet = 
    discard "Sends command for execution on server"
    var pkt = conn.newPacket(ptEXECCMD)
    pkt.body = cmd
    conn.sendpacket(pkt)
    sleep(50)
    conn.parsePacket()

proc newRCONConnection*(host: string = "127.0.0.1",
                       port: int = 27015,
                       password: string = ""): RCONConnection =
    discard "Creates new RCONConnection object"
    result.host = host
    result.port = port
    result.password = password
    result.sock = newSocket()
    result.sock.connect(host, Port(port))
    if not result.auth():
        raise newException(AuthError, "Wrong Password")
