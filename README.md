# Nimrcon

Simple RCON in Nim

## Usage

```nim
import nimrcon

let conn = newRCONConnection("local.host", 27015, "hunter2")

discard conn.exec("command") 
# by default returns Packet(size, id, type, body) object

var resp = conn.exec("command with args")
echo resp.toJSON # converting to JSON
```

## Features

- Simple
- Missing support for Multi-packet response
