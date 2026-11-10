# port-scanner

A multithreaded TCP connect port scanner in Python with banner grabbing and risk notes. Standard library only. The code is commented so the networking ideas are easy to follow.

```
$ python scanner.py 127.0.0.1 -p 1-1024
   22/tcp open  ssh       SSH-2.0-OpenSSH_9.6
   80/tcp open  http
 3389/tcp open  rdp       ! RDP exposed to the network
3 open port(s) found
```

## How it works

1. `parse_ports` turns `22,80,8000-8010` into a sorted list and rejects bad input.
2. `probe` opens a TCP connection to one port. If it connects, the port is open; it then waits briefly for a banner, because services like SSH and SMTP greet first.
3. `scan` runs probes in a thread pool, since each attempt mostly waits on the network.
4. Open ports get a service label and, for risky ones (FTP, Telnet, SMB, RDP), a note.

## Safety

Scan only machines you own or are authorized to test. The CLI refuses public IP addresses unless you pass `--allow-public`.

## Run

```bash
pip install pytest
python -m pytest -q      # 5 tests, each starts its own local test server
python scanner.py 127.0.0.1 -p 1-1024
```

## Limits

It only does full TCP connects, so it is easy to detect and does not try UDP, stealth scans or service fingerprinting.
