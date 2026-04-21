# SDN Firewall using Ryu and Mininet

A software-defined networking firewall implemented with the Ryu controller and Mininet network emulator. The controller uses MAC learning to forward traffic efficiently and blocks specified IP pairs bidirectionally.

## Features
- MAC learning — traffic is forwarded out the correct port after the first packet
- Bidirectional IP blocking — blocking h1→h2 automatically blocks h2→h1
- ARP blocking — blocked pairs cannot resolve each other's MAC addresses
- DNS packet filtering — DNS packets are ignored to prevent parsing errors
- Drop rules pre-installed on switch connect — visible immediately in flow table

## Requirements
- Ubuntu (tested on Ubuntu 22.04)
- Python 3.9
- Mininet
- Ryu SDN Framework

## Setup

### 1. Install Python 3.9 and create virtual environment
```bash
sudo apt update
sudo apt install python3.9 python3.9-venv
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
sudo python3.9 get-pip.py
python3.9 -m venv ~/ryu-env
source ~/ryu-env/bin/activate
```

### 2. Install dependencies
```bash
pip install setuptools==58.0.0
pip install ryu
pip install eventlet==0.30.2
```

### 3. Install Mininet
```bash
sudo apt install mininet
```

## Usage

### Step 1 — Start the Ryu controller (Terminal 1)
```bash
source ~/ryu-env/bin/activate
ryu-manager firewall.py
```

### Step 2 — Start Mininet (Terminal 2)
```bash
sudo python3 topo.py
```

### Step 3 — Test connectivity
```bash
# These should work (0% packet loss)
h1 ping -c 3 h3
h1 ping -c 3 h4

# This should be blocked (100% packet loss)
h1 ping -c 3 h2
```

### Step 4 — View flow tables
```bash
sh ovs-ofctl -O OpenFlow13 dump-flows s1
sh ovs-ofctl -O OpenFlow13 dump-flows s2
```

## Topology
```
        s1 ───── s2
       /  \     /  \
      h1  h2  h3   h4
```

## Modifying Blocked Pairs
Edit the `blocked_pairs` set in `firewall.py`:
```python
self.blocked_pairs = {
    ('10.0.0.1', '10.0.0.2'),  # blocks h1 <-> h2
    ('10.0.0.3', '10.0.0.4'),  # blocks h3 <-> h4
}
```
