import io
import os
import time

import paramiko
import requests
from dotenv import load_dotenv

load_dotenv()

# Configuration
DO_API_TOKEN = os.getenv("DO_API_TOKEN")
SSH_KEY_ID = "5d:90:1c:21:30:0e:42:54:3e:21:31:d7:3a:85:cf:a8"
DROPLET_NAME = "proxy-sg"
REGION = "sgp1"
SIZE = "s-1vcpu-512mb-10gb"
IMAGE = "ubuntu-24-04-x64"


def check_droplet_exists():
    """Check if a droplet with name containing 'proxy' already exists."""
    url = "https://api.digitalocean.com/v2/droplets"
    headers = {
        "Authorization": f"Bearer {DO_API_TOKEN}",
        "Content-Type": "application/json",
    }

    response = requests.get(url, headers=headers)
    response.raise_for_status()

    droplets = response.json().get("droplets", [])
    for droplet in droplets:
        if "proxy" in droplet["name"].lower():
            print(
                f"[!] Droplet with name '{droplet['name']}' already exists (ID: {droplet['id']})"
            )
            return droplet
    return None


def create_droplet():
    # Check if proxy droplet already exists
    existing_droplet = check_droplet_exists()
    if existing_droplet:
        print(
            f"[!] Using existing droplet: {existing_droplet['name']} (ID: {existing_droplet['id']})"
        )
        return existing_droplet["id"]

    url = "https://api.digitalocean.com/v2/droplets"
    headers = {
        "Authorization": f"Bearer {DO_API_TOKEN}",
        "Content-Type": "application/json",
    }
    data = {
        "name": DROPLET_NAME,
        "region": REGION,
        "size": SIZE,
        "image": IMAGE,
        "ssh_keys": [SSH_KEY_ID],
        "backups": False,
        "ipv6": False,
        "user_data": None,
        "private_networking": None,
        "monitoring": False,
    }

    response = requests.post(url, json=data, headers=headers)
    response.raise_for_status()
    droplet = response.json()["droplet"]
    droplet_id = droplet["id"]
    print(f"[+] Droplet created with ID: {droplet_id}")
    return droplet_id


def get_droplet_ip(droplet_id):
    url = f"https://api.digitalocean.com/v2/droplets/{droplet_id}"
    headers = {"Authorization": f"Bearer {DO_API_TOKEN}"}

    for _ in range(30):
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        networks = response.json()["droplet"]["networks"]
        v4 = networks.get("v4", [])
        if v4:
            ip_address = v4[0]["ip_address"]
            print(f"[+] Droplet IP: {ip_address}")
            return ip_address
        time.sleep(5)
    raise Exception("Timeout: IP not assigned")


def generate_random_credentials():
    """Generate random username and password for proxy authentication."""
    import random
    import string

    username = "".join(random.choices(string.ascii_letters, k=8))
    password = "".join(random.choices(string.ascii_letters + string.digits, k=16))
    return username, password


def setup_socks5_proxy(ip_address):
    """
    Set up SOCKS5 proxy on the target server using Dante with authentication.
    Returns proxy URL in format: socks5://username:password@ip:port
    """
    print("[+] Setting up SOCKS5 proxy with Dante...")

    # Generate random credentials if not provided
    proxy_user = os.getenv("PROXY_USER")
    proxy_pass = os.getenv("PROXY_PASSWORD")

    if not all([proxy_user, proxy_pass]):
        proxy_user, proxy_pass = generate_random_credentials()
        print(
            f"[!] Generated credentials - Username: {proxy_user}, Password: {proxy_pass}"
        )
    else:
        print("[*] Using provided credentials from environment variables")

    # Get SSH key from environment variable
    ssh_private_key = os.getenv("SSH_PRIVATE_KEY")
    if not ssh_private_key:
        raise ValueError("SSH_PRIVATE_KEY environment variable is not set")

    # Clean and format the key
    ssh_private_key = ssh_private_key.strip().replace("\\n", "\n")

    # Try different key types
    key = None
    key_types = [
        (paramiko.RSAKey, "RSA"),
        (paramiko.Ed25519Key, "Ed25519"),
        (paramiko.ECDSAKey, "ECDSA"),
    ]

    for key_class, key_type in key_types:
        try:
            key = key_class.from_private_key(
                file_obj=io.StringIO(ssh_private_key),
                password=os.getenv("SSH_PASSPHRASE", None),
            )
            print(f"[+] Using {key_type} key")
            break
        except paramiko.ssh_exception.SSHException:
            continue

    if key is None:
        raise ValueError(
            "Failed to load private key. Unsupported key format or invalid passphrase"
        )

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connected = False
    for _ in range(10):
        try:
            ssh.connect(ip_address, username="root", pkey=key, timeout=10)
            connected = True
            break
        except Exception:
            time.sleep(5)

    if not connected:
        raise Exception("SSH connection failed")

    # Create system user for proxy authentication
    cmds = [
        "apt update && apt install -y dante-server apache2-utils",
        # Create proxy user with no shell access
        f"useradd -r -s /usr/sbin/nologin {proxy_user}",
        # Set password for the user
        f'echo "{proxy_user}:{proxy_pass}" | chpasswd',
        # Create Dante config with authentication
        "cat > /etc/danted.conf <<EOF\n"
        "logoutput: syslog\n"
        "internal: eth0 port = 1080\n"
        "external: eth0\n"
        "socksmethod: username\n"  # Enable username/password auth
        "user.privileged: root\n"
        "user.notprivileged: nobody\n"
        "user.libwrap: nobody\n"
        "client pass {\n"
        "    from: 0.0.0.0/0 to: 0.0.0.0/0\n"
        "    log: connect disconnect error\n"
        "}\n"
        "socks pass {\n"
        "    from: 0.0.0.0/0 to: 0.0.0.0/0\n"
        "    command: bind connect udpassociate\n"
        "    log: connect disconnect error\n"
        "    method: username\n"  # Require authentication
        "}\n"
        "EOF",
        "systemctl enable danted",
        "systemctl start danted",
    ]

    for cmd in cmds:
        stdin, stdout, stderr = ssh.exec_command(cmd)
        stdout.channel.recv_exit_status()

    ssh.close()

    # Return proxy URL for easy access
    proxy_url = f"socks5://{proxy_user}:{proxy_pass}@{ip_address}:1080"
    print("[+] SOCKS5 proxy is ready!")
    print(f"[+] Proxy URL: {proxy_url}")
    print(
        f"[+] Command to use: curl --socks5 {ip_address}:1080 --proxy-user {proxy_user}:{proxy_pass} http://ifconfig.me"
    )

    return proxy_url


def main():
    try:
        droplet_id = create_droplet()
        if droplet_id:
            ip_address = get_droplet_ip(droplet_id)
            setup_socks5_proxy(ip_address)
            print(f"[+] SOCKS5 proxy setup complete! Use {ip_address}:1080")
    except Exception as e:
        print(f"[-] Error: {str(e)}")
        return 1
    return 0


if __name__ == "__main__":
    main()
