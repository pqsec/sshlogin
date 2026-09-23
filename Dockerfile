FROM registry.fedoraproject.org/fedora:latest

# Install build tools, PAM libraries, pamtester, and utilities
RUN dnf install -y \
    golang \
    pam-devel \
    pamtester \
    gcc \
    make \
    openssh-clients \
    shadow-utils \
    tmux \
    python3 \
    && dnf clean all

WORKDIR /src

# Copy source files
COPY . /src/

# Build and install pam_sshlogin.so and sshlogin-response
RUN make clean && make build && make install

# Configure PAM service for sshlogin
RUN cat <<'EOF' > /etc/pam.d/sshlogin
#%PAM-1.0
auth    sufficient    pam_sshlogin.so  otp_len=10
auth    required      pam_deny.so
account required      pam_permit.so
session required      pam_permit.so
EOF

# Setup test user 'alice' with Ed25519 and ECDSA keys
RUN useradd -m -s /bin/bash alice && \
    mkdir -p /home/alice/.ssh && \
    ssh-keygen -t ed25519 -N "" -f /home/alice/.ssh/id_ed25519 -C "alice-ed25519" && \
    ssh-keygen -t ecdsa -b 256 -N "" -f /home/alice/.ssh/id_ecdsa -C "alice-ecdsa" && \
    cat /home/alice/.ssh/id_ed25519.pub /home/alice/.ssh/id_ecdsa.pub > /home/alice/.ssh/authorized_keys && \
    chmod 700 /home/alice/.ssh && \
    chmod 600 /home/alice/.ssh/authorized_keys /home/alice/.ssh/id_* && \
    chown -R alice:alice /home/alice/.ssh

# Create a demo helper script that automates the interactive challenge-response cycle
RUN cat <<'EOF' > /usr/local/bin/test-auth
#!/usr/bin/env python3
import subprocess
import pty
import os
import re
import select
import sys

key_type = sys.argv[1] if len(sys.argv) > 1 else "ed25519"
key_file = "/home/alice/.ssh/id_ed25519" if key_type == "ed25519" else "/home/alice/.ssh/id_ecdsa"
curve_prefix = "x25519:" if key_type == "ed25519" else "nistp256:"

print(f"[*] Testing PAM authentication for user 'alice' using key {key_file} ({key_type})...\n")

master, slave = pty.openpty()
proc = subprocess.Popen(
    ["pamtester", "-v", "sshlogin", "alice", "authenticate"],
    stdin=slave,
    stdout=slave,
    stderr=slave,
    close_fds=True
)
os.close(slave)

output = ""
token = None

while True:
    r, _, _ = select.select([master], [], [], 2.0)
    if not r:
        break
    try:
        data = os.read(master, 1024).decode('utf-8', errors='replace')
    except OSError:
        break
    if not data:
        break
    output += data
    sys.stdout.write(data)
    sys.stdout.flush()

    # Look for matching curve token in prompt
    for line in output.splitlines():
        line = line.strip()
        if line.startswith(curve_prefix):
            token = line

    if "Enter OTP" in output and token:
        break

if not token:
    print(f"\n[!] Error: Could not find token starting with {curve_prefix}")
    proc.kill()
    sys.exit(1)

print(f"\n[*] Found challenge token: {token}")
res = subprocess.run(["sshlogin-response", "-c", token, "-i", key_file], capture_output=True, text=True, check=True)
otp = res.stdout.strip()
print(f"[*] Computed OTP: {otp}")
print(f"[*] Sending OTP to pamtester...\n")

os.write(master, (otp + "\n").encode('utf-8'))

# Read final result
while True:
    r, _, _ = select.select([master], [], [], 2.0)
    if not r:
        break
    try:
        data = os.read(master, 1024).decode('utf-8', errors='replace')
    except OSError:
        break
    if not data:
        break
    sys.stdout.write(data)
    sys.stdout.flush()

os.close(master)
proc.wait()
sys.exit(proc.returncode)
EOF
RUN chmod +x /usr/local/bin/test-auth

# Print welcome banner in interactive bash shell
RUN cat <<'EOF' >> /etc/bashrc

echo "================================================================="
echo " sshlogin Interactive PAM Test Environment"
echo "================================================================="
echo " Test user: alice"
echo " SSH Keys : /home/alice/.ssh/id_ed25519 (x25519)"
echo "            /home/alice/.ssh/id_ecdsa   (nistp256)"
echo ""
echo " Options to test:"
echo "   1) Automated test helper:"
echo "      test-auth ed25519       # Test Ed25519 authentication"
echo "      test-auth ecdsa         # Test ECDSA P-256 authentication"
echo ""
echo "   2) Manual step-by-step (e.g. in tmux or two terminals):"
echo "      pamtester -v sshlogin alice authenticate"
echo "      sshlogin-response -c <token> -i /home/alice/.ssh/id_ed25519"
echo "================================================================="
echo ""
EOF

CMD ["/bin/bash"]
