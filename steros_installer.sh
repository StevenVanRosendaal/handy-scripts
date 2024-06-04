#!/bin/sh

# Set -e: Exit immediately if a command exits with a non-zero status.
set -e

echo "This script installs the Steros software on a Linux system."
while true; do
    read -p "Do you want to continue? (y/n) " yn
    case $yn in
        [Yy]* ) break;;
        [Nn]* ) exit;;
        * ) echo "Please answer yes or no.";;
    esac
done

# Check if the user is root
if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root" 1>&2
    exit 1
fi

# Check if the user is running the script on a unsupported OS
if [ ! -f /etc/debian_version ]; then
    echo "Unsupported OS"
    exit 1
fi

# Check for updates
echo "Checking for updates..."
apt-get update
apt-get upgrade -y

# Install setup dependencies
echo "Installing dependencies..."
apt-get install screen fail2ban net-tools unattended-upgrades apt-listchanges -y
echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | debconf-set-selections
dpkg-reconfigure -f noninteractive unattended-upgrades
echo 'APT::Periodic::Update-Package-Lists "1";' >> /etc/apt/apt.conf.d/20auto-upgrades
echo 'APT::Periodic::Unattended-Upgrade "1";' >> /etc/apt/apt.conf.d/20auto-upgrades

# Enable ipv6
# Check the content of the /proc/sys/net/ipv6/conf/all/disable_ipv6 file to see if ipv6 is enabled
if [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)" -eq 0 ]; then
    echo "IPv6 is already enabled"
else
    ipv6=false
    # Ask if the user wants to enable ipv6
    while true; do
        read -p "Do you want to enable IPv6? (y/n) " yn
        case $yn in
            [Yy]* ) ipv6=true; break;;
            [Nn]* ) break;;
            * ) echo "Please answer yes or no.";;
        esac
    done
    if $ipv6; then
        # List the network interfaces
        echo "Network interfaces:"
        ls /sys/class/net

        valid_interface=false

        while [ "$valid_interface" = false ]; do
            # Ask for the network interface
            read -p "Enter the main network interface name: " interface
            # Check if the network interface is valid
            if [ ! -d /sys/class/net/$interface ]; then
                echo "Invalid network interface. Please try again."
                ls /sys/class/net
            else
                valid_interface=true
            fi
        done
        # Enable ipv6
        echo "Enabling IPv6..."
        echo "net.ipv6.conf.all.disable_ipv6 = 0" >> /etc/sysctl.conf
        echo "net.ipv6.conf.default.disable_ipv6 = 0" >> /etc/sysctl.conf
        echo "net.ipv6.conf.lo.disable_ipv6 = 0" >> /etc/sysctl.conf
        sysctl -p
        # Configure the network interface
        echo "Configuring the network interface..."
        echo "iface $interface inet6 auto" >> /etc/network/interfaces
        echo "IPv6 has been enabled. Network will restart at the end of the script."
    fi
fi

# Add a user
valid_user=false

while [ "$valid_user" = false ]; do
    read -p "Enter the username of the user you want to add: " username
    # Check if the user already exists
    if getent passwd "$username" >/dev/null 2>&1; then
        echo "User already exists. Please choose another username."
    else
        valid_user=true
    fi
done
adduser $username
usermod -aG sudo $username

# Configure SSH with public key authentication for the user
if [ ! -f /etc/ssh/sshd_config ]; then
    echo "OpenSSH server is not installed. Installing now..."
    sudo apt-get update
    sudo apt-get install -y openssh-server
fi
echo "Configuring SSH..."
mkdir /home/$username/.ssh
touch /home/$username/.ssh/authorized_keys
chown -R $username:$username /home/$username/.ssh
chmod 700 /home/$username/.ssh
chmod 600 /home/$username/.ssh/authorized_keys

valid_key=false

while [ "$valid_key" = false ]; do
    read -p "Enter the public key of the user: " public_key
    # Validate the public key
    if echo "$public_key" | grep -qvE "^ssh-rsa|^ssh-ed25519|^ecdsa-sha2-nistp256"; then
        echo "Invalid public key. Please try again."
    else
        valid_key=true
    fi
done

echo $public_key >> /home/$username/.ssh/authorized_keys

# Configure the sshd_config file to disable password authentication and enable public key authentication
if grep -q "^PasswordAuthentication yes" /etc/ssh/sshd_config; then
    sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
fi

if grep -q "^PubkeyAuthentication no" /etc/ssh/sshd_config; then
    sed -i 's/PubkeyAuthentication no/PubkeyAuthentication yes/g' /etc/ssh/sshd_config
fi

if grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config; then
    sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
fi

two_fa=false
# Configure 2FA
while true; do
    read -p "Do you want to enable 2FA for login? (y/n) " yn
    case $yn in
        [Yy]* ) two_fa=true; break;;
        [Nn]* ) break;;
        * ) echo "Please answer yes or no.";;
    esac
done
if $two_fa; then
    apt-get install libpam-google-authenticator -y
    # Run google-authenticator with all answers set to yes
    su - $username -c "google-authenticator"
    if ! grep -q "auth required pam_google_authenticator.so" /etc/pam.d/sshd; then
        echo "auth required pam_google_authenticator.so" >> /etc/pam.d/sshd
    fi

    if grep -q "UsePam no" /etc/ssh/sshd_config; then
        sed -i 's/UsePam no/UsePam yes/g' /etc/ssh/sshd_config
    fi

    if grep -q "ChallengeResponseAuthentication no" /etc/ssh/sshd_config; then
        sed -i 's/ChallengeResponseAuthentication no/ChallengeResponseAuthentication yes/g' /etc/ssh/sshd_config
    fi
fi

# Setup firewall
echo "Setting up the firewall..."
apt-get install ufw -y
ufw default deny incoming
ufw default allow outgoing


ssh=false
# Change the SSH port
while true; do
    read -p "Do you want to change the SSH port? (y/n) " yn
    case $yn in
        [Yy]* ) ssh=true; break;;
        [Nn]* ) break;;
        * ) echo "Please answer yes or no.";;
    esac
done
if $ssh; then
    valid_port=false

    while [ "$valid_port" = false ]; do
        read -p "Enter the new SSH port: " ssh_port
        #validate the port number
        if ! echo "$ssh_port" | grep -qE '^[0-9]+$' || [ "$ssh_port" -lt 1 ] || [ "$ssh_port" -gt 65535 ]; then
            echo "Invalid port number. Please try again."
        elif netstat -tuln | grep -q ":$ssh_port "; then
            echo "Port $ssh_port is already in use. Please choose another one."
        else
            valid_port=true
        fi
    done
    sed -i "s/#Port 22/Port $ssh_port/g" /etc/ssh/sshd_config
    ufw allow $ssh_port
else
    ufw allow ssh
fi

ufw enable

echo "Steros has been installed successfully. The system will now restart the SSH services and network interfaces which will disconnect you from the server. Please reconnect to the server as the new user."

# Start a new screen session in detached mode, then run the commands
screen -dm bash -c "
    systemctl restart sshd
    ifdown $interface
    ifup $interface
"