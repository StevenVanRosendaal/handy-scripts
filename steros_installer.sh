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

# Install screen
echo "Installing screen..."
apt-get install screen -y

# Install fail2ban
echo "Installing fail2ban..."
apt-get install fail2ban -y

# Install unattended-upgrades
echo "Installing unattended-upgrades..."
apt-get install unattended-upgrades apt-listchanges -y
echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | debconf-set-selections
dpkg-reconfigure -f noninteractive unattended-upgrades
echo 'APT::Periodic::Update-Package-Lists "1";' >> /etc/apt/apt.conf.d/20auto-upgrades
echo 'APT::Periodic::Unattended-Upgrade "1";' >> /etc/apt/apt.conf.d/20auto-upgrades

# Enable ipv6
# Check the content of the /proc/sys/net/ipv6/conf/all/disable_ipv6 file to see if ipv6 is enabled
if [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)" -eq 0 ]; then
    echo "IPv6 is already enabled"
else
    # Ask if the user wants to enable ipv6
    while true; do
        read -p "Do you want to enable IPv6? (y/n) " yn
        case $yn in
            [Yy]* ) break;;
            [Nn]* ) exit;;
            * ) echo "Please answer yes or no.";;
        esac
    done
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
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
    if id "$username" &>/dev/null; then
        echo "User already exists. Please choose another username."
    else
        valid_user=true
    fi
done
adduser $username
usermod -aG sudo $username

passwords_match=false

while [ "$passwords_match" = false ]; do
    # Ask for the password of the user
    read -s -p "Enter the password of the user: " password
    # Repeat the password
    read -s -p "Repeat the password: " password2
    # Check if the passwords match
    if [ "$password" != "$password2" ]; then
        echo "Passwords do not match. Please try again."
    else
        passwords_match=true
        echo "$username:$password" | chpasswd
    fi
done

# Configure SSH with public key authentication for the user
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
    if [[ ! $public_key =~ ^ssh-rsa[[:space:]] ]] && [[ ! $public_key =~ ^ssh-ed25519[[:space:]] ]] && [[ ! $public_key =~ ^ecdsa-sha2-nistp256[[:space:]] ]]; then
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

# Configure 2FA
while true; do
    read -p "Do you want to enable 2FA for login? (y/n) " yn
    case $yn in
        [Yy]* ) break;;
        [Nn]* ) exit;;
        * ) echo "Please answer yes or no.";;
    esac
done
if [[ $REPLY =~ ^[Yy]$ ]]; then
    apt-get install libpam-google-authenticator
    # Run google-authenticator with all answers set to yes
    su - $username -c "google-authenticator -t -d -f -r 3 -R 30 -W"
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
apt-get install ufw
ufw default deny incoming
ufw default allow outgoing

# Change the ssh port
while true; do
    read -p "Do you want to change the SSH port? (y/n) " yn
    case $yn in
        [Yy]* ) break;;
        [Nn]* ) exit;;
        * ) echo "Please answer yes or no.";;
    esac
done
if [[ $REPLY =~ ^[Yy]$ ]]; then
    valid_port=false

    while [ "$valid_port" = false ]; do
        read -p "Enter the new SSH port: " ssh_port
        #validate the port number
        if ! [[ $ssh_port =~ ^[0-9]+$ ]] || [ $ssh_port -lt 1 ] || [ $ssh_port -gt 65535 ]; then
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