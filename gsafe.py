import os
import subprocess

def check_firewall():
    try:
        # Check if UFW (Uncomplicated Firewall) is enabled
        ufw_status = subprocess.check_output("sudo ufw status", shell=True)
        if "active" in str(ufw_status):
            print("[INFO] UFW (Firewall) is enabled.")
        else:
            print("[WARNING] UFW (Firewall) is not enabled. Consider enabling it.")
    except Exception as e:
        print("[ERROR] Error checking UFW status:", e)

def check_ssh_security():
    try:
        # Check for SSH settings in the sshd_config file
        with open("/etc/ssh/sshd_config", "r") as file:
            config = file.read()
            if "PasswordAuthentication no" in config:
                print("[INFO] SSH password authentication is disabled.")
            else:
                print("[WARNING] SSH password authentication is enabled. Consider disabling it.")
    except Exception as e:
        print("[ERROR] Error reading sshd_config:", e)

def check_software_updates():
    try:
        # Check if system updates are required
        update_check = subprocess.check_output("sudo apt-get update && sudo apt-get -s upgrade", shell=True)
        if "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded." in str(update_check):
            print("[INFO] System is up-to-date.")
        else:
            print("[WARNING] Some packages are outdated. Consider updating your system.")
    except Exception as e:
        print("[ERROR] Error checking for updates:", e)

def check_sudo_usage():
    try:
        # Check for users with sudo privileges
        sudoers_file = subprocess.check_output("sudo cat /etc/sudoers", shell=True)
        if "root" in str(sudoers_file):
            print("[INFO] Root has sudo privileges.")
        else:
            print("[WARNING] Root doesn't have sudo privileges. Please check sudoers file.")
    except Exception as e:
        print("[ERROR] Error checking sudoers file:", e)

def check_user_permissions():
    try:
        # Check for world-writable files in the system
        files = subprocess.check_output("find / -xdev -type f -perm -002", shell=True)
        if files:
            print("[WARNING] World-writable files found:", files)
        else:
            print("[INFO] No world-writable files found.")
    except Exception as e:
        print("[ERROR] Error checking file permissions:", e)

def check_security_tools():
    # Check if security tools like fail2ban, apparmor, or selinux are installed
    tools = ["fail2ban", "apparmor", "selinux"]
    for tool in tools:
        try:
            output = subprocess.check_output(f"dpkg -l | grep {tool}", shell=True)
            if tool in str(output):
                print(f"[INFO] {tool} is installed.")
            else:
                print(f"[WARNING] {tool} is not installed. Consider installing it for added security.")
        except Exception as e:
            print(f"[ERROR] Error checking for {tool}:", e)

def main():
    print("[INFO] Running security checks...")
    check_firewall()
    check_ssh_security()
    check_software_updates()
    check_sudo_usage()
    check_user_permissions()
    check_security_tools()
    print("[INFO] Security check complete.")

if __name__ == "__main__":
    main()
