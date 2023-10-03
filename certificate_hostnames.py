import argparse
import subprocess
import re

def get_hostnames_from_certificate(ip, port=443):
    try:
        # Use OpenSSL to connect to the IP and retrieve the certificate information
        cmd = f"openssl s_client -connect {ip}:{port} -servername {ip} 2>/dev/null | openssl x509 -noout -text"
        output = subprocess.check_output(cmd, shell=True, text=True)

        # Use regular expressions to extract hostnames from the certificate
        hostnames = re.findall(r'DNS:([^\s,]+)', output)

        return hostnames
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        return []

def process_input_file(file_path):
    try:
        with open(file_path, 'r') as file:
            for line in file:
                line = line.strip()
                parts = line.split(':')
                if len(parts) == 1:
                    ip = parts[0]
                    port = 443  # Default to port 443
                elif len(parts) == 2:
                    ip, port = parts[0], int(parts[1])
                else:
                    print(f"Invalid format in line: {line}")
                    continue
                
                hostnames = get_hostnames_from_certificate(ip, port)
                if hostnames:
                    print(f"Hostnames found in the certificate for {ip}:{port}:")
                    for hostname in hostnames:
                        print(hostname)
                else:
                    print(f"No hostnames found in the certificate for {ip}:{port}")
    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except Exception as e:
        print(f"An error occurred: {e}")

def main():
    parser = argparse.ArgumentParser(description="Retrieve hostnames from certificates when connecting to an IP using OpenSSL.")
    parser.add_argument("-i", "--ip", help="Single IP address and optional port in 'ip:port' format.")
    parser.add_argument("-I", "--input-file", help="File containing IP addresses and ports in 'ip:port' format, one per line.")

    args = parser.parse_args()

    if args.ip:
        parts = args.ip.split(':')
        if len(parts) == 1:
            ip = parts[0]
            port = 443  # Default to port 443
        elif len(parts) == 2:
            ip, port = parts[0], int(parts[1])
        else:
            print("Invalid input format.")
        hostnames = get_hostnames_from_certificate(ip, port)
        if hostnames:
            print(f"Hostnames found in the certificate for {ip}:{port}:")
            for hostname in hostnames:
                print(hostname)
        else:
            print(f"No hostnames found in the certificate for {ip}:{port}")

    elif args.input_file:
        process_input_file(args.input_file)
    
    else:
        print("Please provide either a single IP address using -i or an input file using -I.")

if __name__ == "__main__":
    main()
