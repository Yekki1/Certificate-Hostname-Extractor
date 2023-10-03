OpenSSL Certificate Hostname Extractor
This Python script allows you to retrieve hostnames from SSL/TLS certificates when connecting to an IP address using the OpenSSL command-line tool.

Usage
To use this script, you have two options:

Single IP Address Input:
Use the -i or --ip flag followed by the IP address and optional port in the format ip:port. If no port is provided, it defaults to port 443.
```
python certificate_hostnames.py -i 209.97.191.30
```
Input from a File:

Use the -I or --input-file flag followed by the path to a text file containing IP addresses and ports in the format ip:port, with each combination on a separate line.
Example:
```
python certificate_hostnames.py -I input.txt
```

How It Works
The script uses the subprocess module to invoke the openssl s_client command to establish a secure connection to the specified IP address and retrieve the SSL/TLS certificate.
It then parses the certificate information using regular expressions to extract the hostnames listed in the certificate's subject alternative name (SAN) field.
The script displays the hostnames found in the certificate.
