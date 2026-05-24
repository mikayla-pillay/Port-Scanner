# Port-Scanner
A command-line TCP port scanner built in Python using only the standard library. Scans a target host for open ports across a configurable range, identifies running services by port number, and optionally grabs service banners to fingerprint what's listening.

What it does:
Resolves hostnames to IP addresses
Scans single ports, port ranges, or a preset of common ports (SSH, HTTP, MySQL, RDP, etc.)
Runs scans concurrently using Python threads for speed (100–200+ threads)
Displays open ports, service names, and optional banners in a clean results table

Technologies: Python 3, socket, threading, argparse
