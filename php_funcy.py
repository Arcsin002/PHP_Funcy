#!/usr/bin/python3

# Author: github.com/Arcsin002
# Checks if dangerous functions are left out of phpinfo() disabled_functions

import argparse
import sys
from colorama import Fore, Style

def main ():
	# Parsing arguments (filename is positional and required)
	parser = argparse.ArgumentParser(add_help = True)
	parser.add_argument('filename', help="comma separated list of disabled functions from phpinfo()")
	args = parser.parse_args()
	
	# Establish list of dangerous functions and split list of disabled functions
	dangerous_funcs = dangerous_functions = ['pcntl_alarm','pcntl_fork','pcntl_waitpid','pcntl_wait','pcntl_wifexited','pcntl_wifstopped','pcntl_wifsignaled','pcntl_wifcontinued','pcntl_wexitstatus','pcntl_wtermsig','pcntl_wstopsig','pcntl_signal','pcntl_signal_get_handler','pcntl_signal_dispatch','pcntl_get_last_error','pcntl_strerror','pcntl_sigprocmask','pcntl_sigwaitinfo','pcntl_sigtimedwait','pcntl_exec','pcntl_getpriority','pcntl_setpriority','pcntl_async_signals','error_log','system','exec','shell_exec','popen','proc_open','passthru','link','symlink','syslog','ld','mail']
	vuln = []	
	funcs = open(args.filename, "r").readlines()[0].split(',')
	
	# Check if any of the dangerous functions are not disabled
	print(Fore.MAGENTA + "\nChecking for dangerous PHP functions:" + Fore.RESET)
	for f in dangerous_funcs:
		if f not in funcs:
			vuln.append(f)
	
	# If theres any dangerous functions print them
	if len(vuln) > 0:
		for line in vuln:
			print(Fore.LIGHTGREEN_EX+"[*]" + Fore.RESET + " Vulnerable: " + line)
	else:
		print(Fore.LIGHTRED_EX + "[!]" + Fore.RESET + " No vulnerable functions found...")
		
	
if __name__ == "__main__":
	main()
