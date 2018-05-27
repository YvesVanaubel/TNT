#!/usr/bin/env python

################################################################################
#   Author : Yves Vanaubel                                                     #
#   Date : 2018/05/24                                                          #
#                                                                              #
#   Read IP addresses from TNT warts files that are not trace destinations.    #
#   The IP addresses are writen 1 per line into an output file.                #
################################################################################

# IMPORT
import sys, re, os
import subprocess
from optparse import OptionParser

# Regex patterns
ip_pat = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
trace_re = re.compile(ip_pat + "\sto\s(" + ip_pat + ")")

################################################################################

# Find the destination of a trace based on the first line
# If not found, return *
def get_trace_destination(trace_first_line):
  dst = trace_re.search(trace_first_line)
  if not dst:
    return "*"
  return dst.group(1)

################################################################################

def main():
  
  usage = ("usage: %prog <vps_warts_dir> <output_file>\n"
         "  where:\n"
         "      - vps_warts_dir is the directory containing the traces "
         "collected by each VP during the campaign.\n"
         "        Format: <vps_warts_dir>/<VP>/<VP_cycle>.warts\n"
         "      - output_file is the output file.\n")
  parser = OptionParser(usage=usage)

  (options, args) = parser.parse_args()

  # Check arg number
  if not len(args) == 2:
    parser.print_help()
    sys.exit(1)
  run(args)

################################################################################

# Read a warts file and get traces. A trace is a list of traceroute lines.
def read_warts_traces(warts_file, ips):
  tmp_trace_file_name = "tmp_traces_mpls_tunnels.txt"
  
  # Uncompress files if necessary
  current_input_file_name = warts_file
  if warts_file.endswith(".gz"):
    current_input_file_name = basename(warts_file.split(".gz")[0])
    os.system("gunzip -c " + warts_file + " > " + current_input_file_name)
  
  cmd = "sc_tnt -d1 " + current_input_file_name + " > " + tmp_trace_file_name
  os.system(cmd)

  tmp_trace_file = open(tmp_trace_file_name)
  dst = ""
  for line in tmp_trace_file:
    line = line.strip()
    if line == "" or "#" in line:
      continue
    
    # New trace
    if "trace" in line:
      dst = get_trace_destination(line)
    # Copy the trace's content
    else:
      ip = line.split()[1]
      if ip != "*" and ip != dst:
        ips.add(ip)
          
  tmp_trace_file.close()
  os.system("rm " + tmp_trace_file_name)
  
  # Delete uncompressed file if necessary
  if warts_file.endswith(".gz"):
    os.system("rm " + current_input_file_name)

################################################################################

# Read IP addresses
def run(args):

  vps_warts_dir = args[0]
  output_file = args[1]
  
  # Read warts files and get IP addresses
  ips = set()
  # Consider all the VPs
  cmd = "ls " + vps_warts_dir
  vps = subprocess.check_output(cmd, shell=True).split()
  for vp in vps:
    current_dir = vps_warts_dir + "/" + vp
    cmd = "ls " + current_dir
    warts_files = subprocess.check_output(cmd, shell=True).split()
    
    # Read each warts file for the VP and find IP addresses
    for warts_file in warts_files:
      read_warts_traces(current_dir + "/" + warts_file, ips)

  # Output the IP addresses
  output_file = open(output_file, 'w')
  for ip in ips:
    output_file.write(ip + "\n")
  output_file.close()
  return

if __name__ == '__main__':
    sys.exit(main())
