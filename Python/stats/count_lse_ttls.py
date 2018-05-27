#!/usr/bin/env python

# ==============================================================================
# @(#)count_lse_ttls.py
# @date 2018/04/03
#
# @author Yves Vanaubel
#   Compute the distribution of LSE TTL values (only for top of the label stack)
#   All occurences of LSE TTLs are considered as they appear in the different
#   traces. No kind of sorting is applied.
# ==============================================================================


# IMPORTS
import sys, os, re, subprocess
from optparse import OptionParser
from os.path import basename

# Regex patterns
ip_pat = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
trace_re = re.compile(ip_pat + "\sto\s(" + ip_pat + ")")

################################################################################

# Find the destination of a trace based on the first line.
# If not found, return *
def get_trace_destination(trace_first_line):
  dst = trace_re.search(trace_first_line)
  if not dst:
    return "*"
  return dst.group(1)

################################################################################

# Read a line and store the mTTL value for top labels, if any.
def read_line(line, mttls_distr):
  if line == "":
    return

  line_split = line.split()
  nelmt = len(line_split)

  # IP address
  ip = line_split[1]

  # Non responding node
  if ip == "*":
    return

  for i in range(4, nelmt):
    elmt = line_split[i]
    # LSE TTL (for top label only)
    if "mTTL=" in elmt:
      mttl = elmt.split("=")[-1]
      if mttl in mttls_distr:
        mttls_distr[mttl] += 1
      else:
        mttls_distr[mttl] = 1
      return
  return

################################################################################

# Read a warts file, get traces, and update the LSE TTL distribution.
# A trace is a list of traceroute lines.
def read_warts_traces(warts_file, mttls_distr):
  trace_file_name = "traces_mpls_tunnels_" + warts_file.split("/")[-1] + ".txt"
  
  # Uncompress if necessary
  current_input_file_name = warts_file
  if warts_file.endswith(".gz"):
    current_input_file_name = basename(warts_file.split(".gz")[0])
    os.system("gunzip -c " + warts_file + " > " + current_input_file_name)

  cmd = "sc_tnt -d1 " + current_input_file_name + " > " + trace_file_name
  os.system(cmd)

  # Read file
  trace_file = open(trace_file_name)
  ntraces = 0
  for line in trace_file:
    line = line.strip()
    if line == "" or "#" in line:
      continue

    # New trace
    if "trace" in line:
      ntraces += 1
    # Analyze a line
    else:
      read_line(line, mttls_distr)

  trace_file.close()
  os.system("rm " + trace_file_name)

  # Delete uncompressed file if necessary
  if warts_file.endswith(".gz"):
    os.system("rm " + current_input_file_name)
  
  return ntraces

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
  #Check arg number
  if not len(args)== 2:
    parser.print_help()
    sys.exit(1)

  traces_dir = args[0]
  output_file_name = args[1]

  # Consider all VPs
  cmd = "ls " + traces_dir
  vps = subprocess.check_output(cmd, shell=True).split()
  ntraces = 0
  mttls_distr = dict()
  for vp in vps:
    current_dir = traces_dir + "/" + vp
    cmd = "ls " + current_dir
    warts_files = subprocess.check_output(cmd, shell=True).split()
  
    # Read each warts file for the VP and find LSE TTLs
    for warts_file in warts_files:
      ntraces += read_warts_traces(current_dir + "/" + warts_file, mttls_distr)

  # Output file
  output_file = open(output_file_name, 'w')
  output_file.write("#LSE_TTL #nocc\n")
  for ttl in sorted(mttls_distr):
    output_file.write(ttl + " " + str(mttls_distr[ttl]) + "\n")
  output_file.close()

  # Arrange ouptut file
  os.system("column -t " + output_file_name + " > tmp_col.txt")
  os.system("mv tmp_col.txt " + output_file_name)

  # Print the number of traces in the campaign
  print "Number of traces: " + str(ntraces)
  return

if __name__ == '__main__':
	sys.exit(main())
