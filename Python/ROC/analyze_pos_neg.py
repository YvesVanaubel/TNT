#!/usr/bin/env python

# ==============================================================================
# @(#)analyze_pos_neg.py
# @date 2018/03/27
#
# @author Yves Vanaubel
#   Read raw TNT warts files obtained during a brute force (BTFC) campaign and
#   perform a true/false positives/negatives analysis based on the triggers, the
#   revelation attempts, and the revealed tunnels.
#   The algorithm classifies tested IP pairs (possible entry/exit(/DUPIP) points
#   of an MPLS tunnel) into one of the following categories:
#     0. True Positive [TP] (trigger seen, tunnel revealed)
#         => (INGR, EGR) + DUPIP/FRPLA/RTLA/MTTL
#     1. False Negative [FN] (no trigger seen, tunnel revealed)
#         => (INGR, EGR) + BTFC
#     2. False Positive [FP] (trigger seen, nothing revealed)
#         => no (INGR,EGR) + DUPIP/FRPLA/RTLA/MTTL + ATTEMPT NTH-RV
#     3. Inconclusive Positive [IP] (trigger seen, revelation could not be
#        performed)
#         => no (INGR,EGR) + DUPIP/FRPLA/RTLA/MTTL + ATTEMPT TGT-NR/ING-NF
#     4. True Negative [TN] (no trigger seen, nothing revealed)
#         => no (INGR,EGR) + ATTEMPT NTH-RV
#     5. Inconclusive Negative [IN] (no trigger seen, revelation could not be
#        performed)
#         => no (INGR,EGR) + ATTEMPT TGT-NR/ING-NF
#
#   Remarks:
#   > TGT-NR means target not reached
#   > ING-NF means ingress not found
#   > NTH-RV means nothing revealed
#   > TNT writes ATTEMPT in its output only if it failed (no IP was revealed).
#     Successful attempts that lead to a revelation are not written.
#   > An IP pair may be found in multiple classes
#   > The analysis is performed per VP, and also for all VPs together
# ==============================================================================


# IMPORTS
import sys, os, subprocess, copy
from optparse import OptionParser
from collections import defaultdict
from os.path import basename

################################################################################

# Read a trace line and store the interesting fields into an list.
# Output fields order:
#   0. IP address
#   1. TTLs <TE,ER>
#   2. Node Type (ING, EGR, LSR) [list if node ingress and egress]
#   3. Tun. Type (INV, EXP, IMP, OPA) [list if node in two difrnt tunnels]
#   4. Tun. Trigger (RTLA, FRPLA, DUPIP, MTTL, QTTL, UTURN, BTFC)
#      [list if node in two difrnt tunnels]
#   5. Attempt result (NTH-RV, ING-NF, TGT-NR, or -)
#   6. Attempt trigger (RTLA, FRPLA, DUPIP, MTTL, or -)
def read_line(line):
  line_fields = list()
  # Empty line
  if line == "":
    for i in range(0, 6):
      line_fields.append("-")
    for i in range(2, 5):
      line_fields[i] = list()
    return line_fields

  line_split = line.split()
  nelmt = len(line_split)

  # IP address
  ip = line_split[1]
  line_fields.append(ip)

  # Non responding node
  if ip == "*":
    for i in range(1, 6):
      line_fields.append("-")
    for i in range(2, 5):
      line_fields[i] = list()
    return line_fields

  # Other elements may be optional
  nodetype = list()
  tuntype = list()
  tuntrig = list()
  attempttrig = "-"
  attemptres = "-"

  for i in range(4, nelmt):
    elmt = line_split[i]
    # TE and ER TTLs
    if "rTTLs=" in elmt:
      ttls = elmt.split("=")[-1]
    elif "MPLS" in elmt:
      elmt_split = elmt[1:-1].split(",")
      for subelmt in elmt_split:
        # Tunnel type
        if (subelmt == "EXP" or subelmt == "IMP" or
            subelmt == "INV" or subelmt == "OPA"):
          tuntype.append(subelmt)
        # Node type
        elif (subelmt == "LSR" or subelmt == "ING" or subelmt == "EGR"):
          nodetype.append(subelmt)
        # Tunnel trigger
        elif (subelmt == "FRPLA" or subelmt == "RTLA" or subelmt == "DUPIP" or
              subelmt == "QTTL" or subelmt == "UTURN" or subelmt == "MTTL" or
              subelmt == "BTFC"):
          tuntrig.append(subelmt)
    elif "ATTEMPT" in elmt:
      elmt_split = elmt[1:-1].split(",")
      for subelmt in elmt_split:
        if (subelmt == "NTH-RV" or subelmt == "ING-NF" or subelmt == "TGT-NR"):
          attemptres = subelmt
        # Attempt trigger
        elif (subelmt == "FRPLA" or subelmt == "RTLA" or
              subelmt == "DUPIP" or subelmt == "MTTL"):
          attempttrig = subelmt

  line_fields.append(ttls)
  line_fields.append(nodetype)
  line_fields.append(tuntype)
  line_fields.append(tuntrig)
  line_fields.append(attemptres)
  line_fields.append(attempttrig)
  return line_fields

################################################################################

# Add an IP pair to a distribution according to its class and trigger
def add_ip_pair(ip_pair, class_nb, trigger, trig2ip_pair2cat):
  triggers = ["all"]
  if trigger != "-" and trigger != "BTFC":
    triggers.append(trigger)
  
  for t in triggers:
    if ip_pair not in trig2ip_pair2cat[t]:
      trig2ip_pair2cat[t][ip_pair] = [0,0,0,0,0,0]
    trig2ip_pair2cat[t][ip_pair][class_nb] += 1
  return

################################################################################

# Get the invisible trigger in a set of triggers
def get_inv_trigger(triggers):
  if not triggers:
    return ""

  ntrig = len(triggers)
  if ntrig > 2:
    return ""
  elif ntrig == 1:
    return triggers[0]
  else:
    trig = triggers[0]
    if trig == "QTTL" or trig == "UTURN":
      return triggers[1]
    return trig

################################################################################

# Analyze a trace.
def analyze_trace(trace, vp_trig2ip_pair2cat, global_trig2ip_pair2cat):
  
  # Emtpy trace
  if not trace:
    return

  # Get the trace length
  trace_len = len(trace) - 1

  # IP addresses to classify (ip1 is entry, ip2 is exit)
  ip1 = ""
  ip2 = ""

  # Read the trace
  trigger = ""
  prevline = ""
  prevline_elmts = ""
  firstline = ""
  firstline_elmts = ""
  secline = ""
  secline_elmts = ""
  i = 1
  while i < trace_len+1:
    # Get lines for the analysis (lines i-1 (prev), i (first), and i+1 (sec))
    firstline = trace[i]
    if i == 1:
      firstline_elmts = read_line(firstline)
      prevline_elmts = read_line(prevline)
    else:
      prevline = trace[i-1]
      prevline_elmts = copy.deepcopy(firstline_elmts)
      firstline_elmts = copy.deepcopy(secline_elmts)
    secline = ""
    if i < trace_len:
      secline = trace[i+1]
    secline_elmts = read_line(secline)

    # Check invisible status of previous node
    prev_inv = False
    if "INV" in prevline_elmts[3] or prevline.startswith("H"):
      prev_inv = True

    # Analysis
    
    # If an attempt is observed outside an invisible tunnel
    if secline_elmts[5] != "-" and not secline.startswith("H"):
      # ip1 and ip2 should be emtpy, otherwise previous analysis did not end
      if ip1 or ip2:
        ip1 = ""
        ip2 = ""
        i += 1
        continue
      # Get the entry and exit points
      if firstline_elmts[0] == "*":
        ip1 = prevline_elmts[0]
      else:
        ip1 = firstline_elmts[0]
      ip2 = secline_elmts[0]

      # IP pair
      ip_pair = (ip1, ip2)

      # Classification
      # Trigger
      trigger = secline_elmts[6]
      if trigger != "-":
        # Trigger seen, nothing revealed => class 2
        if secline_elmts[5] == "NTH-RV":
          add_ip_pair(ip_pair, 2, trigger, vp_trig2ip_pair2cat)
          add_ip_pair(ip_pair, 2, trigger, global_trig2ip_pair2cat)
        # Trigger seen, target not reached or ingress not found => class 3
        else:
          add_ip_pair(ip_pair, 3, trigger, vp_trig2ip_pair2cat)
          add_ip_pair(ip_pair, 3, trigger, global_trig2ip_pair2cat)
      # No trigger
      else:
        # No trigger seen, nothing revealed => class 4
        if secline_elmts[5] == "NTH-RV":
          add_ip_pair(ip_pair, 4, trigger, vp_trig2ip_pair2cat)
          add_ip_pair(ip_pair, 4, trigger, global_trig2ip_pair2cat)
        # No trigger seen, target not reached or ingress not found => class 5
        else:
          add_ip_pair(ip_pair, 5, trigger, vp_trig2ip_pair2cat)
          add_ip_pair(ip_pair, 5, trigger, global_trig2ip_pair2cat)
      # Reset entry and exit
      ip1 = ""
      ip2 = ""

    # Find the entry node
    if ("INV" in firstline_elmts[3] and
        "ING" in firstline_elmts[2] and not prev_inv):
      ip1 = firstline_elmts[0]
      i += 1
      continue
    elif (firstline_elmts[0] == "*" and not firstline.startswith("H") and
          secline.startswith("H")):
      ip1 = prevline_elmts[0]
      i += 1
      continue
    # Previous hop is LSR implicit or ingress opaque
    elif (not ip1 and firstline.startswith("H")):
      ip1 = prevline_elmts[0]
      i += 1
      continue

    # An entry point must have been found
    if not ip1:
      i += 1
      continue

    # Find the egress
    if (("INV" in firstline_elmts[3] or "OPA" in firstline_elmts[3]) and
        "EGR" in firstline_elmts[2] and prev_inv):
      # Egress duplicate IP
      if firstline.startswith("H") and "DUPIP" in firstline_elmts[4]:
        ip2 = secline_elmts[0]
        trigger = "DUPIP"
      else:
        ip2 = firstline_elmts[0]
        trigger = get_inv_trigger(firstline_elmts[4])
    elif not firstline.startswith("H"):
      # Next hop is LSR implicit
      if ("IMP" in firstline_elmts[3] or
          ("LSR" in firstline_elmts[2] and not firstline_elmts[4])):
        ip2 = firstline_elmts[0]
        trigger = get_inv_trigger(firstline_elmts[4])
      # Duplicate IP address with non responding egress
      elif firstline_elmts[0] == secline_elmts[0]:
        ip2 = firstline_elmts[0]
        trigger = "DUPIP"
    
    # Update the distributions
    if ip1 and ip2:
      ip_pair = (ip1, ip2)
      # No trigger, revelation => class 1
      if trigger == "BTFC":
        add_ip_pair(ip_pair, 1, trigger, vp_trig2ip_pair2cat)
        add_ip_pair(ip_pair, 1, trigger, global_trig2ip_pair2cat)
      # Trigger, revelation => class 0
      else:
        add_ip_pair(ip_pair, 0, trigger, vp_trig2ip_pair2cat)
        add_ip_pair(ip_pair, 0, trigger, global_trig2ip_pair2cat)
      # Only one revelation per trace
      return

    # The current node should have been revealed
    if not firstline.startswith("H"):
      ip1 = ""
      ip2 = ""
    i += 1

  return

################################################################################

# Output the different classes for each IP pair
def output_classes(trig2ip_pair2cat, output_dir):

  for trig in trig2ip_pair2cat:
    output_file_name = output_dir + "/" + trig + ".txt"
    output_file = open(output_file_name, 'w')
    output_file.write("#IP_pair TP FN FP IP TN IN\n")
    # Write each IP pair
    for ip_pair in trig2ip_pair2cat[trig]:
      ip1 = ip_pair[0]
      ip2 = ip_pair[1]
      output_file.write("<" + ip1 + "," + ip2 + ">")
      for cat in trig2ip_pair2cat[trig][ip_pair]:
        output_file.write(" " + str(cat))
      output_file.write("\n")
    output_file.close()
    # Arrange the output file columns
    os.system("column -t " + output_file_name + " > tmp_col.txt")
    os.system("mv tmp_col.txt " + output_file_name)
  return

################################################################################

# Read a warts file, get traces, and perform the true/false positives/negatives
# analysis. A trace is a list of traceroute lines.
def read_warts_traces(warts_file, vp_output_dir, vp_name,
                      global_trig2ip_pair2cat, vp_trig2ip_pair2cat):
  trace_file_name = "traces_mpls_tunnels_" + warts_file.split("/")[-1] + ".txt"
  
  # Uncompress if necessary
  current_input_file_name = warts_file
  if warts_file.endswith(".gz"):
    current_input_file_name = basename(warts_file.split(".gz")[0])
    os.system("gunzip -c " + warts_file + " > " + current_input_file_name)

  cmd = "sc_tnt -vd1 " + current_input_file_name + " > " + trace_file_name
  os.system(cmd)

  # Read traces
  current_trace = list()
  current_dst = ""
  trace_file = open(trace_file_name)
  for line in trace_file:
    line = line.strip()
    if line == "" or "#" in line:
      continue

    # New trace
    if "trace" in line:
      analyze_trace(current_trace, vp_trig2ip_pair2cat, global_trig2ip_pair2cat)
      current_trace = [line]
    # Copy the trace's content
    else:
      current_trace.append(line)

  # Check the last trace of the file
  analyze_trace(current_trace, vp_trig2ip_pair2cat, global_trig2ip_pair2cat)

  trace_file.close()
  os.system("rm " + trace_file_name)

  # Delete uncompressed file if necessary
  if warts_file.endswith(".gz"):
    os.system("rm " + current_input_file_name)

################################################################################

def main():
  usage = ("usage: %prog <vps_warts_dir> <output_dir>\n"
           "  where:\n"
           "      - vps_warts_dir is the directory containing the traces"
           " collected by each VP during the campaign.\n"
           "        Format: <vps_warts_dir>/<ij>/<VP>/<VP>-<ij>.warts\n"
           "      - output_dir is the output directory.\n")
  parser = OptionParser(usage=usage)

  (options, args) = parser.parse_args()
  #Check arg number
  if not len(args)== 2:
    parser.print_help()
    sys.exit(1)

  traces_dir = args[0]
  output_dir = args[1]

  global_trig2ip_pair2cat = defaultdict(lambda:defaultdict(list))
  for type in ["all", "FRPLA", "RTLA", "DUPIP", "MTTL"]:
    global_trig2ip_pair2cat[type] = defaultdict(list)

  # Output dir
  os.system("rm -r " + output_dir + "; mkdir " + output_dir)
  os.system("mkdir " + output_dir + "/vps")

  # Consider all VPs
  cmd = "ls " + traces_dir
  vps = subprocess.check_output(cmd, shell=True).split()
  for vp in vps:
    cmd = "ls " + traces_dir + "/" + vp
    warts_files = subprocess.check_output(cmd, shell=True).split()
    vp_output_dir = output_dir + "/vps/" + vp
    os.system("mkdir " + vp_output_dir)
    
    # Initialize the per VP distribution structure
    vp_trig2ip_pair2cat = defaultdict(lambda:defaultdict(list))
    for type in ["all", "FRPLA", "RTLA", "DUPIP", "MTTL"]:
      vp_trig2ip_pair2cat[type] = defaultdict(list)
    
    # Read each warts file for the VP and find tunnels
    for warts_file in warts_files:
      read_warts_traces(traces_dir + "/" + vp + "/" + warts_file,
                        vp_output_dir, vp, global_trig2ip_pair2cat,
                        vp_trig2ip_pair2cat)
    # Output for the current VP
    output_classes(vp_trig2ip_pair2cat, vp_output_dir)
  
  # Output the global stats
  output_classes(global_trig2ip_pair2cat, output_dir)
  return

if __name__ == '__main__':
	sys.exit(main())
