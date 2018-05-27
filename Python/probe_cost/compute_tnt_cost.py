#!/usr/bin/env python

# ==============================================================================
# @(#)compute_tnt_cost.py
# @date 2018/04/03
#
# @author Yves Vanaubel
#   Read raw TNT warts files and compute an estimation of the cost of
#   the tunnel revelation.
#   Hypotheses:
#     - 1 traceroute probe sent per hop
#     - 3 traceroute probes for a non responding IP hop.
#     - discovery traces start with a TTL = TTL_ingress - 2
#     - a trace ends at the destination or with 5 non-responding nodes
#     - 1 ping per IP address
#
#   The ouptut file differentiates the probes sent for traces, pings and pings
#   performed for the buddy technique.
#   The different lines represent different categories:
#     > original: probes sent during standard traceroutes with fingerprinting
#     > rev: probes sent during successful tunnel revelations
#     > attempt_norev: probes sent during attempts with no revelation
#     > attempt_tgt_nr: probes sent during attempts with target not reached
#     > attempt_ing_nf: probes sent during attempts with ingress not found
#     > bforce_rev: probes sent during brute force successful tunnel revelations
#     > bforce_attempt_norev: probes sent during brute force attempts with
#       no revelation
#     > bforce_attempt_tgt_nr: probes sent during brute force attempts with
#       target not reached
#     > bforce_attempt_ing_nf: probes sent during brute force attempts with
#       ingress not found
#
# ==============================================================================


# IMPORT
import sys, os, subprocess
from optparse import OptionParser
from os.path import basename

################################################################################

# Update a distribution
def update_distr(distr, key):
  if key in distr:
    distr[key] += 1
  else:
    distr[key] = 1

################################################################################

# Determine the number of probes needed to reveal a tunnel
def analyse_tunnel(rev_nodes, pinged_ips, buddypinged_ips, probes, ie_pair):
  
  # Count the number of LSRs revealed at each step
  stepnds = dict()
  current_step = 1
  
  # The revelation technique is used to know how much probes were sent:
  #  DPR: 1 trace for all the LSRs
  #  BRPR: 1 trace for each LSR
  revtech = ""
  i = len(rev_nodes) - 1
  # Determine the number of probes for each revealed LSR
  for line in reversed(rev_nodes):
    nd = line.split()
    ip = nd[1]
    # Unresponsive node (3 probes sent)
    if ip == "*":
      probes["trace"] += 2 # other probe taken into account later
      if (revtech == "BRPR" or revtech == "BUDDY") and i == 0:
        current_step += 1
    else:
      # Ping probe as IP was still not pinged
      if ip not in pinged_ips:
        pinged_ips.add(ip)
        probes["ping"] += 1
    for elmt in nd:
      if "MPLS" in elmt:
        elmt_split = elmt[1:-1].split(",")
        for subelmt in elmt_split:
          # Node revelation technique
          if (subelmt == "BRPR" or subelmt == "DPR" or
              subelmt == "UNKN" or subelmt == "BUDDY"):
            revtech = subelmt
            # Probes sent for buddy technique
            if subelmt == "BUDDY":
              budip = ie_pair[1]
              if i != len(rev_nodes) - 1:
                budip = rev_nodes[i+1].split()[1]
              if budip not in buddypinged_ips:
                buddypinged_ips.add(budip)
                probes["budping"] += 1
              probes["trace"] += 8
          # Step
          elif "step=" in subelmt:
            current_step = int(subelmt.split("=")[-1])
      # Attempt with buddy technique
      elif "ATTEMPT" in elmt and "BUD" in elmt:
        probes["trace"] += 4
        if ip not in buddypinged_ips:
          buddypinged_ips.add(ip)
          probes["budping"] += 1
    # Update the number of nodes for the current step
    if "BUDDY" not in line:
      update_distr(stepnds, current_step)
    i -= 1
      
  # Count the number of probes
  
  # Last trace that did not reveal nodes anymore
  # Target not reached -> 5 non-responding nodes + 3 hops (ingr + 2 hops before)
  if "TGT-NR" in rev_nodes[0]:
    c = 18
  # Revelation ended with a non-responding hop (no trace run)
  elif rev_nodes[0].split()[1] == "*":
    c = 0
  # Normal trace with no revelation (2 hops + ingr + dst)
  else:
    c = 4

  # Probes for each step
  for step in sorted(stepnds):
    c += stepnds[step] + 4
  probes["trace"] += c

  return


################################################################################

# Determine the number of probes sent for a TNT trace
def analyze_trace(trace, pinged_ips, buddypinged_ips, tested_pairs,
                  original_probes, rev_probes, attempt_probes_norev,
                  attempt_probes_tgt_nr, attempt_probes_ing_nf,
                  bruteforce_rev_probes,
                  bruteforce_attempt_probes_norev,
                  bruteforce_attempt_probes_tgt_nr,
                  bruteforce_attempt_probes_ing_nf):
  if not trace:
    return
  trace_len = len(trace)

  # Will contain the revealed nodes
  rev_nodes = list()
  ingress_ip = ""
  egress_ip = ""

  # Read the trace and count the probes sent
  i = 1
  while i < trace_len:
    line = trace[i]
    line_split = line.split()
    ip = line_split[1]
    
    # Non-revealed node
    if not line.startswith("H"):
      # Non-responding node (3 probes)
      if ip == "*":
        original_probes["trace"] += 3
      # Responding node (1 probe)
      else:
        original_probes["trace"] += 1
        # 1 probe for ping
        if ip not in pinged_ips:
          original_probes["ping"] += 1
          pinged_ips.add(ip)

      # Real tunnel
      if rev_nodes:
        egress_ip = ip
        ie_pair = (ingress_ip, egress_ip)
        # Check only pairs not already considered
        if ie_pair not in tested_pairs:
          tested_pairs.add(ie_pair)
          # Tunnel revealed with brute force
          if "BTFC" in line:
            analyse_tunnel(rev_nodes, pinged_ips, buddypinged_ips,
                           bruteforce_rev_probes, ie_pair)
          # Tunnel revealed thanks to a trigger
          else:
            analyse_tunnel(rev_nodes, pinged_ips, buddypinged_ips,
                           rev_probes, ie_pair)
        ingress_ip = ""
        egress_ip = ""
        del rev_nodes[:]
      # Failed attempt
      elif ip != "*":
        attempt = line_split[-1]
        if "ATTEMPT" in attempt:
          # Find the first IP
          first_line_split = trace[i-1].split()
          if first_line_split[1] == "*":
            first_line_split = trace[i-2].split()
          first_ip = first_line_split[1]
          # The first IP must respond
          if first_ip == "*":
            i += 1
            ingress_ip = ""
            egress_ip = ""
            del rev_nodes[:]
            continue
          ip_pair = (first_ip, ip)
          # Check only pairs not already considered
          if ip_pair not in tested_pairs:
            tested_pairs.add(ip_pair)
            attempt_split = attempt[1:-1].split(",")
            # Real attempt
            if ("FRPLA" in attempt_split or "RTLA" in attempt_split or
                "DUPIP" in attempt_split or "MTTL" in attempt_split):
              attempt_distr = attempt_probes_norev
              # Target not reached
              if "TGT-NR" in attempt_split:
                attempt_distr = attempt_probes_tgt_nr
                attempt_distr["trace"] += 14     # Assume 5 non responding nodes
              # Ingress not found
              elif "ING-NF" in attempt_split:
                attempt_distr = attempt_probes_ing_nf
              # Take into account the buddy technique
              if "BUD" in attempt_split and ip not in buddypinged_ips:
                attempt_distr["budping"] += 1
                buddypinged_ips.add(ip)
                attempt_distr["trace"] += 4      # 4 probes for UDP trace
              attempt_distr["trace"] += 4        # 4 probes for ICMP trace
                
            # Brute force attempt
            else:
              bruteforce_attempt_distr = bruteforce_attempt_probes_norev
              # Target not reached
              if "TGT-NR" in attempt_split:
                bruteforce_attempt_distr = bruteforce_attempt_probes_tgt_nr
                bruteforce_attempt_distr["trace"] += 14 # 5 non responding nodes
              # Ingress not found
              elif "ING-NF" in attempt_split:
                bruteforce_attempt_distr = bruteforce_attempt_probes_ing_nf
              # Take into account the buddy technique
              if "BUD" in attempt_split and ip not in buddypinged_ips:
                bruteforce_attempt_distr["budping"] += 1
                buddypinged_ips.add(ip)
                bruteforce_attempt_distr["trace"] += 4
              bruteforce_attempt_distr["trace"] += 4
    # This node was revealed
    else:
      rev_nodes.append(line)
      if not ingress_ip:
        # Find the ingress IP
        ingr_line_split = trace[i-1].split()
        if ingr_line_split[1] == "*":
          ingr_line_split = trace[i-2].split()
        ingress_ip = ingr_line_split[1]
        if ingress_ip == "*":
          ingress_ip = ""
    i += 1
  return

################################################################################

# Read a warts file, get the traces, and perform the cost analysis
def read_warts_traces(warts_file, original_probes, rev_probes,
                      attempt_probes_norev, attempt_probes_tgt_nr,
                      attempt_probes_ing_nf, bruteforce_rev_probes,
                      bruteforce_attempt_probes_norev,
                      bruteforce_attempt_probes_tgt_nr,
                      bruteforce_attempt_probes_ing_nf):
  trace_file_name = "traces_mpls_tunnels_" + warts_file.split("/")[-1] + ".txt"
  
  # Uncompress if necessary
  current_input_file_name = warts_file
  if warts_file.endswith(".gz"):
    current_input_file_name = basename(warts_file.split(".gz")[0])
    os.system("gunzip -c " + warts_file + " > " + current_input_file_name)

  # Read warts file
  cmd = "sc_tnt -vd1 " + current_input_file_name + " > " + trace_file_name
  os.system(cmd)

  current_trace = list()
  pinged_ips = set()
  buddypinged_ips = set()
  tested_pairs = set()
  trace_file = open(trace_file_name)
  for line in trace_file:
    line = line.strip()
    if line == "" or "#" in line:
      continue

    # New trace
    if "trace" in line:
      analyze_trace(current_trace, pinged_ips, buddypinged_ips, tested_pairs,
                    original_probes, rev_probes, attempt_probes_norev,
                    attempt_probes_tgt_nr, attempt_probes_ing_nf,
                    bruteforce_rev_probes,
                    bruteforce_attempt_probes_norev,
                    bruteforce_attempt_probes_tgt_nr,
                    bruteforce_attempt_probes_ing_nf)
      current_trace = [line]
    # Copy the trace's content
    else:
      current_trace.append(line)

  # Check the last trace of the file
  analyze_trace(current_trace, pinged_ips, buddypinged_ips, tested_pairs,
                original_probes, rev_probes, attempt_probes_norev,
                attempt_probes_tgt_nr, attempt_probes_ing_nf,
                bruteforce_rev_probes, bruteforce_attempt_probes_norev,
                bruteforce_attempt_probes_tgt_nr,
                bruteforce_attempt_probes_ing_nf)
  
  trace_file.close()
  os.system("rm " + trace_file_name)

  # Delete uncompressed file if necessary
  if warts_file.endswith(".gz"):
    os.system("rm " + current_input_file_name)
  return

################################################################################

# Write a distribution into the output file
def write_distr(distr, status, output_file):
  output_file.write(status)
  # Traces
  output_file.write(" " + str(distr["trace"]))
  # Pings
  pings = "0"
  if "ping" in distr:
    pings = str(distr["ping"])
  output_file.write(" " + pings)
  # Buddy pings
  budpings = "0"
  if "budping" in distr:
    budpings = str(distr["budping"])
  output_file.write(" " + budpings)
  output_file.write("\n")
  return

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
  if not len(args)== 2:
    parser.print_help()
    sys.exit(1)

  traces_dir = args[0]
  output_file_name = args[1]

  # Consider all VPs
  cmd = "ls " + traces_dir
  vps = subprocess.check_output(cmd, shell=True).split()

  # Original traces, without any revelation
  original_probes = {"trace": 0, "ping": 0}
  # Probes sent during the revelations with trigger
  rev_probes = {"trace": 0, "ping": 0, "budping": 0}
  # Probes sent without any revelation with trigger
  attempt_probes_norev = {"trace": 0, "budping": 0}
  attempt_probes_tgt_nr = {"trace": 0, "budping": 0}
  attempt_probes_ing_nf = {"trace": 0, "budping": 0}
  # Probes sent during the revelations without trigger
  bruteforce_rev_probes = {"trace": 0, "ping": 0, "budping": 0}
  # Probes sent without any revelation without trigger
  bruteforce_attempt_probes_norev = {"trace": 0, "budping": 0}
  bruteforce_attempt_probes_tgt_nr = {"trace": 0, "budping": 0}
  bruteforce_attempt_probes_ing_nf = {"trace": 0, "budping": 0}

  for vp in vps:
    current_dir = traces_dir + "/" + vp
    cmd = "ls " + current_dir
    warts_files = subprocess.check_output(cmd, shell=True).split()
  
    # Read each warts file for the VP and analyze thz cost
    for warts_file in warts_files:
      read_warts_traces(current_dir + "/" + warts_file,
                        original_probes, rev_probes,
                        attempt_probes_norev,
                        attempt_probes_tgt_nr,
                        attempt_probes_ing_nf,
                        bruteforce_rev_probes,
                        bruteforce_attempt_probes_norev,
                        bruteforce_attempt_probes_tgt_nr,
                        bruteforce_attempt_probes_ing_nf)

  # Output file
  output_file = open(output_file_name, 'w')
  output_file.write("#status trace ping budping\n")
  write_distr(original_probes, "original", output_file)
  write_distr(rev_probes, "rev", output_file)
  write_distr(attempt_probes_norev, "attempt_norev", output_file)
  write_distr(attempt_probes_tgt_nr, "attempt_tgt_nr", output_file)
  write_distr(attempt_probes_ing_nf, "attempt_ing_nf", output_file)
  write_distr(bruteforce_rev_probes, "bforce_rev", output_file)
  write_distr(bruteforce_attempt_probes_norev,
              "bforce_attempt_norev", output_file)
  write_distr(bruteforce_attempt_probes_tgt_nr,
              "bforce_attempt_tgt_nr", output_file)
  write_distr(bruteforce_attempt_probes_ing_nf,
              "bforce_attempt_ing_nf", output_file)
  output_file.close()
  os.system("column -t " + output_file_name + " > tmp_col.txt")
  os.system("mv tmp_col.txt " + output_file_name)
  
  return

if __name__ == '__main__':
	sys.exit(main())
