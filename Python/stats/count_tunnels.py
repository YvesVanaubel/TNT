#!/usr/bin/env python

# ==============================================================================
# @(#)count_tunnels.py
# @date 2018/04/06
#
# @author Yves Vanaubel
#   Count the different types of tunnels (IP based):
#     - EXPLICIT (EXP)
#     - IMPLICIT (IMP)
#     - OPAQUE (OPA)
#     - INVISIBLE (INV)
#     - HET (heterogeneous, means a tunnel with some LSRs having a given type,
#       and others another type (e.g. explicit tunnel with some implicit LSRs)
#     - CHA (chameleon, a tunnel seen multiple times, with different types
#       (e.g. once the tunnel is EXP, later it is seen as IMP))
#   Get also the tunnel distribution according to the triggers and the
#   revelation techniques.
#
# Different output files are generated:
#   - A file named tunnel_count.txt containing the tunnel distribution according
#     to their type:
#         > ALL       all tunnels
#         > EXP       all explicit tunnels
#         > IMP       all implicit tunnels
#         > IMP_QTTL  implicit tunnels with QTTL indicator
#         > IMP_UTURN implicit tunnels with UTURN indicator
#         > IMP_BOTH  implicit tunnels with QTTL and UTURN indicators
#         > OPA       all opaque tunnels
#         > OPA_REV   opaque tunnels whose content was revealed
#         > OPA_NOREV opaque tunnels whose content was not revealed
#         > INV       all invisible tunnels
#         > HET       all heterogeneous tunnels
#         > CHA       all chameleon tunnels
#   - A file named opaque_revtech.txt containing the revealed opaque tunnel
#     distribution according to their revelation technique
#   - A file named inv_triggers.txt containing the invisible tunnel
#     distribution according to their triggers:
#         > DUPIP         all tunnels with DUPIP trigger
#         > DUPIPBUD      tunnels with DUPIP trigger and buddy technique
#         > DUPIPNOBUD    tunnels with DUPIP trigger and no buddy technique
#         > <trig>        tunnels revealed thanks to trigger trig
#         > <trig1_trig2> tunnels revealed thanks to trigger trig1 in some cases
#                         and thanks to trigger trig2 in other cases
#   - Multiple files named inv_<trig(s)>_revtech.txt containing the invisible
#     tunnel distribution for the specific trigger(s) trig(s) (appearing
#     in the file name) according to the revelation techniques:
#         > ALLBUDDY            tunnels whose LSRs were all revealed with the
#                               buddy technique.
#         > <revtech>           tunnels whose content was revealed with the
#                               revelation technique revtech
#         > <revtech1_revtech2> tunnels whose content was revealed with the
#                               revelation technique revtech1 in some cases, and
#                               with the technique revtech2 in other cases
# ==============================================================================


# IMPORT
import sys, os
from optparse import OptionParser
from collections import defaultdict

################################################################################

def main():
  usage = ("usage: %prog <tunnels_file> <output_dir> <vp_name>\n"
           "  where:\n"
           "      - tunnels_file is the file containing all the tunnels"
           " to be classified.\n"
           "      - output_dir is the output directory.\n"
           "      - vp_name is the name of the VP to consider. 'all' means"
           " all VPs.\n")
  parser = OptionParser(usage=usage)

  (options, args) = parser.parse_args()
  # Check arg number
  if not len(args)== 3:
    parser.print_help()
    sys.exit(1)

  tunnels_file = args[0]
  output_dir = args[1]
  tgt_vp = args[2]

  os.system("rm -r " + output_dir + "; mkdir " + output_dir)

  # Structures
  types = ["EXP", "IMP", "OPA", "INV", "HET", "CHA"]
  all_tuns = set()
  # Tunnels classified according to their type
  type2tuns = defaultdict(set)
  # Trigger and revelation technique for each tunnel
  tun2trig_revtechs = defaultdict(set)
  # Tunnel with at least one LSR revealed with the buddy technique
  buddytuns = set()
  # Initialize the type structure
  for t in types:
    type2tuns[t] = set()

  # Read the input file
  input_file = open(tunnels_file)
  for line in input_file:
    line = line.strip()
    # Empty line
    if line == "" or "#" in line:
      continue
    
    # Get needed fields in line
    line_split = line.split()
    vp_name = line_split[0]
    if tgt_vp != "all" and vp_name != tgt_vp:
      continue
    tun_type = line_split[1]
    tun_trig = line_split[2]
    tun_revtech = line_split[3]
    tun_buddy = line_split[4]
    ip_tun = list()

    # Get the tunnel in terms of IP addresses
    comp_tunnel = line.split("=")[2]
    tun_split = comp_tunnel.split()
    for hop in tun_split:
      hop_split = hop.split(":")
      ip = hop_split[0]
      ip_tun.append(ip)
    tunnel = " ".join(ip_tun)
    all_tuns.add(tunnel)

    # Check if tunnel already seen previously
    tunseen = False
    for t in types:
      if tunnel in type2tuns[t]:
        if t != tun_type and t != "CHA":
          type2tuns[t].remove(tunnel)
          type2tuns["CHA"].add(tunnel)
        tunseen = True

    # Add to the right sets
    if not tunseen:
      type2tuns[tun_type].add(tunnel)
    if tun_buddy != "-":
      buddytuns.add(tunnel)
    if tun_trig != "-":
      trig_revtech = (tun_trig, tun_revtech)
      tun2trig_revtechs[tunnel].add(trig_revtech)
  input_file.close()


  # Write the output files
  
  # 1. Tunnel count according the type
  output_file_name = output_dir + "/tunnel_count.txt"
  output_file = open(output_file_name, 'w')
  output_file.write("#Type ntun\n")
  output_file.write("ALL " + str(len(all_tuns)) + "\n" )
  for t in types:
    output_file.write(t + " " + str(len(type2tuns[t])) + "\n")
    # For implicit tunnels, separate according to QTTL and UTURN
    if t == "IMP":
      count = {"QTTL": 0, "UTURN": 0, "MULTI": 0}
      for tunnel in type2tuns[t]:
        for trig_revtech in tun2trig_revtechs[tunnel]:
          trig = trig_revtech[0]
          count[trig] += 1
      output_file.write("IMP_QTTL " + str(count["QTTL"]) + "\n")
      output_file.write("IMP_UTURN " + str(count["UTURN"]) + "\n")
      output_file.write("IMP_BOTH " + str(count["MULTI"]) + "\n")
    # For opaque tunnel, separate according to LSRs were revealed or not
    elif t == "OPA":
      count = {"REV": 0, "NOREV": 0}
      for tunnel in type2tuns[t]:
        for trig_revtech in tun2trig_revtechs[tunnel]:
          revtech = trig_revtech[1]
          if revtech == "-":
            count["NOREV"] += 1
          else:
            count["REV"] += 1
      output_file.write("OPA_REV " + str(count["REV"]) + "\n")
      output_file.write("OPA_NOREV " + str(count["NOREV"]) + "\n")
  output_file.close()
  os.system("column -t " + output_file_name + " > tmp_col.txt; mv tmp_col.txt " + output_file_name)

  # 2. Opaque revelation techniques
  revtech2ntun = defaultdict()
  for tunnel in type2tuns["OPA"]:
    cur_revtechs = set()
    for trig_revtech in tun2trig_revtechs[tunnel]:
      revtech = trig_revtech[1]
      if revtech != "-":
        cur_revtechs.add(revtech)
    revtech = "_".join(list(sorted(cur_revtechs)))
    # Update distribution
    if revtech:
      if revtech in revtech2ntun:
        revtech2ntun[revtech] += 1
      else:
        revtech2ntun[revtech] = 1
  output_file_name = output_dir + "/opaque_revtech.txt"
  output_file = open(output_file_name, 'w')
  output_file.write("#revtech ntun\n")
  for revtech in sorted(revtech2ntun):
    output_file.write(revtech + " " + str(revtech2ntun[revtech]) + "\n")
  output_file.close()
  # Arrange output file
  os.system("column -t " + output_file_name + " > tmp_col.txt")
  os.system("mv tmp_col.txt " + output_file_name)

  # 3. Triggers and revelation techniques for invisible tunnels
  trig2revtech2ntun = defaultdict(lambda: defaultdict(set))
  trig2ntun = {"DUPIPBUD": 0, "DUPIPNOBUD": 0}
  for tunnel in type2tuns["INV"]:
    cur_revtechs = set()
    cur_triggers = set()
    for trig_revtech in tun2trig_revtechs[tunnel]:
      trig = trig_revtech[0]
      revtech = trig_revtech[1]
      cur_triggers.add(trig)
      cur_revtechs.add(revtech)
    # Combine multiple triggers and revelation techniques if necessary
    revtech = "_".join(list(sorted(cur_revtechs)))
    trigger = "_".join(list(sorted(cur_triggers)))
    # Update distributions
    # According to the trigger
    if trigger in trig2ntun:
      trig2ntun[trigger] += 1
    else:
      trig2ntun[trigger] = 1
    # Check if the buddy technique was needed
    if trigger == "DUPIP":
      if tunnel in buddytuns:
        trig2ntun["DUPIPBUD"] += 1
      else:
        trig2ntun["DUPIPNOBUD"] += 1
    # According to the trigger and the revelation technique
    if revtech in trig2revtech2ntun[trigger]:
      trig2revtech2ntun[trigger][revtech] += 1
    else:
      trig2revtech2ntun[trigger][revtech] = 1

  # Output the trigger results
  output_file_name = output_dir + "/inv_triggers.txt"
  output_file = open(output_file_name, 'w')
  output_file.write("#trigger ntun\n")
  for trigger in sorted(trig2ntun):
    output_file.write(trigger + " " + str(trig2ntun[trigger]) + "\n")
  output_file.close()
  os.system("column -t " + output_file_name + " > tmp_col.txt")
  os.system("mv tmp_col.txt " + output_file_name)

  # Output the trigger and revelation technique results
  for trigger in sorted(trig2revtech2ntun):
    output_file_name = output_dir + "/inv_" + trigger + "_revtech.txt"
    output_file = open(output_file_name, 'w')
    output_file.write("#revtech ntun\n")
    for revtech in sorted(trig2revtech2ntun[trigger]):
      output_file.write(revtech + " " +
                        str(trig2revtech2ntun[trigger][revtech]) + "\n")
    output_file.close()
    os.system("column -t " + output_file_name + " > tmp_col.txt")
    os.system("mv tmp_col.txt " + output_file_name)

  return

if __name__ == '__main__':
	sys.exit(main())
