/*
 * sc_tnt: Driver to reveal MPLS tunnels on the path to a destination
 *
 * $Id: sc_tnt.c,v 5.0 2018/05/23 16:54:34 mjl Exp $
 *
 *		   Yves Vanaubel
 *		   http://www.montefiore.ulg.ac.be/~bdonnet/mpls/contact.html
 *
 * This program was written based on the other drivers for Scamper
 * written by Matthew Luckie
 *
 * Copyright (C) 2017-2018 Yves Vanaubel
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef lint
static const char rcsid[] =
"$Id: sc_tnt.c,v 5.0 2018/05/23 16:54:34 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "config.h"
#include "scamper_addr.h"
#include "scamper_list.h"
#include "ping/scamper_ping.h"
#include "trace/scamper_trace.h"
#include "scamper_icmpext.h"
#include "scamper_file.h"
#include "mjl_list.h"
#include "mjl_splaytree.h"
#include "mjl_heap.h"
#include "mjl_prefixtree.h"
#include "utils.h"

#define OPT_HELP                0x0001
#define OPT_ADDRFILE            0x0002
#define OPT_OUTFILE             0x0004
#define OPT_PORT                0x0008
#define OPT_LOG                 0x0010
#define OPT_UNIX                0x0020
#define OPT_DUMP                0x0040
#define OPT_IPADDR              0x0080
#define OPT_METHOD              0x0100
#define OPT_COUNT               0x0200
#define OPT_DAEMON              0x0400
#define OPT_STARTTTL            0x0800
#define OPT_FRPLATHRESH         0x1000
#define OPT_RTLATHRESH          0x2000
#define OPT_DISPLAY             0x4000
#define OPT_BRUTEFORCE          0x8000

#define DISPLAY_STAND           0x00
#define DISPLAY_VERB            0x01

#define BRUTE_FORCE_DIS         0x00
#define BRUTE_FORCE_ENA         0x01

#define PROB_MODE_TRACE         0x00
#define PROB_MODE_PING          0x01
#define PROB_MODE_PING_BUDDY    0x02
#define PROB_MODE_TRACE_BUDDY   0x03

#define TEST_TRACE              0x00
#define TEST_TRACE_DISC         0x01
#define TEST_PING               0x02
#define TEST_PING_BUDDY         0x03

#define METHOD_ICMP             0x00
#define METHOD_UDP              0x01

#define STARTTTL_OFF            0x02

#define UTURN_SEQ_THRESHOLD     0x03

#define BUDDY_IP_NONE           0x00
#define BUDDY_IP                0x01

#define RTLA_THRESHOLD          0x01
#define FRPLA_THRESHOLD         0x03

#define TRIG_NONE               0x00
#define TRIG_DUP_IP             0x01
#define TRIG_RTLA               0x02
#define TRIG_FRPLA              0x03
#define TRIG_MTTL               0x04

#define RET_NO_TUNNEL           0x00
#define RET_TRACE_UPDATED       0x01
#define RET_DISCOVERY_RUN       0x02

#define REV_EMPTY               0x00
#define REV_NEW_LSRS            0x01
#define REV_INGR_NOT_FOUND      0x02
#define REV_TARGET_NOT_REACHED  0x03

#define REV_MODE_NONE           0x00
#define REV_MODE_DPR            0x01
#define REV_MODE_BRPR           0x02

#define DATA_TRACE              0x00
#define DATA_TUNNEL             0x01

#define INGRESS_IS_NULL         0x00
#define INGRESS_IS_START        0x01

#define TUN_STATUS_COMPL        0x00
#define TUN_STATUS_INCOMPL      0x01

#define PRINT_PREV_NOT_FOUND    0x00
#define PRINT_PREV_FOUND        0x01

#define UTURN_NEXT_NOT_EGRESS   0x00
#define UTURN_NEXT_EGRESS       0x01

/*
 * Echo-reply TTL received from an IP address during a trace with pings
 */
typedef struct sc_trace_ping
{
  scamper_addr_t   *addr;
  uint8_t           rttl;
} sc_trace_ping_t;

/* 
 * Tunnel structure used to avoid revealing the same tunnel multiple times.
 * start_addr: IP address of the assumed ingress LER, or the hop before.
 * next_addr: IP address following the start address in the original trace.
 * lsp: list of scamper_trace_hop (LSRs) in the invisible tunnel.
 * next_addr_fail_mflags: failure MPLS flags for next_addr.
 * tun_status: determine is the tunnel is complete or may be incomplete.
 * probec: number of probes needed to reveal the tunnel (traces and pings).
 *
 * start_addr is not necessarily the ingress LER.
 * If the ingress LER does not respond, the start address will be the previous
 * IP address.
 * next_addr is not necessarily the egress LER.
 * It is identical to the egress IP address only if PHP and not opaque tunnel.
 * Note also that in case of UHP with duplicate IP address, the real egress will
 * be the last hop of the LSP in the structure.
 */
typedef struct sc_tunnel
{
  scamper_addr_t        *start_addr;
  scamper_addr_t        *next_addr;
  uint8_t               next_addr_fail_mflags;
  slist_t               *lsp;
  uint8_t               tun_status;
  uint8_t               probec;
} sc_tunnel_t;

/* 
 * Buddy address of a given addr on a point-to-point link
 * addr: IP address
 * buddy_addr: IP address of the buddy of addr
 */
typedef struct sc_buddy
{
  scamper_addr_t   *addr;
  scamper_addr_t   *buddy_addr;
} sc_buddy_t;

/* Generic measurement target */
typedef struct sc_target
{
  scamper_addr_t   *addr;
  int               type;
  void             *data;
  slist_t          *blocked;
  splaytree_node_t *tree_node;
} sc_target_t;

/* Generic measurement test */
typedef struct sc_test
{
  int               type;
  void             *data;
  struct timeval    wait;
} sc_test_t;

/* 
 * TNT test
 * addr: destination of the trace
 * trace: scamper_trace to the destination
 * pingleft: number of pings that must still be done for hop fingerprinting
 * invtuntests: list of invisible tunnel tests that may be run
 * ingress_status: ingress status for current revelation
 * (equal to start address or no resp.)
 */
typedef struct sc_tnt_test
{
  scamper_addr_t       *addr;
  scamper_trace_t      *trace;
  uint32_t              userid;
  splaytree_node_t     *tree_node;
  int                   pingleft;
  slist_t              *invtuntests;
  uint8_t               ingress_status;
} sc_tnt_test_t;

/* 
 * Tunnel test
 * start_addr: IP address of the assumed ingress LER, or the hop before
 * next_addr: IP address following the start address in the original trace
 * target_addr: current target of the test
 * tunnel: sc_tunnel corresponding to the invisible tunnel
 * probing_mode: current probing mode (ping, buddy ping, trace, buddy trace)
 * trace_sttl: start TTL for the current trace
 * buddy_status: determine if the current target is a buddy IP address
 * trigger_type: trigger that identified the tunnel (FRPLA, RTLA, DUPIP, MTTL)
 * rev_mode: current revelation mode (DPR, BRPR)
 * ingress_status: current ingress status (equal to start address or no resp.)
 * iteration: current step in revelation
 * pingleft: number of pings that must still be done for LSR fingerprinting
 */
typedef struct sc_tunnel_test
{
  scamper_addr_t       *start_addr;
  scamper_addr_t       *next_addr;
  scamper_addr_t       *target_addr;
  sc_tunnel_t          *tunnel;
  uint32_t              userid;
  uint8_t               probing_mode;
  uint8_t               trace_sttl;
  uint8_t               buddy_status;
  uint8_t               trigger_type;
  uint8_t               rev_mode;
  uint8_t               ingress_status;
  int                   iteration;
  int                   pingleft;
} sc_tunnel_test_t;

/* 
 * Buddy test
 * addr: IP address whose buddy must be found
 * target_addr: current target of the test
 * prefix30: ordered array of the 4 IP addresses belonging to the prefix addr/30
 * addr_pos: index of addr in prefix30
 */
typedef struct sc_buddy_test
{
  scamper_addr_t   *addr;
  scamper_addr_t   *target_addr;
  scamper_addr_t  **prefix30;
  sc_buddy_t       *buddy;
  uint8_t           addr_pos;
  splaytree_node_t *tree_node;
} sc_buddy_test_t;

/* 
 * Structure to wait for a ping requested in multiple tests
 * addr: destination address of the ping
 * list_tntt: list of TNT tests awaiting for the ping
 * list_tunt: list of tunnel tests awaiting for the ping
 */
typedef struct sc_ping_wait
{
  scamper_addr_t   *addr;
  slist_t          *list_tntt;
  slist_t          *list_tunt;
  splaytree_node_t *tree_node;
} sc_ping_wait_t;

/* 
 * Structure to wait for a tunnel requested in multiple TNT tests
 * start_addr: IP address of the assumed ingress LER, or the hop before
 * next_addr: IP address following the start address in the original trace
 * list: list of TNT tests awaiting for the tunnel
 */
typedef struct sc_tunnel_wait
{
  scamper_addr_t   *start_addr;
  scamper_addr_t   *next_addr;
  slist_t          *list;
  splaytree_node_t *tree_node;
} sc_tunnel_wait_t;

/* 
 * Structure to wait for a buddy requested in multiple tunnel tests
 * addr: IP address whose buddy must be found
 * list: list of tunnel tests awaiting for the buddy
 */
typedef struct sc_buddy_wait
{
  scamper_addr_t   *addr;
  slist_t          *list;
  splaytree_node_t *tree_node;
} sc_buddy_wait_t;

/* Dump functions */
typedef struct sc_dump
{
  char  *descr;
  int  (*proc_tnt)(scamper_trace_t *trace);
} sc_dump_t;

/* Function to dump a trace with tunnel revelation */
static int process_tnt_1(scamper_trace_t *);

static uint32_t               options         = 0;
static char                  *address         = NULL;
static unsigned int           port            = 0;
static splaytree_t           *targets         = NULL;
static char                  *unix_name       = NULL;
static char                  *outfile_name    = NULL;
static scamper_file_t        *outfile         = NULL;
static FILE                  *logfile         = NULL;
static scamper_file_filter_t *ffilter         = NULL;
static int                    scamper_fd      = -1;
static char                  *readbuf         = NULL;
static size_t                 readbuf_len     = 0;
static int                    data_left       = 0;
static scamper_file_t        *decode_in       = NULL;
static int                    decode_in_fd    = -1;
static int                    decode_out_fd   = -1;
static int                    more            = 0;
static int                    probing         = 0;
static int                    method          = 0;
static uint32_t               userid          = 1;
static struct timeval         now;
static int                    dump_id         = 0;
static char                 **dump_files;
static int                    dump_filec      = 0;
static const sc_dump_t        dump_funcs[]    = {
  {NULL, NULL},
  {"dump tnt traces", process_tnt_1},
};
static int dump_funcc = sizeof(dump_funcs) / sizeof(sc_dump_t);
static uint16_t              unkown_rev_mask     = 0xffcf;
static uint8_t               lsr_mask            = 0xfb;
static uint16_t              trig_mask           = 0xfff0;
static uint16_t              clear_trig_mask     = 0x000f;
static uint8_t               clear_lsr_type_mask = 0xf8;
static uint8_t               clear_tun_type_mask = 0x07;

/* Current tnt test measurements */
static splaytree_t           *tnttests = NULL;
/* Current buddy test measurements */
static splaytree_t           *buddytests    = NULL;
/* Collected pings to avoid redundant measurements */
static splaytree_t           *pings         = NULL;
/* Wait for ping measurement */
static splaytree_t           *ping_waits    = NULL;
/* Candidate tunnels identified so far to avoid redundant measurements */
static splaytree_t           *tunnels       = NULL;
/* Wait for tunnel measurement */
static splaytree_t           *tunnel_waits  = NULL;
/* Collected traces during tunnel revelation to avoid redundant measurements */
static splaytree_t           *traces        = NULL;
/* Collected buddies during tunnel revelation to avoid redundant measurements */
static splaytree_t           *buddies       = NULL;
/* Wait for buddy test measurement */
static splaytree_t           *buddy_waits   = NULL;
/* FRPLA threshold */
static int                    frplathresh   = FRPLA_THRESHOLD;
/* RTLA threshold */
static int                    rtlathresh    = RTLA_THRESHOLD;
/* Start ttl for the initial trace */
static int                    startttl      = 1;
/* Number of pings to send for fingerprinting */
static int                    pingfpc       = 1;
/* Lists with destinations */
static slist_t               *probelist     = NULL;
/* List with ping measurements to be done */
static slist_t               *waitlist      = NULL;
/* Diplay revelation stop reason on output */
static uint8_t                display     = DISPLAY_STAND;
/* Brute force to bypass triggers */
static uint8_t                brutef      = BRUTE_FORCE_DIS;

/*
 * Print the program usage
 */
static void usage(uint32_t opt_mask)
{
  fprintf(stderr,
          "usage: sc_tnt [-?Db] [-a addressfile] [-c pingcount]\n"
          "              [-f frplathresh] [-i dst] [-l logfile]\n"
          "              [-m method] [-o outputfile] [-p port]\n"
          "              [-r rtlathresh] [-s startttl ] [-U unix]\n"
          "\n"
          "       sc_tnt [-v] [-d dump] file.warts\n\n"
          "version: 5.0 2018/05/23 16:54:34\n"
          "\n");
  if (opt_mask == 0) return;
  
  fprintf(stderr, "\n");
  
  if (opt_mask & OPT_HELP)
    fprintf(stderr, "     -? give an overview of the usage of sc_tnt\n");
  if (opt_mask & OPT_DAEMON)
    fprintf(stderr, "     -D start as daemon\n");
  if (opt_mask & OPT_BRUTEFORCE)
    fprintf(stderr, "     -b brute force (bypass the triggers)\n");
  if (opt_mask & OPT_ADDRFILE)
    fprintf(stderr, "     -a input address file, if multiple destinations\n");
  if (opt_mask & OPT_COUNT)
    fprintf(stderr, "     -c number of pings for fingerprinting. Default 1\n");
  if (opt_mask & OPT_FRPLATHRESH)
    fprintf(stderr, "     -f threshold value for FRPLA trigger (>0)."
            " Default 3\n");
  if (opt_mask & OPT_IPADDR)
    fprintf(stderr, "     -i destination IP address, if unique destination\n");
  if (opt_mask & OPT_LOG)
    fprintf(stderr, "     -l log file\n");
  if (opt_mask & OPT_METHOD)
    fprintf(stderr, "     -m method to collect traces (icmp-paris"
            " or udp-paris). Default icmp-paris\n");
  if (opt_mask & OPT_OUTFILE)
    fprintf(stderr, "     -o output warts file\n");
  if (opt_mask & OPT_PORT)
    fprintf(stderr, "     -p port to find scamper on\n");
  if (opt_mask & OPT_RTLATHRESH)
    fprintf(stderr, "     -r threshold value for RTLA trigger (>0)."
            " Default 1\n");
  if (opt_mask & OPT_STARTTTL)
    fprintf(stderr, "     -s start TTL for the initial trace (>0)."
            " Default 1\n");
  if (opt_mask & OPT_UNIX)
    fprintf(stderr, "     -U unix domain to find scamper on\n");
  if (opt_mask & OPT_DISPLAY)
    fprintf(stderr, "     -v verbose display (only in dump mode,"
            " shows tunnel discovery attempts)\n");
  if (opt_mask & OPT_DUMP)
    fprintf(stderr, "     -d dump. Use 1 to display MPLS tunnels\n");
  
  return;
}

/*
 * Check program arguments
 */
static int check_options(int argc, char *argv[])
{
  int ch; long lo;
  char *opts = "?a:bc:d:Df:i:l:m:o:p:r:s:U:v";
  char *opt_port = NULL, *opt_unix = NULL, *opt_log = NULL, *opt_dump = NULL;
  char *opt_method = NULL, *opt_count = NULL, *opt_startttl = NULL;
  char *opt_frplathresh = NULL, *opt_rtlathresh = NULL;
  
  while ((ch = getopt(argc, argv, opts)) != -1)
  {
    switch (ch)
    {
      case 'a':
        options |= OPT_ADDRFILE;
        address = optarg;
        break;
        
      case 'b':
        options |= OPT_BRUTEFORCE;
        break;
        
      case 'c':
        options |= OPT_COUNT;
        opt_count = optarg;
        break;
        
      case 'd':
        options |= OPT_DUMP;
        opt_dump = optarg;
        break;
        
      case 'D':
        options |= OPT_DAEMON;
        break;
      
      case 'f':
        options |= OPT_FRPLATHRESH;
        opt_frplathresh = optarg;
        break;
        
      case 'i':
        options |= OPT_IPADDR;
        address = optarg;
        break;
        
      case 'l':
        options |= OPT_LOG;
        opt_log = optarg;
        break;
        
      case 'm':
        options |= OPT_METHOD;
        opt_method = optarg;
        break;
        
      case 'o':
        options |= OPT_OUTFILE;
        outfile_name = optarg;
        break;
        
      case 'p':
        options |= OPT_PORT;
        opt_port = optarg;
        break;
      
      case 'r':
        options |= OPT_RTLATHRESH;
        opt_rtlathresh = optarg;
        break;
        
      case 's':
        options |= OPT_STARTTTL;
        opt_startttl = optarg;
        break;
        
      case 'U':
        options |= OPT_UNIX;
        opt_unix = optarg;
        break;
      
      case 'v':
        options |= OPT_DISPLAY;
        break;
        
      case '?':
      default:
        usage(0xffffffff);
        return -1;
    }
  }
  
  if (options == 0)
  {
    usage(0);
    return -1;
  }
  
  /* Measurement mode */
  if ((options & OPT_DUMP) == 0)
  {
    if ((options & OPT_OUTFILE) == 0)
    {
      usage(OPT_OUTFILE);
      return -1;
    }
    if ((options & (OPT_PORT|OPT_UNIX)) == 0 ||
       (options & (OPT_PORT|OPT_UNIX)) == (OPT_PORT|OPT_UNIX))
    {
      usage(OPT_PORT|OPT_UNIX);
      return -1;
    }
    if ((options & (OPT_IPADDR|OPT_ADDRFILE)) == 0 ||
       (options & (OPT_IPADDR|OPT_ADDRFILE)) == (OPT_IPADDR|OPT_ADDRFILE))
    {
      usage(OPT_IPADDR|OPT_ADDRFILE);
      return -1;
    }
    if (options & OPT_METHOD)
    {
      if (strcasecmp(opt_method, "udp-paris") == 0)
      {
        method = METHOD_UDP;
      }
      else if (strcasecmp(opt_method, "icmp-paris") == 0)
      {
        method = METHOD_ICMP;
      }
      else
      {
        usage(OPT_METHOD);
        return -1;
      }
    }
    if (options & OPT_PORT)
    {
      if (string_tolong(opt_port, &lo) != 0 || lo < 1 || lo > 65535)
      {
        usage(OPT_PORT);
        return -1;
      }
      port = lo;
    }
    if (options & OPT_UNIX)
    {
      unix_name = opt_unix;
    }
    if (options & OPT_COUNT)
    {
      if (string_tolong(opt_count, &lo) != 0 || lo < 1)
      {
        usage(OPT_COUNT);
        return -1;
      }
      pingfpc = lo;
    }
    if (opt_log != NULL && (logfile = fopen(opt_log, "w")) == NULL)
    {
      usage(OPT_LOG);
      fprintf(stderr, "could not open %s\n", opt_log);
      return -1;
    }
    if (opt_startttl != NULL)
    {
      if(string_tolong(opt_startttl, &lo) != 0 || lo < 1)
      {
        usage(OPT_STARTTTL);
        return -1;
      }
      startttl = lo;
    }
    if (opt_frplathresh != NULL)
    {
      if (string_tolong(opt_frplathresh, &lo) != 0 || lo < 1)
      {
        usage(OPT_FRPLATHRESH);
        return -1;
      }
      frplathresh = lo;
    }
    if (opt_rtlathresh != NULL)
    {
      if (string_tolong(opt_rtlathresh, &lo) != 0 || lo < 1)
      {
        usage(OPT_RTLATHRESH);
        return -1;
      }
      rtlathresh = lo;
    }
    if (options & OPT_BRUTEFORCE)
      brutef = BRUTE_FORCE_ENA;
  }
  /* Warts reading mode */
  else
  {
    if (string_tolong(opt_dump, &lo) != 0 || lo < 1 || lo > dump_funcc)
    {
      usage(OPT_DUMP);
      return -1;
    }
    dump_id    = lo;
    dump_files = argv + optind;
    dump_filec = argc - optind;
    if (options & OPT_DISPLAY)
      display = DISPLAY_VERB;
  }
  
  return 0;
}

/*
 * Transform a splaytree into a list
 */
static int tree_to_slist(void *ptr, void *entry)
{
  if (slist_tail_push((slist_t *)ptr, entry) != NULL)
    return 0;
  return -1;
}

/* Log an error message and print it on the standard error output */
static void logerr(char *format, ...)
{
  va_list ap;
  char msg[131072];
  
  if((options & OPT_DAEMON) && logfile == NULL)
    return;
  
  va_start(ap, format);
  vsnprintf(msg, sizeof(msg), format, ap);
  va_end(ap);
  
  if((options & OPT_DAEMON) == 0)
    fprintf(stderr, "%s", msg);
  
  if(logfile != NULL)
  {
    fprintf(logfile, "%ld: %s", (long int)now.tv_sec, msg);
    fflush(logfile);
  }
  
  return;
}

/* Log a message and print it on the standard output */
static void logprint(char *format, ...)
{
  va_list ap;
  char msg[131072];
  
  if((options & OPT_DAEMON) && logfile == NULL)
    return;
  
  va_start(ap, format);
  vsnprintf(msg, sizeof(msg), format, ap);
  va_end(ap);
  
  if(logfile != NULL)
  {
    fprintf(logfile, "%ld: %s", (long int)now.tv_sec, msg);
    fflush(logfile);
  }
    
  return;
}

/* Free a list containing scamper_trace_hops */
static void scamper_trace_hop_list_free(slist_t *list)
{
  slist_onremove(list, (slist_onremove_t)scamper_trace_hop_free);
  slist_free(list);
  return;
}

/*
 * Free a /30 prefix array
 */
static void free_prefix30_array(scamper_addr_t **prefix30)
{
  int i;
  
  for (i=0; i < 4; i++)
  {
    if (prefix30[i] != NULL)
      scamper_addr_free(prefix30[i]);
  }
  free(prefix30);
}

/*
 * Get the 4 addresses in the /30 prefix of the input address
 */
static scamper_addr_t **get_prefix30_addresses(const scamper_addr_t *addr)
{
  scamper_addr_t **prefix30;
  scamper_addr_t *prefaddr;
  struct in_addr net;
  int i, j;
  
  if (scamper_addr_netaddr(addr, &net, 30) == -1 ||
      (prefix30 = malloc_zero(sizeof(scamper_addr_t) * 4)) == NULL)
    return NULL;
  
  for (i=0; i < 4; i++)
  {
    if ((prefaddr = scamper_addr_alloc(SCAMPER_ADDR_TYPE_IPV4, &net)) == NULL)
    {
      free_prefix30_array(prefix30);
      return NULL;
    }
    prefix30[i] = prefaddr;
    net.s_addr += 0x1000000;
  }
  return prefix30;
}

/*
 * Check if an address IP is already in a tunnel LSP
 */
static int scamper_addr_in_sc_tunnel_lsp(scamper_addr_t *addr, sc_tunnel_t *tun)
{
  slist_node_t *sn;
  scamper_trace_hop_t *hop;
  if (tun == NULL || tun->lsp == NULL)
    return 1;
  
  for (sn=slist_head_node(tun->lsp); sn != NULL; sn=slist_node_next(sn))
  {
    hop = slist_node_item(sn);
    if (hop == NULL)
      continue;
    if (scamper_addr_cmp(hop->hop_addr, addr) == 0)
      return 0;
  }
  return 1;
}

/*
 * Allocate a generic measurement test
 */
static sc_test_t *sc_test_alloc(int type, void *data)
{
  sc_test_t *t;
  if ((t = malloc_zero(sizeof(sc_test_t))) == NULL)
    return NULL;
  t->type = type;
  t->data = data;
  return t;
}

/*
 * Free a generic measurement test
 */
static void sc_test_free(sc_test_t *test)
{
  free(test);
  return;
}

/*
 * Create a measurement test and insert it in the waiting test list
 */
static int sc_test_waitlist(int type, void *data)
{
  sc_test_t *t;
  if ((t = sc_test_alloc(type, data)) == NULL)
  {
    logerr("Could not alloc sc_test_waitlist.\n");
    return -1;
  }
  if (slist_tail_push(waitlist, t) == NULL)
  {
    logerr("Could not push test in sc_test_waitlist.\n");
    return -1;
  }
  return 0;
}

/*
 * Add a different test to a target already existing
 * At least 2 different tests will exist for the target
 */
static int sc_target_block(sc_target_t *tg, sc_test_t *test)
{
  if ((tg->blocked == NULL && (tg->blocked = slist_alloc()) == NULL) ||
      slist_head_push(tg->blocked, test) == NULL)
  {
    logerr("Could not block a test for a target.\n");
    return -1;
  }
  return 0;
}

/*
 * Detach a target from the splaytree of targets
 */
static void sc_target_detach(sc_target_t *tg)
{
  if (tg->tree_node != NULL)
  {
    splaytree_remove_node(targets, tg->tree_node);
    tg->tree_node = NULL;
  }
  return;
}

/*
 * Free a target
 */
static void sc_target_free(sc_target_t *tg)
{
  sc_test_t *bt;
  if (tg == NULL)
    return;
  assert(tg->tree_node == NULL);
  if (tg->addr != NULL)
    scamper_addr_free(tg->addr);
  if (tg->blocked != NULL)
  {
    while ((bt = slist_head_pop(tg->blocked)) != NULL)
    {
      sc_test_waitlist(bt->type, bt->data);
      free(bt);
    }
    slist_free(tg->blocked);
  }
  free(tg);
  return;
}

/*
 * Target comparator based on the destination address
 */
static int sc_target_cmp(const sc_target_t *a, const sc_target_t *b)
{
  return scamper_addr_cmp(a->addr, b->addr);
}

/*
 * Find the target associated to an IP address
 */
static sc_target_t *sc_target_find(scamper_addr_t *addr)
{
  sc_target_t fm;
  fm.addr = addr;
  return splaytree_find(targets, &fm);
}

/*
 * Get or create a target associated to an IP address
 */
static sc_target_t *sc_target_get(scamper_addr_t *addr, int type, void *data)
{
  sc_target_t *tg;
  
  /* Check if target already exists */
  if ((tg = sc_target_find(addr)) != NULL)
    return tg;
  
  /* Create a new target */
  if ((tg = malloc_zero(sizeof(sc_target_t))) == NULL)
    return NULL;
  tg->addr = scamper_addr_use(addr);
  tg->type = type;
  tg->data = data;
  if ((tg->tree_node = splaytree_insert(targets, tg)) == NULL)
  {
    sc_target_free(tg);
    return NULL;
  }
  
  return tg;
}

/*
 * Allocate a trace ping
 */
static sc_trace_ping_t *sc_trace_ping_alloc(void)
{
  sc_trace_ping_t *ping;
  if ((ping = malloc_zero(sizeof(sc_trace_ping_t))) == NULL)
    return NULL;
  return ping;
}

/*
 * Free a trace ping
 */
static void sc_trace_ping_free(sc_trace_ping_t *ping)
{
  if (ping == NULL)
    return;
  if (ping->addr != NULL)
    scamper_addr_free(ping->addr);
  free(ping);
  return;
}

/*
 * Find a specific hop in a trace and set its ping rttl.
 * Go through the whole trace in case of a multiple occurences of an IP address
 */
static int scamper_trace_hop_ping_rttl_set(scamper_trace_t *trace,
                                           const scamper_addr_t *addr,
                                           const uint8_t rttl)
{
  scamper_trace_hop_t *hop;
  int i, rc = -1;
  
  for (i=trace->firsthop-1; i<trace->hop_count; i++)
  {
    /* Consider only public and valid IP addresses */
    if ((hop = trace->hops[i]) == NULL)
      continue;
    if (scamper_addr_cmp(hop->hop_addr, addr) == 0)
    {
      hop->hop_ping_rttl = rttl;
      /* Update next hop if we received two replies (possible if timeout) */
      if (hop->hop_next != NULL)
        hop->hop_next->hop_ping_rttl = rttl;
      rc = 0;
    }
  }
  if (rc == -1)
    logerr("Could not set ping rttl for hop.\n");
  return rc;
}

/*
 * Find a specific LSR in a tunnel and set its ping rttl
 * Go through the whole tunnel in case of a multiple occurences of an IP address
 */
static int sc_tunnel_lsr_ping_rttl_set(sc_tunnel_t *tun,
                                       const scamper_addr_t *addr,
                                       const uint8_t rttl)
{
  scamper_trace_hop_t *hop;
  slist_node_t *sn;
  int i, rc = -1;
 
  if (tun == NULL || tun->lsp == NULL)
    return 0;
  
  for (sn=slist_head_node(tun->lsp); sn != NULL; sn=slist_node_next(sn))
  {
    hop = slist_node_item(sn);
    /* Consider only public and valid IP addresses */
    if (hop == NULL)
      continue;
    if (scamper_addr_cmp(hop->hop_addr, addr) == 0)
    {
      hop->hop_ping_rttl = rttl;
      rc = 0;
    }
  }
  if (rc == -1)
    logerr("Could not set ping rttl for LSR.\n");
  return rc;
}

/*
 * Get the different IP adresses of a tunnel or a trace in order to
 * ping them later for fingerprinting.
 * data must be either a sc_tunnel_t or a scamper_trace_t
 */
static int scamper_trace_hops2addrs(const void *data, slist_t *list,
                                    int datatype)
{
  slist_t *lista = NULL;
  scamper_addr_t *last = NULL, *addr = NULL;
  scamper_trace_hop_t *hop;
  slist_node_t *sn;
  sc_tunnel_t *tun;
  scamper_trace_t *trace;
  int i;
  
  /* The list must be empty */
  assert (list != NULL && slist_count(list) == 0);
  
  if ((lista = slist_alloc()) == NULL)
    goto err;
  switch (datatype)
  {
    case DATA_TUNNEL:
      /* The tunnel must exist */
      tun = (sc_tunnel_t*) data;
      if (tun == NULL || tun->lsp == NULL)
        return 0;
    
      for (sn=slist_head_node(tun->lsp); sn != NULL; sn=slist_node_next(sn))
      {
        hop = slist_node_item(sn);
        /* Consider only public and valid IP addresses */
        if (hop == NULL || scamper_addr_isreserved(hop->hop_addr))
          continue;
        slist_tail_push(lista, scamper_addr_use(hop->hop_addr));
      }
      break;
      
    case DATA_TRACE:
      trace = (scamper_trace_t*)data;
      for (i=trace->firsthop-1; i<trace->hop_count; i++)
      {
        /* Consider only public and valid IP addresses */
        if ((hop = trace->hops[i]) == NULL ||
            scamper_addr_isreserved(hop->hop_addr))
          continue;
        slist_tail_push(lista, scamper_addr_use(hop->hop_addr));
      }
      break;
      
    default:
      goto err;
  }
  
  /* Need at least one hop */
  if (slist_count(lista) < 2)
  {
    slist_concat(list, lista);
    slist_free(lista);
    return 0;
  }
  
  /* Delete duplicate IP addresses */
  slist_qsort(lista, (slist_cmp_t)scamper_addr_cmp);
  while ((addr = slist_head_pop(lista)) != NULL)
  {
    if (last == NULL || scamper_addr_cmp(last, addr) != 0)
    {
      slist_tail_push(list, addr);
      last = addr;
    }
    else
      scamper_addr_free(addr);
  }
  slist_free(lista);
  return 0;
  
err:
  if (lista != NULL)
  {
    while ((addr = slist_head_pop(lista)) != NULL)
      scamper_addr_free(addr);
    slist_free(lista);
  }
  while ((addr = slist_head_pop(list)) != NULL)
    scamper_addr_free(addr);
  
  logerr("Could not retrieve IP addresses in trace/tunnel.\n");
  return -1;
}


/**
 *  Get the TTLs of each echo-reply message received during a ping
 */
static int scamper_ping_rttls(const scamper_ping_t *ping, int *ttl)
{
  scamper_ping_reply_t *reply;
  int i, rc = 0;
  
  memset(ttl, 0, sizeof(int) * 256);
  
  for (i=0; i<ping->ping_sent; i++)
  {
    if ((reply = ping->ping_replies[i]) == NULL)
      continue;
    if (SCAMPER_PING_REPLY_IS_ICMP_ECHO_REPLY(reply) == 0)
      continue;
    ttl[reply->reply_ttl]++;
    rc++;
  }
  return rc;
}

/*
 * Get the most occuring reply TTL from a ping
 */
static uint8_t scamper_ping_reply_ttl_get(const scamper_ping_t *ping)
{
  int prttls[256], cur;
  int best = 255, j;
  int nbest = 0;
  
  /* Find the TTL occuring the most */
  if (scamper_ping_rttls(ping, prttls) > 0)
  {
    nbest = prttls[best];
    for (j=254; j>=0; j--)
    {
      if ((cur = prttls[j]) > nbest)
      {
        best = j;
        nbest = cur;
      }
    }
    if (nbest > 0)
      return (uint8_t) best;
  }
  return 0;
}

/*
 * Trace ping address comparator
 */
static int sc_trace_ping_cmp(const void *a, const void *b)
{
  return scamper_addr_cmp(((sc_trace_ping_t *)a)->addr,
                          ((sc_trace_ping_t *)b)->addr);
}

/*
 * Find a trace ping performed previoulsy
 */
static sc_trace_ping_t *sc_trace_ping_find(scamper_addr_t *addr)
{
  sc_trace_ping_t fm;
  fm.addr = addr;
  return splaytree_find(pings, &fm);
}

/*
 * Get or create a trace ping
 */
static sc_trace_ping_t *sc_trace_ping_get(scamper_addr_t *addr)
{
  sc_trace_ping_t *ping;
  if ((ping = sc_trace_ping_find(addr)) != NULL)
    return ping;
  if ((ping = sc_trace_ping_alloc()) == NULL)
    return NULL;
  ping->addr = scamper_addr_use(addr);
  if (splaytree_insert(pings, ping) == NULL)
  {
    sc_trace_ping_free(ping);
    return NULL;
  }
  return ping;
}

/* 
 * ping_wait comparator
 */
static int sc_ping_wait_cmp(const sc_ping_wait_t *a, const sc_ping_wait_t *b)
{
  return scamper_addr_cmp(a->addr, b->addr);
}

/* 
 * Detach a ping_wait from a splaytree
 */
static void sc_ping_wait_detach(sc_ping_wait_t *pw)
{
  if (pw != NULL && pw->tree_node != NULL)
    splaytree_remove_node(ping_waits, pw->tree_node);
  return;
}

/*
 * Free a ping_wait
 */
static void sc_ping_wait_free(sc_ping_wait_t *pw)
{
  if (pw == NULL)
    return;
  if (pw->addr != NULL)
    scamper_addr_free(pw->addr);
  if (pw->list_tntt != NULL)
    slist_free(pw->list_tntt);
  if (pw->list_tunt != NULL)
    slist_free(pw->list_tunt);
  free(pw);
  return;
}

/* 
 * Find a ping_wait in the splaytree
 */
static sc_ping_wait_t *sc_ping_wait_find(scamper_addr_t *addr)
{
  sc_ping_wait_t fm;
  fm.addr = addr;
  return splaytree_find(ping_waits, &fm);
}

/*
 * Get a ping_wait in the splaytree, if existing. Otherwise, insert a new one.
 */
static sc_ping_wait_t *sc_ping_wait_get(scamper_addr_t *addr)
{
  sc_ping_wait_t *pw = NULL;
  
  if ((pw = sc_ping_wait_find(addr)) != NULL)
    return pw;
  if ((pw = malloc_zero(sizeof(sc_ping_wait_t))) == NULL ||
      (pw->list_tntt = slist_alloc()) == NULL ||
      (pw->list_tunt = slist_alloc()) == NULL)
    goto err;
  pw->addr = scamper_addr_use(addr);
  if ((pw->tree_node = splaytree_insert(ping_waits, pw)) == NULL)
    goto err;
  return pw;
  
err:
  if (pw != NULL)
  {
    sc_ping_wait_detach(pw);
    sc_ping_wait_free(pw);
  }
  return NULL;
}

/*
 * Allocate a buddy
 */
static sc_buddy_t *sc_buddy_alloc(scamper_addr_t *addr)
{
  sc_buddy_t *buddy;
  if ((buddy = malloc_zero(sizeof(sc_buddy_t))) == NULL)
    return NULL;
  buddy->addr = scamper_addr_use(addr);
  return buddy;
}

/*
 * Free a buddy
 */
static void sc_buddy_free(sc_buddy_t *buddy)
{
  if (buddy == NULL)
    return;
  if (buddy->addr != NULL)
    scamper_addr_free(buddy->addr);
  if (buddy->buddy_addr != NULL)
    scamper_addr_free(buddy->buddy_addr);
  free(buddy);
  return;
}

/*
 * Buddy comparator
 */
static int sc_buddy_cmp(const sc_buddy_t *a, const sc_buddy_t *b)
{
  return scamper_addr_cmp(a->addr, b->addr);
}

/*
 * Find a buddy
 */
static sc_buddy_t *sc_buddy_find(scamper_addr_t *addr)
{
  sc_buddy_t fm;
  fm.addr = addr;
  return splaytree_find(buddies, &fm);
}

/*
 * Get or create a buddy
 */
static sc_buddy_t *sc_buddy_get(scamper_addr_t *addr)
{
  sc_buddy_t *buddy;
  if ((buddy = sc_buddy_find(addr)) != NULL)
    return buddy;
  if ((buddy = sc_buddy_alloc(addr)) == NULL)
    return NULL;
  if (splaytree_insert(buddies, buddy) == NULL)
  {
    sc_buddy_free(buddy);
    return NULL;
  }
  return buddy;
}

/* buddy_test comparator */
static int sc_buddy_test_cmp(const sc_buddy_test_t *a, const sc_buddy_test_t *b)
{
  return scamper_addr_cmp(a->addr, b->addr);
}

/*
 * Detach a buddy_test from the splaytree
 */
static void sc_buddy_test_detach(sc_buddy_test_t *bt)
{
  if (bt != NULL && bt->tree_node != NULL)
    splaytree_remove_node(buddytests, bt->tree_node);
  return;
}

/* Free a buddy_test */
static void sc_buddy_test_free(sc_buddy_test_t *bt)
{
  if (bt == NULL)
    return;
  if (bt->addr != NULL)
    scamper_addr_free(bt->addr);
  if (bt->target_addr != NULL)
    scamper_addr_free(bt->target_addr);
  if (bt->prefix30 != NULL)
    free_prefix30_array(bt->prefix30);
  return;
}

/*
 * buddy_wait comparator
 */
static int sc_buddy_wait_cmp(const sc_buddy_wait_t *a, const sc_buddy_wait_t *b)
{
  return scamper_addr_cmp(a->addr, b->addr);
}

/*
 * Detach a buddy_wait from a splaytree
 */
static void sc_buddy_wait_detach(sc_buddy_wait_t *bw)
{
  if (bw != NULL && bw->tree_node != NULL)
    splaytree_remove_node(buddy_waits, bw->tree_node);
  return;
}

/*
 * Free a buddy_wait
 */
static void sc_buddy_wait_free(sc_buddy_wait_t *bw)
{
  if (bw == NULL)
    return;
  if (bw->addr != NULL)
    scamper_addr_free(bw->addr);
  if (bw->list != NULL)
    slist_free(bw->list);
  free(bw);
  return;
}

/*
 * Find a buddy_wait in the splaytree
 */
static sc_buddy_wait_t *sc_buddy_wait_find(scamper_addr_t *addr)
{
  sc_buddy_wait_t fm;
  fm.addr = addr;
  return splaytree_find(buddy_waits, &fm);
}

/*
 * Get a buddy_wait in the splaytree, if existing. Otherwise, insert a new one.
 */
static sc_buddy_wait_t *sc_buddy_wait_get(scamper_addr_t *addr)
{
  sc_buddy_wait_t *bw = NULL;
  if ((bw = sc_buddy_wait_find(addr)) != NULL)
    return bw;
  if ((bw = malloc_zero(sizeof(sc_buddy_wait_t))) == NULL ||
      (bw->list = slist_alloc()) == NULL)
    goto err;
  bw->addr = scamper_addr_use(addr);
  if ((bw->tree_node = splaytree_insert(buddy_waits, bw)) == NULL)
    goto err;
  return bw;
  
err:
  if (bw != NULL)
  {
    sc_buddy_wait_detach(bw);
    sc_buddy_wait_free(bw);
  }
  return NULL;
}

/*
 * Allocate a tunnel
 */
static sc_tunnel_t *sc_tunnel_alloc(void)
{
  sc_tunnel_t *tun;
  if ((tun = malloc_zero(sizeof(sc_tunnel_t))) == NULL)
    return NULL;
  return tun;
}

/*
 * Free a tunnel
 */
static void sc_tunnel_free(sc_tunnel_t *tun)
{
  scamper_trace_hop_t *hop;
  
  if (tun == NULL)
    return;
  if (tun->start_addr != NULL)
    scamper_addr_free(tun->start_addr);
  if (tun->next_addr != NULL)
    scamper_addr_free(tun->next_addr);
  if (tun->lsp != NULL)
    scamper_trace_hop_list_free(tun->lsp);
  free(tun);
  return;
}

/*
 * Tunnel comparator
 */
static int sc_tunnel_cmp(const sc_tunnel_t *a, const sc_tunnel_t *b)
{
  int ra, rb;
  ra = scamper_addr_cmp(a->start_addr, b->start_addr);
  rb = scamper_addr_cmp(a->next_addr, b->next_addr);
  
  if (ra == 0)
    return rb;
  return ra;
}

/*
 * Find a tunnel
 */
static sc_tunnel_t *sc_tunnel_find(scamper_addr_t *start_addr,
                                   scamper_addr_t *next_addr)
{
  sc_tunnel_t fm;
  fm.start_addr = start_addr;
  fm.next_addr = next_addr;
  return splaytree_find(tunnels, &fm);
}

/*
 * Get or create a tunnel
 */
static sc_tunnel_t *sc_tunnel_get(scamper_addr_t *start_addr,
                                  scamper_addr_t *next_addr)
{
  sc_tunnel_t *tun;
  if ((tun = sc_tunnel_find(start_addr, next_addr)) != NULL)
    return tun;
  if ((tun = sc_tunnel_alloc()) == NULL)
    return NULL;
  tun->start_addr = scamper_addr_use(start_addr);
  tun->next_addr = scamper_addr_use(next_addr);
  if (splaytree_insert(tunnels, tun) == NULL)
  {
    sc_tunnel_free(tun);
    return NULL;
  }
  return tun;
}

/*
 * tunnel_wait comparator
 */
static int sc_tunnel_wait_cmp(const sc_tunnel_wait_t *a,
                              const sc_tunnel_wait_t *b)
{
  int ra, rb;
  ra = scamper_addr_cmp(a->start_addr, b->start_addr);
  rb = scamper_addr_cmp(a->next_addr, b->next_addr);
  
  if (ra == 0)
    return rb;
  return ra;
}

/*
 * Detach a tunnel_wait from a splaytree
 */
static void sc_tunnel_wait_detach(sc_tunnel_wait_t *tw)
{
  if (tw != NULL && tw->tree_node != NULL)
    splaytree_remove_node(tunnel_waits, tw->tree_node);
  return;
}

/*
 * Free a tunnel_wait
 */
static void sc_tunnel_wait_free(sc_tunnel_wait_t *tw)
{
  if (tw == NULL)
    return;
  if (tw->start_addr != NULL)
    scamper_addr_free(tw->start_addr);
  if (tw->next_addr != NULL)
    scamper_addr_free(tw->next_addr);
  if (tw->list != NULL)
    slist_free(tw->list);
  free(tw);
  return;
}

/*
 * Find a tunnel_wait in the splaytree
 */
static sc_tunnel_wait_t *sc_tunnel_wait_find(scamper_addr_t *start_addr,
                                             scamper_addr_t *next_addr)
{
  sc_tunnel_wait_t fm;
  fm.start_addr = start_addr;
  fm.next_addr = next_addr;
  return splaytree_find(tunnel_waits, &fm);
}

/*
 * Get a tunnel_wait in the splaytree, if existing. Otherwise, insert a new one.
 */
static sc_tunnel_wait_t *sc_tunnel_wait_get(scamper_addr_t *start_addr,
                                            scamper_addr_t *next_addr)
{
  sc_tunnel_wait_t *tw = NULL;
  if ((tw = sc_tunnel_wait_find(start_addr, next_addr)) != NULL)
    return tw;
  if ((tw = malloc_zero(sizeof(sc_tunnel_wait_t))) == NULL ||
      (tw->list = slist_alloc()) == NULL)
    goto err;
  tw->start_addr = scamper_addr_use(start_addr);
  tw->next_addr = scamper_addr_use(next_addr);
  if ((tw->tree_node = splaytree_insert(tunnel_waits, tw)) == NULL)
    goto err;
  return tw;
  
err:
  if (tw != NULL)
  {
    sc_tunnel_wait_detach(tw);
    sc_tunnel_wait_free(tw);
  }
  return NULL;
}

/*
 * Allocate a tunnel test
 */
static sc_tunnel_test_t *sc_tunnel_test_alloc(scamper_addr_t *start_addr,
                                              scamper_addr_t *next_addr,
                                              uint8_t sttl,
                                              uint8_t trigger_type,
                                              uint32_t userid,
                                              uint8_t ingress_status)
{
  sc_tunnel_test_t *tunt;
  
  /* start and next IP addresses must exist */
  if (start_addr == NULL || next_addr == NULL)
    return NULL;
  
  if ((tunt = malloc_zero(sizeof(sc_tunnel_test_t))) == NULL)
    return NULL;
  tunt->start_addr = scamper_addr_use(start_addr);
  tunt->next_addr = scamper_addr_use(next_addr);
  tunt->ingress_status = ingress_status;
  tunt->target_addr = scamper_addr_use(next_addr);
  tunt->userid = userid;
  tunt->probing_mode = PROB_MODE_TRACE;
  tunt->trace_sttl = sttl;
  tunt->trigger_type = trigger_type;
  tunt->iteration = 1;
  return tunt;
}

/*
 * Free a tunnel test
 */
static void sc_tunnel_test_free(sc_tunnel_test_t *tunt)
{
  if (tunt == NULL)
    return;
  if (tunt->start_addr != NULL)
    scamper_addr_free(tunt->start_addr);
  if (tunt->next_addr != NULL)
    scamper_addr_free(tunt->next_addr);
  if (tunt->target_addr != NULL)
    scamper_addr_free(tunt->target_addr);
  free(tunt);
  return;
}

/* 
 * Free a TNT test
 */
static sc_tnt_test_t *sc_tnt_test_free(sc_tnt_test_t *tntt)
{
  sc_tunnel_test_t *tunt;
  
  if (tntt == NULL)
    return NULL;
  
  if (tntt->trace != NULL)
    scamper_trace_free(tntt->trace);
    
  if (tntt->addr != NULL)
    scamper_addr_free(tntt->addr);
  
  if (tntt->invtuntests != NULL)
  {
    while ((tunt = slist_head_pop(tntt->invtuntests)) != NULL)
      sc_tunnel_test_free(tunt);
  }
  free(tntt);
  return NULL;
}

/* 
 * Detach a TNT test from the splaytree
 */
static void sc_tnt_test_detach(sc_tnt_test_t *tntt)
{
  if(tntt != NULL && tntt->tree_node != NULL)
    splaytree_remove_node(tnttests, tntt->tree_node);
  return;
}

/*
 * Compare TNT tests based on the destination addresses
 */
static int sc_tnt_test_cmp(const sc_tnt_test_t *a, const sc_tnt_test_t *b)
{
  return scamper_addr_cmp(a->addr, b->addr);
}

/*
 * Get initial TTL
 */
static uint8_t get_ittl(uint8_t rttl)
{
  if (rttl > 128)
    return 255;
  else if (rttl > 64)
    return 128;
  else if (rttl > 32)
    return 64;
  else
    return 32;
}


/*
 * Compute FRPLA (return/forward path asymmetry)
 */
static int get_frpla(scamper_trace_hop_t *hop)
{
  uint8_t te_rttl, te_ittl, probe_ttl;
  int nb_hops_forward, nb_hops_return;
  
  if (hop == NULL)
    return 0;
  
  te_rttl = hop->hop_reply_ttl;
  te_ittl = get_ittl(te_rttl);
  
  nb_hops_forward = hop->hop_probe_ttl;
  nb_hops_return = te_ittl - te_rttl + 1;
  
  return nb_hops_return - nb_hops_forward;
}

/*
 * Compute RTLA (return tunnel length asymmetry)
 */
static int get_rtla(scamper_trace_hop_t *hop)
{
  uint8_t te_rttl, te_ittl, er_rttl, er_ittl;
  int nb_hops_return_te, nb_hops_return_er;
  
  /* The ping reply TTL must be available */
  if (hop == NULL || (er_rttl = hop->hop_ping_rttl) == 0)
    return 0;
  te_rttl = hop->hop_reply_ttl;
  
  te_ittl = get_ittl(te_rttl);
  er_ittl = get_ittl(er_rttl);
  
  /* Router must be <255,X> with X <= 128 */
  if (te_ittl != 255 || er_ittl == 255)
    return 0;
  
  nb_hops_return_te = te_ittl - te_rttl + 1;
  nb_hops_return_er = er_ittl - er_rttl + 1;
  
  return nb_hops_return_te - nb_hops_return_er;
}

/*
 * Compute Uturn
 */
static int get_uturn(scamper_trace_hop_t *hop)
{
  uint8_t te_rttl, te_ittl, er_rttl, er_ittl;
  int nb_hops_return_te, nb_hops_return_er;
  
  /* The ping reply TTL must be available */
  if (hop == NULL || (er_rttl = hop->hop_ping_rttl) == 0)
    return 0;
  te_rttl = hop->hop_reply_ttl;
  
  te_ittl = get_ittl(te_rttl);
  er_ittl = get_ittl(er_rttl);
  
  nb_hops_return_te = te_ittl - te_rttl + 1;
  nb_hops_return_er = er_ittl - er_rttl + 1;
  
  return nb_hops_return_te - nb_hops_return_er;
}

/*
 * Print on the standard output the failure triggers for a given hop
 */
static void scamper_trace_hop_fail_trig_print(scamper_trace_hop_t *hop)
{
  if (SCAMPER_TRACE_HOP_IS_MPLS_FAIL_DUPIP(hop))
    printf(",DUPIP");
  if (SCAMPER_TRACE_HOP_IS_MPLS_FAIL_RTLA(hop))
    printf(",RTLA");
  if (SCAMPER_TRACE_HOP_IS_MPLS_FAIL_FRPLA(hop))
    printf(",FRPLA");
  if (SCAMPER_TRACE_HOP_IS_MPLS_FAIL_MTTL(hop))
    printf(",MTTL");
  return;
}

/*
 * Print on the standard output the discovery triggers for a given hop
 */
static void scamper_trace_hop_disc_trig_print(scamper_trace_hop_t *hop)
{
  /* Brute force */
  if (SCAMPER_TRACE_HOP_IS_MPLS_NO_TRIG(hop) &&
      SCAMPER_TRACE_HOP_IS_MPLS_INV(hop))
  {
    printf(",BTFC");
    return;
  }
  if (SCAMPER_TRACE_HOP_IS_MPLS_DUPIP(hop))
    printf(",DUPIP");
  if (SCAMPER_TRACE_HOP_IS_MPLS_RTLA(hop))
    printf(",RTLA");
  if (SCAMPER_TRACE_HOP_IS_MPLS_FRPLA(hop))
    printf(",FRPLA");
  if (SCAMPER_TRACE_HOP_IS_MPLS_MTTL(hop))
    printf(",MTTL");
  return;
}

/*
 * Print a TNT trace on the standard output
 */
static int scamper_trace_tnt_print(scamper_trace_t *trace)
{
  scamper_trace_hop_t *hop, *next_hop = NULL;
  scamper_icmpext_t *ie;
  char buf[64], str_rtt[24], str_tun_ttl[4];
  int i, j, k, rtla, frpla, uturn, inv = 0, mplsc;
  int previous_status = PRINT_PREV_NOT_FOUND;
  uint8_t ping_rttl;
  char method_icmp_str[] = "icmp-paris";
  char method_udp_str[] = "udp-paris";
  char *method_str;
  
  if (SCAMPER_TRACE_TYPE_IS_UDP_PARIS(trace))
    method_str = method_udp_str;
  else if (SCAMPER_TRACE_TYPE_IS_ICMP_PARIS(trace))
    method_str = method_icmp_str;
  else
  {
    logerr("Trace is not UDP-paris or ICMP-paris\n");
    return -1;
  }
  
  printf("trace [%s]", method_str);
  printf(" from %s", scamper_addr_tostr(trace->src, buf, sizeof(buf)));
  printf(" to %s\n", scamper_addr_tostr(trace->dst, buf, sizeof(buf)));
  for (i=trace->firsthop-1, k=i+1; i<trace->hop_count; i++)
  {
    /* Hop number */
    if ((hop = trace->hops[i]) == NULL)
    {
      if (inv == 0)
      {
        printf("%3d *\n", k++);
        if (previous_status == PRINT_PREV_FOUND)
        {
          inv++;
          previous_status = PRINT_PREV_NOT_FOUND;
        }
      }
      else
      {
        snprintf(str_tun_ttl, sizeof(str_tun_ttl), "H%d", inv++);
        printf("%3s *\n", str_tun_ttl);
      }
      continue;
    }
    if (SCAMPER_TRACE_HOP_IS_MPLS_REV(hop))
    {
      /* Take into account a non-responding ingress */
      if (inv == 0)
        inv++;
      snprintf(str_tun_ttl, sizeof(str_tun_ttl), "H%d", inv++);
      printf("%3s ", str_tun_ttl);
    }
    else
    {
      if (SCAMPER_TRACE_HOP_IS_MPLS_PREV(hop))
        previous_status = PRINT_PREV_FOUND;
      
      if (SCAMPER_TRACE_HOP_IS_MPLS_INV(hop) &&
          (!SCAMPER_TRACE_HOP_IS_MPLS_INTERN(hop) ||
           !SCAMPER_TRACE_HOP_IS_MPLS_IMP(hop)) &&
          (!SCAMPER_TRACE_HOP_IS_MPLS_EGR(hop) || (inv == 0)))
      {
        inv++;
      }
      else
        inv = 0;
      printf("%3d ", k++);
    }
    
    /* IP address */
    printf("%-15s", scamper_addr_tostr(hop->hop_addr, buf, sizeof(buf)));
    
    /* RTT */
    timeval_tostr(&hop->hop_rtt, str_rtt, sizeof(str_rtt));
    printf(" %s ms", str_rtt);
    
    /* Reserved IP */
    if (scamper_addr_isreserved(hop->hop_addr))
    {
      printf(" rsvd");
      printf(" rTTLs=<%d,*>", hop->hop_reply_ttl);
    }
    else
    {
      /* TTLs */
      ping_rttl = hop->hop_ping_rttl;
      if (ping_rttl <= 0)
        printf(" rTTLs=<%d,*>", hop->hop_reply_ttl);
      else
        printf(" rTTLs=<%d,%d>", hop->hop_reply_ttl, ping_rttl);
    }
    
    if (SCAMPER_TRACE_HOP_IS_ICMP_TTL_EXP(hop))
    {
      /* Quoted TTL */
      printf(" qttl=%d", hop->hop_icmp_q_ttl);
      
      /* Uturn */
      uturn = get_uturn(hop);
      if (uturn != 0)
        printf(" uturn=%d", uturn);
      
      /* FRPLA */
      frpla = get_frpla(hop);
      if (frpla > 0)
        printf(" frpla=%d", frpla);
      
      /* RTLA */
      rtla = get_rtla(hop);
      if (rtla > 0)
        printf(" rtla=%d", rtla);
    }
    
    /* MPLS hops info */
    if (SCAMPER_TRACE_HOP_IS_MPLS(hop))
    {
      printf(" [MPLS");
      
      /* Type of tunnel */
      if (!SCAMPER_TRACE_HOP_IS_MPLS_INTERN(hop))
      {
        /* Multiple types are possible for LERs */
        if (SCAMPER_TRACE_HOP_IS_MPLS_EXP(hop))
          printf(",EXP");
        if (SCAMPER_TRACE_HOP_IS_MPLS_OPA(hop))
          printf(",OPA");
        if (SCAMPER_TRACE_HOP_IS_MPLS_IMP(hop))
          printf(",IMP");
        if (SCAMPER_TRACE_HOP_IS_MPLS_INV(hop))
          printf(",INV");
      }
      else
      {
        /* Only one possible type for an internal LSR */
        if (SCAMPER_TRACE_HOP_IS_MPLS_IMP(hop))
          printf(",IMP");
        else if (SCAMPER_TRACE_HOP_IS_MPLS_OPA(hop))
          printf(",OPA");
        else if (SCAMPER_TRACE_HOP_IS_MPLS_EXP(hop))
          printf(",EXP");
        else if (SCAMPER_TRACE_HOP_IS_MPLS_INV(hop))
          printf(",INV");
        printf(",LSR");
      }
      
      /* Egress */
      if (SCAMPER_TRACE_HOP_IS_MPLS_EGR(hop))
        printf(",EGR");
      
      /* Ingress */
      if (SCAMPER_TRACE_HOP_IS_MPLS_INGR(hop))
        printf(",ING");
      
      /* Incomplete tunnel */
      if (SCAMPER_TRACE_HOP_IS_MPLS_INC(hop))
        printf(",INCOMP?");
        
      /* Trigger and signatures */
      scamper_trace_hop_disc_trig_print(hop);
      if (SCAMPER_TRACE_HOP_IS_MPLS_INFERRED(hop))
        printf(",INF");
      else
      {
        /* Implicit signatures */
        if (SCAMPER_TRACE_HOP_IS_MPLS_IMP_QT(hop))
          printf(",QTTL");
        if (SCAMPER_TRACE_HOP_IS_MPLS_IMP_UT(hop))
          printf(",UTURN");
      }
      
      /* Discovery method */
      if (SCAMPER_TRACE_HOP_IS_MPLS_REV(hop))
      {
        if (SCAMPER_TRACE_HOP_IS_MPLS_DPR(hop))
          printf(",DPR");
        else if (SCAMPER_TRACE_HOP_IS_MPLS_BRPR(hop))
          printf(",BRPR");
        else if (SCAMPER_TRACE_HOP_IS_MPLS_BUD(hop))
          printf(",BUDDY");
        else
          printf(",UNKN");
        printf(",step=%u", hop->hop_mpls_iteration);
      }
      printf("]");
    }
    
    /* MPLS labels */
    for (ie = hop->hop_icmpext; ie != NULL; ie = ie->ie_next)
    {
      if (SCAMPER_ICMPEXT_IS_MPLS(ie))
      {
        mplsc = SCAMPER_ICMPEXT_MPLS_COUNT(ie);
        if (mplsc > 0)
        {
          printf(" Labels %d mTTL=%d", SCAMPER_ICMPEXT_MPLS_LABEL(ie, 0),
                 SCAMPER_ICMPEXT_MPLS_TTL(ie, 0));
          
          for (j=1; j < mplsc; j++)
          {
            printf(" | %d mTTL=%d", SCAMPER_ICMPEXT_MPLS_LABEL(ie, j),
                   SCAMPER_ICMPEXT_MPLS_TTL(ie, j));
          }
        }
      }
    }
    
    /* Verbose display if asked */
    if (display == DISPLAY_VERB)
    {
      /* Tag unreachable messages other than port unreachable */
      if (SCAMPER_TRACE_HOP_IS_ICMP_UNREACH(hop) &&
          !SCAMPER_TRACE_HOP_IS_ICMP_UNREACH_PORT(hop))
      {
        printf(" (dstunr code=%d)", hop->hop_icmp_code);
      }
      
      /* Display triggers and revelation stop reason */
      if (SCAMPER_TRACE_HOP_HAS_MPLS_STOP_REAS(hop))
      {
        printf(" (ATTEMPT");
        scamper_trace_hop_disc_trig_print(hop);
        if (SCAMPER_TRACE_HOP_IS_MPLS_NTH_REV(hop))
          printf(",NTH-RV");
        else if (SCAMPER_TRACE_HOP_IS_MPLS_INGR_NF(hop))
          printf(",ING-NF");
        else if (SCAMPER_TRACE_HOP_IS_MPLS_TGT_NR(hop))
          printf(",TGT-NR");
        if (SCAMPER_TRACE_HOP_IS_MPLS_BUD_REP(hop))
          printf(",BUD");
        printf(")");
      }
      
      /* Display triggers and failure stop reason */
      if (SCAMPER_TRACE_HOP_HAS_MPLS_FAIL_REAS(hop))
      {
        printf(" (ATTEMPT");
        scamper_trace_hop_fail_trig_print(hop);
        if (SCAMPER_TRACE_HOP_IS_MPLS_FAIL_NTH_REV(hop))
          printf(",NTH-RV");
        else if (SCAMPER_TRACE_HOP_IS_MPLS_FAIL_INGR_NF(hop))
          printf(",ING-NF");
        else if (SCAMPER_TRACE_HOP_IS_MPLS_FAIL_TGT_NR(hop))
          printf(",TGT-NR");
        if (SCAMPER_TRACE_HOP_IS_MPLS_FAIL_BUD_REP(hop))
          printf(",BUD");
        printf(")");
      }
    }
    printf("\n");
  }
  printf("\n");
  return 0;
}

/*
 * Ping hops of a trace
 */
static int sc_tnt_test_pings(sc_tnt_test_t *tntt)
{
  scamper_trace_t *trace;
  scamper_trace_hop_t *hop;
  sc_ping_wait_t *pw = NULL;
  slist_t *addr_list = NULL;
  sc_trace_ping_t *pt;
  scamper_addr_t *addr;
  int i, rc = -1;
  uint16_t count;
  
  /* Get IP address of each hop */
  if (tntt == NULL || (trace = tntt->trace) == NULL ||
      (addr_list = slist_alloc()) == NULL ||
      scamper_trace_hops2addrs(trace, addr_list, DATA_TRACE) != 0)
  {
    logerr("Could not get IP addresses for trace\n");
    goto err;
  }
  
  /* If no hop on the path, the trace is useless */
  if ((count = slist_count(addr_list)) == 0)
  {
    rc = 0;
    goto done;
  }
  trace->probec += count * pingfpc;
  
  for (i=0; i<count; i++)
  {
    addr = slist_head_pop(addr_list);
    pw = sc_ping_wait_find(addr);
    if ((pt = sc_trace_ping_find(addr)) == NULL || pw != NULL)
    {
      tntt->pingleft++;
      /* Create a new test if needed */
      if (pw == NULL)
      {
        /* pt is necessary NULL, otherwise it would exist */
        if ((pt = sc_trace_ping_get(addr)) == NULL ||
            sc_test_waitlist(TEST_PING, pt) != 0 ||
            (pw = sc_ping_wait_get(addr)) == NULL)
        {
          logerr("Could not create a ping test\n");
          goto err;
        }
      }
      if (slist_tail_push(pw->list_tntt, tntt) == NULL)
      {
        logerr("Could not push TNT test in ping wait list\n");
        goto err;
      }
    }
    else
    {
      /* Set the ttl to the value collected previously */
      if (scamper_trace_hop_ping_rttl_set(trace, addr, pt->rttl) != 0)
      {
        logerr("Could not set ping rttl for trace hop\n");
        goto err;
      }
    }
  }
  rc = 0;
  goto done;
  
err:
  if (tntt != NULL)
    sc_tnt_test_free(tntt);
done:
  if (addr_list != NULL)
  {
    while ((addr = slist_head_pop(addr_list)) != NULL)
      scamper_addr_free(addr);
    slist_free(addr_list);
  }
  return rc;
}

/*
 * Ping LSRs of a tunnel.
 */
static int sc_tunnel_test_ping_lsrs(sc_tunnel_test_t *tunt)
{
  sc_tunnel_t *tun;
  scamper_trace_hop_t *hop;
  sc_ping_wait_t *pw = NULL;
  slist_t *addr_list = NULL;
  sc_trace_ping_t *pt;
  scamper_addr_t *addr;
  int i, rc = -1;
  uint16_t count;
  
  /* Get IP address of each hop */
  if (tunt == NULL || (tun = tunt->tunnel) == NULL ||
      (addr_list = slist_alloc()) == NULL ||
      scamper_trace_hops2addrs(tun, addr_list, DATA_TUNNEL) != 0)
  {
    logerr("Could not get IP addresses for tunnel\n");
    goto err;
  }
  
  /* No LSR */
  if ((count = slist_count(addr_list)) == 0)
  {
    rc = 0;
    goto done;
  }
  tun->probec += count * pingfpc;
  
  for (i=0; i<count; i++)
  {
    addr = slist_head_pop(addr_list);
    pw = sc_ping_wait_find(addr);
    if ((pt = sc_trace_ping_find(addr)) == NULL || pw != NULL)
    {
      tunt->pingleft++;
      /* Create a new test if needed */
      if (pw == NULL)
      {
        /* pt is necessary NULL, otherwise ping_wait would exist */
        if ((pt = sc_trace_ping_get(addr)) == NULL ||
            sc_test_waitlist(TEST_PING, pt) != 0 ||
            (pw = sc_ping_wait_get(addr)) == NULL)
        {
          logerr("Could not create a ping test\n");
          goto err;
        }
      }
      if (slist_tail_push(pw->list_tunt, tunt) == NULL)
      {
        logerr("Could not push tunnel test in ping wait list\n");
        goto err;
      }
    }
    else
    {
      /* Set the ttl to the value collected previously */
      if (sc_tunnel_lsr_ping_rttl_set(tun, addr, pt->rttl) != 0)
      {
        logerr("Could not set ping rttl for LSR\n");
        goto err;
      }
    }
  }
  rc = 0;
  goto done;
  

err:
  if (tunt != NULL)
    sc_tunnel_test_free(tunt);
  
done:
  if (addr_list != NULL)
  {
    while ((addr = slist_head_pop(addr_list)) != NULL)
      scamper_addr_free(addr);
    slist_free(addr_list);
  }
  return rc;
}

/*
 * Add an entry in the probelist
 */
static int probelist_addr(char *line, void *param)
{
  struct in_addr addr;
  void *ptr = NULL;
  
  if (line[0] == '#' || line[0] == '\0')
    return 0;
  if (inet_aton(line, &addr) != 1 ||
     (ptr = memdup(&addr, sizeof(addr))) == NULL ||
     slist_tail_push(probelist, ptr) == NULL)
  {
    if (ptr != NULL)
      free(ptr);
    {
      logerr("ERROR probelist_addr!\n");
      return -1;
    }
  }
  return 0;
}

/*
 * Clean the probelist
 */
static void probelist_empty(void)
{
  struct in_addr *addr;
  while ((addr = slist_head_pop(probelist)) != NULL)
    free(addr);
  return;
}

/*
 * Get a new test from the destinations list
 */
static sc_test_t *probelist_test(void)
{
  /* Get the next destination IP address */
  struct in_addr *addr = NULL;
  sc_tnt_test_t *tntt = NULL;
  sc_test_t *t = NULL;
  
  if (slist_count(probelist) == 0)
    return NULL;
  addr = slist_head_pop(probelist);
  
  /* Create the splaytree of TNT tests if needed */
  if (tnttests == NULL &&
      (tnttests = splaytree_alloc((splaytree_cmp_t)sc_tnt_test_cmp)) == NULL)
  {
    goto err;
  }
  
  /* Create the TNT test */
  assert(addr != NULL);
  if ((tntt = malloc_zero(sizeof(sc_tnt_test_t))) == NULL ||
      (tntt->addr = scamper_addr_alloc(SCAMPER_ADDR_TYPE_IPV4, addr)) == NULL)
  {
    goto err;
  }
  free(addr);
  addr = NULL;
  tntt->userid = userid++;
  
  /* Check is test was already performed */
  if (splaytree_find(tnttests, tntt) != NULL)
  {
    if (tntt != NULL)
    {
      if (tntt->addr != NULL)
        scamper_addr_free(tntt->addr);
      free(tntt);
    }
    return probelist_test();
  }
  /* Insert in the splaytree */
  if ((tntt->tree_node = splaytree_insert(tnttests, tntt)) == NULL)
    goto err;
  /* Create a generic measurement test */
  if ((t = sc_test_alloc(TEST_TRACE, tntt)) == NULL)
    goto err;
  
  return t;
  
err:
  if (tntt != NULL)
  {
    if (tntt->addr != NULL)
      scamper_addr_free(tntt->addr);
    free(tntt);
  }
  return NULL;
}

/*
 * Set the TNT probe TTLs.
 * During revelation, new hops are inserted in the original trace, and the
 * probe TTLs do not correspond to the output with revealed tunnels.
 * This may cause problems when reading a warts file.
 * This new probe TTL allows to build the trace correctly without modifying
 * the original probe TTL.
 */
static void scamper_trace_tnt_probe_ttl_set(scamper_trace_t *trace)
{
  int i;
  scamper_trace_hop_t *hop, *tmp_hop;
  
  if (trace == NULL)
    return;
  
  for (i=trace->firsthop-1; i<trace->hop_count; i++)
  {
    if ((hop = trace->hops[i]) != NULL)
    {
      hop->hop_tnt_probe_ttl = i+1;
      
      /* Update next hop if we received several replies (possible if timeout) */
      if (hop->hop_next != NULL)
      {
        tmp_hop = hop->hop_next;
        while (tmp_hop != NULL)
        {
          tmp_hop->hop_tnt_probe_ttl = i+1;
          tmp_hop = tmp_hop->hop_next;
        }
      }
    }
  }
  return;
}

/*
 * Update the MPLS tunnel type flag of an LSR depending on the tunnel test state
 */
static void scamper_trace_hop_tunnel_type_mflag_set(scamper_trace_hop_t *hop,
                                                    sc_tunnel_test_t *tunt)
{
  if (tunt->trigger_type == TRIG_MTTL)
    hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_OPA;
  else
    hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_INV;
  return;
}

/*
 * Set the MPLS discovery trigger flags of an LSR depending on the
 * tunnel test state
 */
static void scamper_trace_hop_disc_trig_mflags_set(scamper_trace_hop_t *hop,
                                                   sc_tunnel_test_t *tunt)
{
  switch (tunt->trigger_type)
  {
    case TRIG_RTLA:
      hop->hop_disc_mflags |= SCAMPER_TRACE_HOP_DISC_MFLAG_RTLA;
      break;
    case TRIG_FRPLA:
      hop->hop_disc_mflags |= SCAMPER_TRACE_HOP_DISC_MFLAG_FRPLA;
      break;
    case TRIG_DUP_IP:
      hop->hop_disc_mflags |= SCAMPER_TRACE_HOP_DISC_MFLAG_DUPIP;
      break;
    case TRIG_MTTL:
      hop->hop_disc_mflags |= SCAMPER_TRACE_HOP_DISC_MFLAG_MTTL;
    default:
      break;
  }
  return;
}

/*
 * Update the MPLS flags of an LSR depending on the tunnel test state
 */
static void scamper_trace_hop_mpls_flags_set(scamper_trace_hop_t *hop,
                                             sc_tunnel_test_t *tunt)
{
  if (hop == NULL)
    return;
  
  hop->hop_mpls_iteration = tunt->iteration;
  hop->hop_disc_mflags |= SCAMPER_TRACE_HOP_DISC_MFLAG_REV;
  hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_INTERN;
  
  /* Update the trigger */
  scamper_trace_hop_disc_trig_mflags_set(hop, tunt);
  scamper_trace_hop_tunnel_type_mflag_set(hop, tunt);
  
  /* Update the revelation mode */
  if (tunt->rev_mode == REV_MODE_DPR)
    hop->hop_disc_mflags |= SCAMPER_TRACE_HOP_DISC_MFLAG_DPR;
  else if (tunt->rev_mode == REV_MODE_BRPR)
    hop->hop_disc_mflags |= SCAMPER_TRACE_HOP_DISC_MFLAG_BRPR;
  else if (tunt->buddy_status == BUDDY_IP)
    hop->hop_disc_mflags |= SCAMPER_TRACE_HOP_DISC_MFLAG_BUD;
  
  /* Update the next hop if we received two replies (possible if timeout) */
  if (hop->hop_next != NULL)
    scamper_trace_hop_mpls_flags_set(hop->hop_next, tunt);

  return;
}

/*
 * Add a tunnel to a scamper trace.
 * Return the number of hops added to the trace, or -1 in case of error.
 */
static int sc_tnt_test_tunnel_add(sc_tnt_test_t *tntt, sc_tunnel_test_t *tunt)
{
  scamper_trace_t *trace;
  scamper_trace_hop_t **updated_trace_hops;
  scamper_trace_hop_t  *hop, *ingress_hop = NULL, *egress_hop = NULL, *tmphop;
  sc_tunnel_t * tun;
  slist_node_t *sn;
  int nlsr = 0, nhop = 0, ipos = -1, i, j;
  size_t size;
  
  if ((trace = tntt->trace) == NULL || (tun = tunt->tunnel) == NULL)
  {
    logerr("Could not retrieve trace or tunnel\n");
    return -1;
  }
  trace->probec += tun->probec;
  if (tun->lsp == NULL || (nlsr = slist_count(tun->lsp)) == 0 ||
      (nlsr == 1 && tntt->ingress_status == INGRESS_IS_NULL))
  {
    return 0;
  }
  
  /* Create a new hop array */
  nhop = trace->hop_count + nlsr;
  /* The non-responding ingress is already in the tunnel */
  if (tntt->ingress_status == INGRESS_IS_NULL)
    nhop -= 1;
  size = sizeof(scamper_trace_hop_t *) * nhop;
  if ((updated_trace_hops = (scamper_trace_hop_t **)malloc_zero(size)) == NULL)
    return -1;
  
  /* Find the start address */
  for (i=trace->firsthop-1, j=i; i<trace->hop_count; i++)
  {
    hop = trace->hops[i];
    updated_trace_hops[j++] = hop;
    if (hop == NULL)
      continue;
    
    /* Add LSR if start address found, ipos ensures tunnel written only once. */
    if (scamper_addr_cmp(hop->hop_addr, tun->start_addr) == 0 && ipos == -1)
    {
      /* Check if start address is not a duplicate IP address */
      if (i<trace->hop_count-1 && (tmphop = trace->hops[i+1]) != NULL &&
          scamper_addr_cmp(tmphop->hop_addr, tun->start_addr) == 0)
      {
        i++;
        updated_trace_hops[j++] = tmphop;
        hop = tmphop;
      }
      
      /* Check if the ingress was already identified or did not response */
      if (tntt->ingress_status == INGRESS_IS_START)
        ingress_hop = hop;
      else
        hop->hop_disc_mflags |= SCAMPER_TRACE_HOP_DISC_MFLAG_PREV;
      
      /* Copy the LSP */
      ipos = j;
      for (sn=slist_head_node(tun->lsp); sn != NULL; sn=slist_node_next(sn))
        updated_trace_hops[j++] = scamper_trace_hop_copy(slist_node_item(sn));
      /* Ensure the ingress is not responding if needed (rare case) */
      if (tntt->ingress_status == INGRESS_IS_NULL &&
          updated_trace_hops[ipos] != NULL)
      {
        /* Happens only if complete tunnel was revealed previously */
        scamper_trace_hop_free(updated_trace_hops[ipos]);
        updated_trace_hops[ipos] = NULL;
      }
      
      i++;
      if (i >= trace->hop_count)
      {
        logerr("Ingress not found in trace\n");
        free(updated_trace_hops);
        return -1;
      }
      
      /* The next hop may be an ingress that did not respond */
      if ((hop = trace->hops[i]) == NULL)
      {
        /* Skip the ingress (already in the tunnel) */
        if (tntt->ingress_status == INGRESS_IS_NULL)
          i++;
        else
        {
          logerr("Ingress not null\n");
          free(updated_trace_hops);
          return -1;
        }
      }

      /* Check if next hop is the tunnel exit point */
      hop = trace->hops[i];
      if (scamper_addr_cmp(hop->hop_addr, tun->next_addr) != 0)
      {
        logerr("Tunnel end hop not found\n");
        free(updated_trace_hops);
        return -1;
      }
      
      /* The egress is the last hop of the discovered LSRs with duplicate IP */
      if (tunt->trigger_type == TRIG_DUP_IP)
      {
        if ((tmphop = updated_trace_hops[j-1]) != NULL)
        {
          egress_hop = tmphop;
          /* Delete the internal MPLS LSR flag */
          egress_hop->hop_types_mflags &= lsr_mask;
        }
      }
      else
        egress_hop = hop;
      updated_trace_hops[j++] = hop;
    }
  }
  
  /* Update ingress/egress/LH MPLS flags */
  if (ingress_hop != NULL)
  {
    scamper_trace_hop_disc_trig_mflags_set(ingress_hop, tunt);
    scamper_trace_hop_tunnel_type_mflag_set(ingress_hop, tunt);
    ingress_hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_INGR;
    if (tun->tun_status == TUN_STATUS_INCOMPL)
      ingress_hop->hop_disc_mflags |= SCAMPER_TRACE_HOP_DISC_MFLAG_INC;
  }
  if (egress_hop != NULL)
  {
    scamper_trace_hop_disc_trig_mflags_set(egress_hop, tunt);
    scamper_trace_hop_tunnel_type_mflag_set(egress_hop, tunt);
    egress_hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_EGR;
  }
  
  free(trace->hops);
  trace->hop_count = nhop;
  trace->hops = updated_trace_hops;
  return nlsr;
}

/*
 * Set the failure MPLS flags for a hop with a positive invisible trigger and
 * no revelation.
 * Return -1 if the hop is not found.
 */
static int sc_trace_tunnel_fail_mflags_set(scamper_trace_t *trace,
                                           sc_tunnel_t *tunnel)
{
  scamper_trace_hop_t  *hop, *start_hop = NULL;
  int i;
 
  /* Find the hop */
  for (i=trace->firsthop-1; i<trace->hop_count; i++)
  {
    hop = trace->hops[i];
    if (hop == NULL)
      continue;
    
    /* Find the start hop */
    if (scamper_addr_cmp(hop->hop_addr, tunnel->start_addr) == 0)
      start_hop = trace->hops[i];
    if (start_hop == NULL)
      continue;
    
    /* Set the flags */
    if (scamper_addr_cmp(hop->hop_addr, tunnel->next_addr) == 0)
    {
      hop->hop_fail_mflags = tunnel->next_addr_fail_mflags;
      return 0;
    }
  }
  logerr("Could not set failure MPLS flags\n");
  return -1;
}

/*
 * Try to run an invisible/opaque tunnel discovery, if any.
 * The list of invisible tunnel tests is read.
 * Stops at the first test
 *       - containing a tunnel with LSRs that were revealed previously, or
 *       - containing a tunnel that was not revealed so far.
 * Return value:
 *       RET_NO_TUNNEL      no tunnel test was found in the trace,
 *                          and no discovery should be run
 *       RET_TRACE_UPDATED  the trace in the TNT test was updated with
 *                          a tunnel previously revealed
 *       RET_DISCOVERY_RUN  a new tunnel discovery was run
 */
static int sc_tnt_test_tunnel_discovery_run(sc_tnt_test_t *tntt)
{
  sc_tunnel_wait_t *tw = NULL;
  sc_tunnel_test_t *tunt = NULL;
  int nlsrs;
  
  if (tntt == NULL)
  {
    logerr("TNT test does not exist\n");
    goto err;
  }
  
  /* Check if an invisible tunnel test is available */
  if (tntt->invtuntests == NULL || slist_count(tntt->invtuntests) == 0)
    return RET_NO_TUNNEL;

  /* Get the tunnel test */
  if ((tunt = slist_head_pop(tntt->invtuntests)) == NULL)
  {
    logerr("Could not retrieve the tunnel test associated to TNT test\n");
    goto err;
  }
  tntt->ingress_status = tunt->ingress_status;
  
  tw = sc_tunnel_wait_find(tunt->start_addr, tunt->next_addr);
  
  /* Get the tunnel, if any already existing */
  tunt->tunnel = sc_tunnel_find(tunt->start_addr, tunt->next_addr);
  
  /* Check if the tunnel was already revealed previously */
  if (tw == NULL && tunt->tunnel != NULL)
  {
    /* Add the tunnel to the trace, if hops were discovered */
    nlsrs = sc_tnt_test_tunnel_add(tntt, tunt);
    if (nlsrs == -1)
    {
      logerr("LSRs could not be added to trace\n");
      goto err;
    }
    
    /* No LSR was revealed, try with the next tunnel test, if any */
    if (nlsrs == 0)
    {
      if (sc_trace_tunnel_fail_mflags_set(tntt->trace, tunt->tunnel) == -1)
        goto err;
      sc_tunnel_test_free(tunt);
      return sc_tnt_test_tunnel_discovery_run(tntt);
    }
    sc_tunnel_test_free(tunt);
    return RET_TRACE_UPDATED;
  }
  
  /* Get the tunnel wait, if any, or create a new one  */
  if (tw == NULL)
  {
    /* Run a new discovery */
    if ((tw = sc_tunnel_wait_get(tunt->start_addr, tunt->next_addr)) == NULL
        || sc_test_waitlist(TEST_TRACE_DISC, tunt) != 0)
    {
      logerr("Could not add tunnel test to discovery test list\n");
      goto err;
    }
  }
  else
    sc_tunnel_test_free(tunt);
  
  /* Update the tunnel wait with the TNT test */
  if (slist_tail_push(tw->list, tntt) == NULL)
  {
    logerr("Could not add TNT test to tunnel wait list\n");
    goto err;
  }
  return RET_DISCOVERY_RUN;
  
err:
  if (tw != NULL)
  {
    sc_tunnel_wait_detach(tw);
    sc_tunnel_wait_free(tw);
  }
  if (tunt != NULL)
    sc_tunnel_test_free(tunt);
  return -1;
}

/*
 * Check if a hop tagged as ingress and egress is a Juniper node.
 * If so, the node is implicit and tagged as internal LSR.
 * Returns 0 if the inference succeeded, 1 otherwise.
 */
static int identify_juniper_implicit_hop(scamper_trace_hop_t *hop)
{
  uint8_t te_rttl, te_ittl, er_rttl, er_ittl;
  
  /* Check if Juniper router (qTTL is 1 or 0, otherwise not egress) */
  if ((er_rttl = hop->hop_ping_rttl) != 0)
  {
    te_rttl = hop->hop_reply_ttl;
    te_ittl = get_ittl(te_rttl);
    er_ittl = get_ittl(er_rttl);
    /* Router must be <255,64> */
    if (te_ittl == 255 && er_ittl == 64)
    {
      hop->hop_types_mflags &= clear_lsr_type_mask;
      hop->hop_types_mflags &= clear_tun_type_mask;
      hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_INTERN;
      hop->hop_disc_mflags &= clear_trig_mask;
      return 0;
    }
  }
  return 1;
}

/*
 * Identify implicit MPLS tunnels based on the Uturn trigger.
 * This function must be called after having revealed hidden MPLS tunnels.
 */
static int scamper_trace_tnt_identify_uturn_tunnels(scamper_trace_t *trace)
{
  scamper_trace_hop_t *hop, *tmp_hop;
  int i, j, uturn = 0, absuturn = 0, rtla = 0, usum = 0;
  int tmp_uturn = 0, tmp_rtla = 0;
  int next_egress_status = UTURN_NEXT_NOT_EGRESS;
  
  /* Get the trace, if any */
  if (trace == NULL)
  {
    logerr("Trace not found for u-turn identification\n");
    return -1;
  }
  
  /* Check if enough nodes */
  if ((trace->hop_count - trace->firsthop) < 2)
    return 0;
  
  for (i=trace->firsthop-1; i<trace->hop_count; i++)
  {
    /* Compute the current uturn value */
    hop = trace->hops[i];
    uturn = get_uturn(hop);
    absuturn = abs(uturn);
    /* Do not infer a tunnel if rtla and uturn have the same value */
    rtla = get_rtla(hop);
    
    /* Flag the egress */
    if (next_egress_status == UTURN_NEXT_EGRESS)
    {
      if (hop != NULL && !SCAMPER_TRACE_HOP_IS_MPLS_INTERN_OR_REV(hop))
      {
        /* Check for duplicate IP */
        tmp_hop = trace->hops[i-1];
        if (tmp_hop != NULL &&
            scamper_addr_cmp(hop->hop_addr, tmp_hop->hop_addr) == 0)
        {
          if (SCAMPER_TRACE_HOP_IS_MPLS_INGR(hop))
            hop->hop_types_mflags &= clear_lsr_type_mask;
          hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_INTERN;
          hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_IMP_UT;
          continue;
        }
        /* IP is not duplicate */
        if ((absuturn < UTURN_SEQ_THRESHOLD || rtla == uturn) &&
            (!SCAMPER_TRACE_HOP_IS_MPLS_INGR(hop) ||
             identify_juniper_implicit_hop(hop) != 0))
        {
          hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_EGR;
          hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_IMP_UT;
        }
      }
      next_egress_status = UTURN_NEXT_NOT_EGRESS;
    }
    
    /* End of the sequence */
    if (uturn == 0 || rtla == uturn || i == trace->hop_count-1 ||
        SCAMPER_TRACE_HOP_IS_MPLS_INTERN_OR_REV(hop) ||
        SCAMPER_TRACE_HOP_IS_MPLS_OPA_EGR(hop))
    {
      /* Implicit tunnel expected, flag the nodes */
      if (usum >= UTURN_SEQ_THRESHOLD)
      {
        if (hop == NULL || (!SCAMPER_TRACE_HOP_IS_MPLS_OPA_EGR(hop) &&
            !SCAMPER_TRACE_HOP_IS_MPLS_INTERN_OR_REV(hop)))
        {
          next_egress_status = UTURN_NEXT_EGRESS;
        }
        /* Current node should be the last hop */
        if (hop != NULL && !SCAMPER_TRACE_HOP_IS_MPLS_INTERN_OR_REV(hop) &&
            !SCAMPER_TRACE_HOP_IS_MPLS_OPA_EGR(hop))
        {
          if (SCAMPER_TRACE_HOP_IS_MPLS_INGR(hop) ||
              SCAMPER_TRACE_HOP_IS_MPLS_EGR(hop))
          {
            hop->hop_types_mflags &= clear_lsr_type_mask;
          }
          hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_IMP_UT;
          /* If destination of the trace, flag as egress */
          if (scamper_addr_cmp(hop->hop_addr, trace->dst) == 0)
            hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_EGR;
          else
            hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_INTERN;
        }
        
        for (j=i-1; j>=trace->firsthop-1; j--)
        {
          tmp_hop = trace->hops[j];
          if (tmp_hop == NULL ||
              SCAMPER_TRACE_HOP_IS_MPLS_INTERN_OR_REV(tmp_hop))
          {
            break;
          }
              
          tmp_uturn = get_uturn(tmp_hop);
          tmp_rtla = get_rtla(tmp_hop);
          if (tmp_uturn == 0 || tmp_rtla == tmp_uturn)
          {
            /* Current node should be the ingress node */
            /* If hop tagged as ingress and egress, it could be implicit */
            if (!SCAMPER_TRACE_HOP_IS_MPLS_EGR(tmp_hop) ||
                SCAMPER_TRACE_HOP_IS_MPLS_OPA_EGR(tmp_hop) ||
                identify_juniper_implicit_hop(tmp_hop) != 0)
            {
              tmp_hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_INGR;
              tmp_hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_IMP_UT;
            }
            break;
          }
          if (SCAMPER_TRACE_HOP_IS_MPLS_INGR(tmp_hop) ||
              SCAMPER_TRACE_HOP_IS_MPLS_EGR(tmp_hop))
          {
            tmp_hop->hop_types_mflags &= clear_lsr_type_mask;
          }
          tmp_hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_INTERN;
          tmp_hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_IMP_UT;
        }
      }
      else if (i == trace->hop_count-1 &&
               absuturn >= UTURN_SEQ_THRESHOLD &&
               rtla != uturn &&
               scamper_addr_cmp(hop->hop_addr, trace->dst) != 0 &&
               !SCAMPER_TRACE_HOP_IS_MPLS_INTERN(hop))
      {
        /* Last hop in trace not the destination and uturn trigger */
        hop->hop_types_mflags &= clear_lsr_type_mask;
        hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_INTERN;
        hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_IMP_UT;
      }
      usum = 0;
      continue;
    }
    usum += absuturn;
  }
  return 0;
}

/*
 * Try to reveal the next tunnel in the list of invisible tunnels
 */
static int sc_tnt_test_tunnel_reveal(sc_tnt_test_t *tntt)
{
  int nrun;
  
  /* Run a tunnel discovery, if any invisible tunnel on the path */
  if (tntt->trace == NULL ||
      (nrun = sc_tnt_test_tunnel_discovery_run(tntt)) == -1)
  {
    logerr("Could not run tunnel discovery\n");
    return -1;
  }
  
  /* If no test, output the complete TNT */
  if (nrun == RET_NO_TUNNEL || nrun == RET_TRACE_UPDATED)
  {
    scamper_trace_tnt_probe_ttl_set(tntt->trace);
    /* Find implicit tunnels based on uturn trigger */
    scamper_trace_tnt_identify_uturn_tunnels(tntt->trace);
    if (scamper_file_write_obj(outfile,
                               SCAMPER_FILE_OBJ_TRACE, tntt->trace) != 0)
    {
      logerr("Could not write TNT trace into output file\n");
      return -1;
    }
    sc_tnt_test_detach(tntt);
    sc_tnt_test_free(tntt);
  }
  return 0;
}

/*
 * Notifies TNT tests that a tunnel revelation is complete.
 */
static int sc_tnt_tunnel_test_completed(sc_tunnel_test_t *tunt)
{
  sc_tunnel_wait_t *tw = NULL;
  scamper_trace_t *trace;
  sc_tnt_test_t *tntt;
  scamper_trace_hop_t *hop;
  sc_tunnel_t *tun;
  int nlsrs = 0, nadded_lsrs = 0, nrun, rc = -1;
  
  /* Get the tunnel associated to the tunnel test */
  if ((tun = tunt->tunnel) == NULL)
  {
    logerr("Tunnel not found for tunnel test\n");
    goto done;
  }
  
  /* Get the corresponding tunnel wait */
  if ((tw = sc_tunnel_wait_find(tunt->start_addr, tunt->next_addr)) == NULL)
  {
    logerr("Tunnel wait not found for tunnel test\n");
    goto done;
  }
  
  if (tun->lsp)
    nlsrs = slist_count(tun->lsp);
  
  /* LSRs were revealed */
  while ((tntt = slist_head_pop(tw->list)) != NULL)
  {
    nadded_lsrs = sc_tnt_test_tunnel_add(tntt, tunt);
    /* Add the tunnel to the trace */
    if ((trace = tntt->trace) == NULL || nadded_lsrs == -1)
    {
      logerr("Could not add tunnel to trace\n");
      goto done;
    }
    
    /* No LSR was added */
    if (nadded_lsrs == 0)
    {
      trace->probec += tun->probec;
      if (sc_trace_tunnel_fail_mflags_set(trace, tun) == -1 ||
          sc_tnt_test_tunnel_reveal(tntt) == -1)
      {
        logerr("Could not set fail flags or could not run new discovery\n");
        goto done;
      }
    }
    else
    {
      /* Write the TNT trace */
      scamper_trace_tnt_probe_ttl_set(trace);
      /* Find implicit tunnels based on uturn trigger */
      scamper_trace_tnt_identify_uturn_tunnels(trace);
      if (scamper_file_write_obj(outfile, SCAMPER_FILE_OBJ_TRACE, trace) != 0)
      {
        logerr("Could not write TNT trace into output file\n");
        goto done;
      }
      sc_tnt_test_detach(tntt);
      sc_tnt_test_free(tntt);
    }
  }
  rc = 0;
  
done:
  if (tw != NULL)
  {
    sc_tunnel_wait_detach(tw);
    sc_tunnel_wait_free(tw);
  }
  if (tunt != NULL)
    sc_tunnel_test_free(tunt);
  return rc;
}

/*
 * Get LSRs that were revealed during a trace and store them in the input list.
 * The LSRs are in the opposite order in the list.
 * Return value:
 *       REV_NEW_LSRS             new LSRs were revealed
 *       REV_EMPTY                no new LSR was revealed
 *       REV_INGR_NOT_FOUND       ingress router not found, tunnel incomplete
 *       REV_TARGET_NOT_REACHED   target not reached, trace incomplete
 */
static int scamper_trace_revealed_lsrs_get(scamper_trace_t *trace,
                                           sc_tunnel_test_t *tunt,
                                           slist_t *rev_lsrs)
{
  scamper_trace_hop_t *hop, *hop2, *nxthop;
  slist_node_t *sn;
  int i, nlsrs, nhops = trace->hop_count - trace->firsthop;
  
  /* Check if the target was reached */
  if ((hop = trace->hops[trace->hop_count-1]) == NULL)
    return REV_TARGET_NOT_REACHED;
  
  /* Check if we revealed an internal address when targeting a buddy address */
  if (tunt->probing_mode == PROB_MODE_TRACE_BUDDY)
  {
    /* Destination not reached */
    if (!SCAMPER_TRACE_HOP_IS_ICMP_UNREACH_PORT(hop))
      return REV_TARGET_NOT_REACHED;
    
    /* Buddy is the start router */
    if (scamper_addr_cmp(hop->hop_addr, tunt->start_addr) == 0)
      return REV_EMPTY;
    
    /* Check if start address is visible */
    if (tunt->ingress_status == INGRESS_IS_NULL)
    {
      if (nhops < 3)
        return REV_INGR_NOT_FOUND;
      hop2 = trace->hops[trace->hop_count-3];
    }
    else
    {
      if (nhops < 2)
        return REV_INGR_NOT_FOUND;
      hop2 = trace->hops[trace->hop_count-2];
    }

    if (hop2 == NULL ||
        scamper_addr_cmp(hop2->hop_addr, tunt->start_addr) != 0)
    {
      return REV_INGR_NOT_FOUND;
    }
    
    /* No public node was revealed */
    if (scamper_addr_cmp(hop->hop_addr, tunt->target_addr) == 0 ||
        scamper_addr_cmp(hop->hop_addr, tunt->next_addr) == 0)
    {
      return REV_EMPTY;
    }
    
    /* Update the MPLS flags */
    scamper_trace_hop_mpls_flags_set(hop, tunt);
    
    /* Egress is found */
    if (slist_head_push(rev_lsrs, hop) == NULL)
    {
      logerr("Could not add buddy egress to revealed LSRs\n");
      slist_empty(rev_lsrs);
      return -1;
    }
    /* Dereference the hop to avoid suppression when the trace will be freed */
    trace->hops[trace->hop_count-1] = NULL;
    return REV_NEW_LSRS;
  }
  
  /* For other revelation trace, the target must have been reached */
  if (scamper_addr_cmp(hop->hop_addr, tunt->target_addr) != 0)
    return REV_TARGET_NOT_REACHED;

  /* The start address should be visible in the trace */
  for (i=trace->firsthop-1; i<trace->hop_count; i++)
  {
    if ((hop = trace->hops[i]) == NULL)
      continue;
  
    if (scamper_addr_cmp(hop->hop_addr, tunt->start_addr) == 0)
    {
      /* Check if start address is not a duplicate IP address */
      if (i<trace->hop_count-1 && (nxthop = trace->hops[i+1]) != NULL &&
          scamper_addr_cmp(nxthop->hop_addr, tunt->start_addr) == 0)
      {
        i++;
      }
      break;
    }
  }
  /* The end of the trace is reached, the ingress was not found */
  if (i == trace->hop_count)
    return REV_INGR_NOT_FOUND;
  
  /* Check if the start address is the ingress address */
  if (tunt->ingress_status == INGRESS_IS_NULL)
    i++;
  
  /* The next hop is the target, no LSR was revealed */
  if (i >= trace->hop_count - 2)
    return REV_EMPTY;

  i++;
  while (i<trace->hop_count-1)
  {
    hop = trace->hops[i];
    /* Push the new LSR in the list, in the reverse order */
    if (slist_head_push(rev_lsrs, hop) == NULL)
    {
      logerr("Could not add new hop to revealed LSRs\n");
      slist_empty(rev_lsrs);
      return -1;
    }
    /* Dereference the hop to avoid suppression when the trace will be freed */
    trace->hops[i] = NULL;
    i++;
  }
  
  /* Check if BRPR or DPR step */
  nlsrs = slist_count(rev_lsrs);
  if (nlsrs == 1)
    tunt->rev_mode = REV_MODE_BRPR;
  else if (slist_count(rev_lsrs) > 2)
    tunt->rev_mode = REV_MODE_DPR;
  else
  {
    tunt->rev_mode = REV_MODE_DPR;
    /* Check for duplicate addresses */
    sn = slist_head_node(rev_lsrs);
    hop = slist_node_item(sn);
    sn = slist_node_next(sn);
    hop2 = slist_node_item(sn);
    if (hop != NULL && hop2 != NULL &&
        scamper_addr_cmp(hop->hop_addr, hop2->hop_addr) == 0)
    {
      tunt->rev_mode = REV_MODE_BRPR;
    }
  }
  
  /* Update the MPLS flags */
  for (sn=slist_head_node(rev_lsrs); sn != NULL; sn=slist_node_next(sn))
  {
    hop = slist_node_item(sn);
    scamper_trace_hop_mpls_flags_set(hop, tunt);
  }
  return REV_NEW_LSRS;
}

/*
 * Update the tunnel buddy state
 */
static int sc_tunnel_test_buddy_state_update(sc_tunnel_test_t *tunt)
{
  scamper_addr_t **prefix30 = NULL;
  sc_buddy_wait_t *bw = NULL;
  sc_buddy_test_t *bt = NULL;
  sc_buddy_t *buddy;
  int rc = -1, i;
  
  /* Check if a buddy was already tested */
  if (tunt->buddy_status == BUDDY_IP)
  {
    if (tunt->target_addr != NULL)
      scamper_addr_free(tunt->target_addr);
    tunt->target_addr = NULL;
    rc = 0;
    goto done;
  }
  
  if (tunt->target_addr == NULL)
  {
    logerr("No target found for tunnel test\n");
    return -1;
  }
  
  /* Get a buddy_wait, if existing */
  bw = sc_buddy_wait_find(tunt->target_addr);
  
  if (bw == NULL &&
      (buddy = sc_buddy_find(tunt->target_addr)) != NULL)
  {
    /* The buddy already exists */
    if (buddy->buddy_addr != NULL && tunt->target_addr != NULL)
    {
      tunt->buddy_status = BUDDY_IP;
      tunt->probing_mode = PROB_MODE_TRACE_BUDDY;
      scamper_addr_free(tunt->target_addr);
      tunt->target_addr = scamper_addr_use(buddy->buddy_addr);
      rc = 0;
    }
    else
      logerr("Buddy does not exist\n");
    goto done;
  }
  
  if (bw == NULL)
  {
    /* Get the /30 prefix */
    if ((prefix30 = get_prefix30_addresses(tunt->target_addr)) == NULL)
    {
      logerr("Could not determine /30 prefix for buddy search\n");
      goto err;
    }
    
    /* Check if address in /31 */
    for (i=0; i < 4; i++)
    {
      if (scamper_addr_cmp(prefix30[i], tunt->target_addr) == 0)
      {
        if (i == 0)
        {
          /* /31 prefix, buddy is address 1 */
          scamper_addr_free(tunt->target_addr);
          tunt->target_addr = scamper_addr_use(prefix30[1]);
          tunt->buddy_status = BUDDY_IP;
          tunt->probing_mode = PROB_MODE_TRACE_BUDDY;
          rc = 0;
          goto done;
        }
        else if (i == 3)
        {
          /* /31 prefix, buddy is address 2 */
          scamper_addr_free(tunt->target_addr);
          tunt->target_addr = scamper_addr_use(prefix30[2]);
          tunt->buddy_status = BUDDY_IP;
          tunt->probing_mode = PROB_MODE_TRACE_BUDDY;
          rc = 0;
          goto done;
        }
        else
        {
          /* /30 prefix, need to ping address 0 */
          if ((bt = malloc_zero(sizeof(sc_buddy_test_t))) == NULL)
            goto err;
          bt->addr = scamper_addr_use(tunt->target_addr);
          bt->target_addr = scamper_addr_use(prefix30[0]);
          bt->prefix30 = prefix30;
          bt->addr_pos = i;
          
          /* Insert a test in the splaytree */
          if ((bt->tree_node = splaytree_insert(buddytests, bt)) == NULL)
          {
            logerr("Buddy test could not be inserted in splaytree\n");
            goto err;
          }
          
          /* Run the test */
          if ((bt->buddy = sc_buddy_get(tunt->target_addr)) == NULL ||
            sc_test_waitlist(TEST_PING_BUDDY, bt) != 0)
          {
            logerr("Buddy not found or buddy ping test not added to list\n");
            goto err;
          }
          /* Create a buddy wait */
          if ((bw = sc_buddy_wait_get(tunt->target_addr)) == NULL)
          {
            logerr("Could not create buddy wait\n");
            goto err;
          }
          break;
        }
      }
    }
  }
  
  /* A buddy wait already exists */
  if (slist_tail_push(bw->list, tunt) == NULL)
  {
    logerr("Tunnel test could not be added to buddy wait list\n");
    goto err;
  }
  tunt->probing_mode = PROB_MODE_PING_BUDDY;
  scamper_addr_free(tunt->target_addr);
  tunt->target_addr = NULL;
  return 0;

err:
  if (bw != NULL)
  {
    sc_buddy_wait_detach(bw);
    sc_buddy_wait_free(bw);
  }
  if (bt != NULL)
  {
    sc_buddy_test_detach(bt);
    sc_buddy_test_free(bt);
  }
done:
  if (prefix30 != NULL)
    free_prefix30_array(prefix30);
  return rc;
}

/*
 * Update the tunnel test state based on the discovered nodes
 */
static int sc_tunnel_test_state_update(sc_tunnel_test_t *tunt,
                                       slist_t *rev_lsrs,
                                       int rev_state)
{
  scamper_trace_hop_t *fh;
  slist_node_t *sn;
  int i, rc = -1;
  tunt->rev_mode = REV_MODE_NONE;
  
  /* Ingress not found or target not reached */
  if (rev_state == REV_INGR_NOT_FOUND || rev_state == REV_TARGET_NOT_REACHED)
  {
    /* UHP */
    if (tunt->trigger_type == TRIG_DUP_IP &&
        sc_tunnel_test_buddy_state_update(tunt) == -1)
    {
      logerr("Could not update buddy state\n");
      return -1;
    }
    return 0;
  }
  
  if (rev_state == REV_EMPTY)
  {
    /* No hop was discovered */
    
    /* PHP */
    if (tunt->trigger_type != TRIG_DUP_IP)
    {
      tunt->probing_mode = PROB_MODE_TRACE;
      return 0;
    }
    
    /* UHP */
    if (sc_tunnel_test_buddy_state_update(tunt) == -1)
    {
      logerr("Could not update buddy state\n");
      return -1;
    }
    return 0;
  }

  /* Some hops were discovered */
  if ((sn = slist_tail_node(rev_lsrs)) == NULL)
  {
    logerr("Could not get first LSR in revealed LSRs list\n");
    return -1;
  }
  fh = slist_node_item(sn);
  
  if (tunt->target_addr != NULL)
    scamper_addr_free(tunt->target_addr);
  
  /* Check if no response from the first node */
  if (fh == NULL)
    tunt->target_addr = NULL;
  else
  {
    /* Avoid loops in revelation */
    if (scamper_addr_in_sc_tunnel_lsp(fh->hop_addr, tunt->tunnel) != 0 &&
        !scamper_addr_isreserved(fh->hop_addr))
    {
      tunt->target_addr = scamper_addr_use(fh->hop_addr);
    }
    else
      tunt->target_addr = NULL;
  }

  tunt->iteration++;
  tunt->buddy_status = BUDDY_IP_NONE;
  tunt->probing_mode = PROB_MODE_TRACE;
  return 0;
}

/*
 * Add the discovered hops to the tunnel structure stored in the tunnel test
 */
static int sc_tunnel_test_hops_add(sc_tunnel_test_t *tunt, slist_t *rev_lsrs)
{
  sc_tunnel_t *tun;
  scamper_trace_hop_t *hop;
  slist_node_t *sn;
  
  /* Get the tunnel */
  if (tunt->tunnel == NULL &&
      (tunt->tunnel = sc_tunnel_get(tunt->start_addr, tunt->next_addr)) == NULL)
  {
    logerr("Tunnel could not be found in tunnel test\n");
    return -1;
  }
  
  /* Check if hops were discovered */
  if (rev_lsrs == NULL || slist_count(rev_lsrs) == 0)
    return 0;
  
  /* Update the tunnel */
  tun = tunt->tunnel;
  if (tun->lsp == NULL && (tun->lsp = slist_alloc()) == NULL)
  {
    logerr("LSP not found in tunnel\n");
    return -1;
  }
  
  for (sn=slist_head_node(rev_lsrs); sn != NULL; sn=slist_node_next(sn))
  {
    hop = slist_node_item(sn);
    if (slist_head_push(tun->lsp, hop) == NULL)
    {
      logerr("Could not add hop to LSP\n");
      scamper_trace_hop_list_free(rev_lsrs);
      scamper_trace_hop_list_free(tun->lsp);
      return -1;
    }
  }
  slist_empty(rev_lsrs);
  return 0;
}

/*
 * Set the failure MPLS flags for a given tunnel test.
 */
static void sc_tunnel_test_fail_mflags_set(sc_tunnel_test_t *tunt,
                                           uint8_t rev_state)
{
  sc_tunnel_t *tunnel;
  /* Get the tunnel */
  if ((tunnel = tunt->tunnel) == NULL)
    return;
  
  /* Set the buddy flag if needed */
  if (tunt->probing_mode == PROB_MODE_TRACE_BUDDY)
    tunnel->next_addr_fail_mflags |= SCAMPER_TRACE_HOP_FAIL_MFLAG_BUD_REP;
  
  /* Set the failure type  */
  switch (rev_state)
  {
    case REV_INGR_NOT_FOUND:
      tunnel->next_addr_fail_mflags |= SCAMPER_TRACE_HOP_FAIL_MFLAG_INGR_NF;
      break;
    case REV_TARGET_NOT_REACHED:
      tunnel->next_addr_fail_mflags |= SCAMPER_TRACE_HOP_FAIL_MFLAG_TGT_NR;
      break;
    case REV_EMPTY:
      tunnel->next_addr_fail_mflags |= SCAMPER_TRACE_HOP_FAIL_MFLAG_NTH_REV;
      break;
    default:
      break;
  }
  /* Set the trigger  */
  switch (tunt->trigger_type)
  {
    case TRIG_RTLA:
      tunnel->next_addr_fail_mflags |= SCAMPER_TRACE_HOP_FAIL_MFLAG_RTLA;
      break;
    case TRIG_FRPLA:
      tunnel->next_addr_fail_mflags |= SCAMPER_TRACE_HOP_FAIL_MFLAG_FRPLA;
      break;
    case TRIG_DUP_IP:
      tunnel->next_addr_fail_mflags |= SCAMPER_TRACE_HOP_FAIL_MFLAG_DUPIP;
      break;
    case TRIG_MTTL:
      tunnel->next_addr_fail_mflags |= SCAMPER_TRACE_HOP_FAIL_MFLAG_MTTL;
      break;
    default:
      break;
  }
  return;
}

/*
 * Set the discovery MPLS flags for a given tunnel test.
 */
static void sc_tunnel_test_disc_mflags_set(sc_tunnel_test_t *tunt,
                                           uint8_t rev_state)
{
  sc_tunnel_t *tunnel;
  scamper_trace_hop_t *hop;
  slist_node_t *sn;
  
  /* Get the tunnel */
  if ((tunnel = tunt->tunnel) == NULL)
    return;
  
  /* Find the node that must be updated */
  if ((sn = slist_head_node(tunnel->lsp)) != NULL)
  {
    hop = slist_node_item(sn);
    if (hop == NULL)
      return;
  }
  
  /* Set the buddy flag if needed */
  if (tunt->probing_mode == PROB_MODE_TRACE_BUDDY)
    hop->hop_disc_mflags |= SCAMPER_TRACE_HOP_DISC_MFLAG_BUD_REP;
  
  /* Set the stop reason flags  */
  switch (rev_state)
  {
    case REV_INGR_NOT_FOUND:
      hop->hop_disc_mflags |= SCAMPER_TRACE_HOP_DISC_MFLAG_INGR_NF;
      break;
    case REV_TARGET_NOT_REACHED:
      hop->hop_disc_mflags |= SCAMPER_TRACE_HOP_DISC_MFLAG_TGT_NR;
      break;
    case REV_EMPTY:
      hop->hop_disc_mflags |= SCAMPER_TRACE_HOP_DISC_MFLAG_NTH_REV;
      break;
    default:
      break;
  }
  /* Set the trigger flags */
  scamper_trace_hop_disc_trig_mflags_set(hop, tunt);
  return;
}


/*
 * Set the trigger and stop reason MPLS flags for a tunnel test.
 */
static void sc_tunnel_test_end_mflags_set(sc_tunnel_test_t *tunt,
                                           uint8_t rev_state)
{
  sc_tunnel_t *tunnel;
  
  /* Get the tunnel */
  if ((tunnel = tunt->tunnel) == NULL)
    return;
  
  /* Check if a tunnel was revealed and set the right flags */
  if (tunnel->lsp != NULL && slist_count(tunnel->lsp) > 0)
    sc_tunnel_test_disc_mflags_set(tunt, rev_state);
  else
    sc_tunnel_test_fail_mflags_set(tunt, rev_state);
}

/*
 * Update a tunnel test with a discovery trace
 */
static int sc_tunnel_test_update(sc_tunnel_test_t *tunt, scamper_trace_t *trace)
{
  scamper_trace_hop_t *hop;
  sc_tunnel_t *tun;
  slist_t *rev_lsrs;
  slist_node_t *sn;
  int rev_state;
  int rc = -1;
  
  /* Create the list for the new LSRs */
  if ((rev_lsrs = slist_alloc()) == NULL)
    goto done;
  
  /* Get the new LSRs, if any */
  if ((rev_state =
       scamper_trace_revealed_lsrs_get(trace, tunt, rev_lsrs)) == -1)
  {
    logerr("Could not get revealed LSRs\n");
    goto done;
  }
  
  /* Update the tunnel test state, if needed */
  if (sc_tunnel_test_state_update(tunt, rev_lsrs, rev_state) == -1)
  {
    logerr("Could not update tunnel test state\n");
    goto done;
  }
  /* Add the discovered hops in the tunnel, if any */
  if (sc_tunnel_test_hops_add(tunt, rev_lsrs) == -1)
  {
    logerr("Could not add LSRs in tunnel\n");
    goto done;
  }
  
  /* Add the number of probes that were sent */
  if ((tun = tunt->tunnel) != NULL)
    tun->probec += trace->probec;
  
  if (rev_state == REV_NEW_LSRS)
  {
    /* Hidden hops were discovered */
    if (tunt->target_addr != NULL)
    {
      /* Continue the revelation */
      rc = sc_test_waitlist(TEST_TRACE_DISC, tunt);
      if (rc == -1)
        logerr("Could not add tunnel test to discovery list\n");
      goto done;
    }
    else
    {
      /* No new target after a revelation */
      if (tun != NULL)
        tun->tun_status = TUN_STATUS_INCOMPL;
    }
  }
  else
  {
    /* No hop was discovered */
    
    /* Try with a buddy address, if available */
    if (tunt->probing_mode == PROB_MODE_TRACE_BUDDY &&
        tunt->target_addr != NULL)
    {
      rc = sc_test_waitlist(TEST_TRACE_DISC, tunt);
      if (rc == -1)
        logerr("Could not add tunnel test to discovery list\n");
      goto done;
    }
  
    /* Buddy ping requested */
    if (tunt->probing_mode == PROB_MODE_PING_BUDDY)
    {
      tun->probec += pingfpc;
      rc = 0;
      goto done;
    }

    /* Mark the first hop to specify the tunnel may be incomplete */
    if (tun != NULL && (tun->lsp != NULL) && rev_state != REV_EMPTY &&
        slist_count(tun->lsp) > 0 && tunt->buddy_status != BUDDY_IP)
    {
      tun->tun_status = TUN_STATUS_INCOMPL;
    }
    sc_tunnel_test_end_mflags_set(tunt, rev_state);
  }
  
  /* If only one discovered hop, change its revelation method to unknown */
  if (tun != NULL && tun->lsp != NULL && slist_count(tun->lsp) == 1)
  {
    if ((sn = slist_head_node(tun->lsp)) != NULL)
    {
      hop = slist_node_item(sn);
      if (hop != NULL)
        hop->hop_disc_mflags &= unkown_rev_mask;
    }
  }
  
  /* Impossible to reveal more LSRs */
  /* Check if the ingress responded */
  if (tunt->ingress_status == INGRESS_IS_NULL)
  {
    if (slist_head_push(rev_lsrs, NULL) == NULL)
    {
      logerr("Could not add empty hop as ingress\n");
      goto done;
    }
    if (sc_tunnel_test_hops_add(tunt, rev_lsrs) == -1)
    {
      logerr("Could not add revealed LSRs\n");
      goto done;
    }
  }
  
  /* Revelation is done, start pings */
  tunt->probing_mode = PROB_MODE_PING;
  if (sc_tunnel_test_ping_lsrs(tunt) == -1)
  {
    logerr("Could not ping tunnel LSRs\n");
    goto done;
  }
  
  /* If no ping is needed, the tunnel is complete */
  if (tunt->pingleft == 0)
  {
    if (sc_tnt_tunnel_test_completed(tunt) == -1)
    {
      logerr("Could not end tunnel test\n");
      goto done;
    }
  }
  rc = 0;
  
done:
  if (trace != NULL)
    scamper_trace_free(trace);
  if (rev_lsrs != NULL)
    scamper_trace_hop_list_free(rev_lsrs);
  return rc;
}

/*
 * Add an invisible/opaque tunnel test to a TNT test
 */
static int sc_tnt_test_tunnel_test_add(sc_tnt_test_t *tntt,
                                       scamper_addr_t *start_addr,
                                       scamper_addr_t *next_addr,
                                       uint8_t startttl,
                                       uint8_t trigger_type,
                                       uint8_t ingress_status)
{
  sc_tunnel_test_t *tunt;
  
  /* Create the list of invisible tunnel tests */
  if (tntt == NULL ||
      (tntt->invtuntests == NULL &&
      (tntt->invtuntests = slist_alloc()) == NULL))
  {
    logerr("Could not create a list for invisible tunnel tests\n");
    return -1;
  }
  
  /* Create an invisible tunnel test and add it to the list */
  if ((tunt = sc_tunnel_test_alloc(start_addr, next_addr,
                                   startttl, trigger_type,
                                   tntt->userid, ingress_status)) == NULL)
  {
    return -1;
  }
  
  /* Add the test to the list of future possible tests to be driven */
  if (slist_tail_push(tntt->invtuntests, tunt) == NULL)
    goto err;
  return 0;
  
err:
  logerr("Could not add tunnel test to list of invisible tunnel tests\n");
  sc_tunnel_test_free(tunt);
  return -1;
}

/*
 * Identify MPLS tunnels and LSRs, if explicit, implicit or opaque.
 * Note that only qTTL implicit tunnels are identified, uturn tunnels must
 * be identified after invisible tunnels have been revealed.
 * If an invisible or opaque tunnel is suspected, it is added in the
 * list of invisible tunnels to investigate.
 */
static int sc_tnt_test_identify_mpls_tunnels(sc_tnt_test_t *tntt)
{
  scamper_trace_t     *trace;
  scamper_addr_t      *start_addr = NULL;
  scamper_trace_hop_t *prev_hop = NULL, *hop = NULL, *ingress_hop = NULL;
  scamper_trace_hop_t *tmp_hop = NULL, *first_hop = NULL, *second_hop = NULL;
  scamper_trace_hop_t *start_hop;
  scamper_icmpext_t   *ie;
  uint8_t              ingress_status, mttl;
  uint8_t              te_rttl, te_ittl, er_ttl, er_ittl;
  int                  i = 0, startttl = 1, rtla, frpla;
  
  /* Get the trace, if any */
  if (tntt->trace == NULL)
  {
    logerr("Not TNT trace found\n");
    return -1;
  }
  trace = tntt->trace;
  
  /* Check if enough nodes */
  if ((trace->hop_count - trace->firsthop) < 2)
    return 0;
  
  for (i=trace->firsthop-1; i<trace->hop_count; i++)
  {
    /* Get hop if any response */
    if ((hop = trace->hops[i]) == NULL)
    {
      /* Check if previous hop is not opaque */
      if (prev_hop != NULL && SCAMPER_TRACE_HOP_IS_MPLS_OPA(prev_hop))
      {
        prev_hop->hop_types_mflags &= clear_lsr_type_mask;
        prev_hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_EGR;
      }
      goto cont;
    }
    
    /* Hop for future analyses */
    if (i > trace->firsthop)
      tmp_hop = trace->hops[i-2];
   
    /* Consider only time-exceeded messages, except to close a tunnel */
    if (SCAMPER_TRACE_HOP_IS_ICMP_TTL_EXP(hop))
    {
      /* MPLS labels -> Explicit or Opaque */
      for (ie = hop->hop_icmpext; ie != NULL; ie = ie->ie_next)
      {
        if (SCAMPER_ICMPEXT_IS_MPLS(ie) && SCAMPER_ICMPEXT_MPLS_COUNT(ie) > 0)
        {
          /* Get the MPLS TTL for the top label */
          mttl = SCAMPER_ICMPEXT_MPLS_TTL(ie, 0);
          
          /* Flag as MPLS hop */
          hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_INTERN;
          
          /* Triggers 1/2: labels -> Explicit/opaque depending on mTTL value */
          if (mttl <= 1 || mttl == 255)
            hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_EXP;
          else
          {
            hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_OPA;
            hop->hop_disc_mflags |= SCAMPER_TRACE_HOP_DISC_MFLAG_MTTL;
          }
          
          /* Identify ingress */
          if (prev_hop != NULL && !SCAMPER_TRACE_HOP_IS_MPLS_INTERN(prev_hop))
          {
            /* If hop tagged as ingress and egress, it could be implicit */
            if (SCAMPER_TRACE_HOP_IS_MPLS_EGR(prev_hop) &&
                identify_juniper_implicit_hop(prev_hop) == 0)
            {
              goto cont;
            }
            
            /* Otherwise, should be a real ingress */
            prev_hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_INGR;
            if (SCAMPER_TRACE_HOP_IS_MPLS_OPA(hop))
            {
              prev_hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_OPA;
              prev_hop->hop_disc_mflags |= SCAMPER_TRACE_HOP_DISC_MFLAG_MTTL;
            }
            else
              prev_hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_EXP;
          }
          goto cont;
        }
      }
      
      /* Trigger 3: q-TTL > 1 -> Implicit */
      if (hop->hop_icmp_q_ttl > 1 && hop->hop_icmp_q_ttl != 255)
      {
        /* Flag the hop */
        hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_INTERN;
        hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_IMP_QT;
        
        /* Identify the entry of the tunnel */
        if (hop->hop_icmp_q_ttl == 2)
        {
          /* First LSR */
          if (prev_hop != NULL && prev_hop->hop_icmp_q_ttl <= 1 &&
              !SCAMPER_TRACE_HOP_IS_MPLS_INTERN(prev_hop) &&
              !SCAMPER_TRACE_HOP_IS_MPLS_OPA_EGR(prev_hop))
          {
            /* Flag the first LSR */
            prev_hop->hop_types_mflags &= clear_lsr_type_mask;
            prev_hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_INTERN;
            prev_hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_IMP_QT;
          }
          else if (prev_hop != NULL)
            goto cont;
          
          /* Ingress hop */
          if (tmp_hop != NULL && !SCAMPER_TRACE_HOP_IS_MPLS_INTERN(tmp_hop) &&
              !SCAMPER_TRACE_HOP_IS_MPLS_INGR(tmp_hop) &&
              (!SCAMPER_TRACE_HOP_IS_MPLS_EGR(tmp_hop) ||
               identify_juniper_implicit_hop(tmp_hop) != 0))
          {
            tmp_hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_INGR;
            tmp_hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_IMP_QT;
          }
        }
        goto cont;
      }
    }
    
    /* Identify egress hops for explicit, implicit, and opaque tunnels */
    if (prev_hop != NULL)
    {
      /* Previous hop must be an LSR */
      if (!SCAMPER_TRACE_HOP_IS_MPLS_INTERN(prev_hop))
        goto cont;
      
      if (SCAMPER_TRACE_HOP_IS_MPLS_EXP(prev_hop))
      {
        hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_EGR;
        hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_EXP;
      }
      else if (SCAMPER_TRACE_HOP_IS_MPLS_IMP(prev_hop))
      {
        /* For implicit tunnels, egress is one hop after qTTL <= 1 */
        hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_IMP_QT;
        if (scamper_addr_cmp(hop->hop_addr, trace->dst) == 0 ||
            (prev_hop->hop_icmp_q_ttl <= 1 &&
             scamper_addr_cmp(hop->hop_addr, prev_hop->hop_addr) != 0))
        {
          hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_EGR;
        }
        else
          hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_INTERN;
      }
      else if (SCAMPER_TRACE_HOP_IS_MPLS_OPA(prev_hop))
      {
        prev_hop->hop_types_mflags &= clear_lsr_type_mask;
        prev_hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_EGR;
      }
    }
    else if (tmp_hop != NULL && SCAMPER_TRACE_HOP_IS_MPLS_IMP(tmp_hop) &&
             tmp_hop->hop_icmp_q_ttl > 1)
    {
      hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_EGR;
      hop->hop_types_mflags |= SCAMPER_TRACE_HOP_TYPES_MFLAG_IMP_QT;
    }

  cont:
    prev_hop = trace->hops[i];
  }

  /* Special loop for invisible tunnels, mandatory due to potential overlap
     with implicit tunnels */
  prev_hop = NULL;
  for (i=trace->firsthop-1; i<trace->hop_count; i++)
  {
    /* Get hop if any public response, not involved in another tunnel */
    if ((hop = trace->hops[i]) == NULL ||
        scamper_addr_isreserved(hop->hop_addr) ||
        SCAMPER_TRACE_HOP_IS_MPLS_INTERN(hop))
    {
      goto continv;
    }
    
    /* Get previous hops */
    if (i > trace->firsthop+1)
      first_hop = trace->hops[i-3];
    if (i > trace->firsthop)
      second_hop = trace->hops[i-2];
    
    /* Duplicate IP address */
    if (prev_hop != NULL &&
        scamper_addr_cmp(prev_hop->hop_addr, hop->hop_addr) == 0)
    {
      /* First IP is already tagged for another tunnel */
      if (SCAMPER_TRACE_HOP_IS_MPLS_EGR(prev_hop) ||
          SCAMPER_TRACE_HOP_IS_MPLS_INTERN(prev_hop))
      {
        goto continv;
      }
      ingress_hop = second_hop;
      start_hop = first_hop;
    }
    else
    {
      ingress_hop = prev_hop;
      start_hop = second_hop;
    }
    
    /* Ingress can not be inside an implicit or explicit tunnel */
    if (ingress_hop != NULL && !SCAMPER_TRACE_HOP_IS_MPLS_OPA(hop) &&
        SCAMPER_TRACE_HOP_IS_MPLS_INTERN(ingress_hop))
    {
      goto continv;
    }
    
    /* Get the start and ingress hops */
    if (ingress_hop == NULL)
    {
      if (start_hop == NULL || scamper_addr_isreserved(start_hop->hop_addr))
        goto continv;
      start_addr = start_hop->hop_addr;
      ingress_status = INGRESS_IS_NULL;
      tmp_hop = start_hop;
    }
    else
    {
      if (scamper_addr_isreserved(ingress_hop->hop_addr))
        goto continv;
      ingress_status = INGRESS_IS_START;
      start_addr = ingress_hop->hop_addr;
      tmp_hop = ingress_hop;
    }
    
    /* Get the probing start TTL */
    if (tmp_hop->hop_probe_ttl > STARTTTL_OFF)
      startttl = tmp_hop->hop_probe_ttl - STARTTTL_OFF;
    else
      startttl = 1;

    /* Ingress and egress are the same router */
    if (scamper_addr_cmp(start_addr, hop->hop_addr) == 0)
      goto continv;
    
    /* An opaque tunnel is found */
    if (SCAMPER_TRACE_HOP_IS_MPLS_OPA_EGR(hop))
    {
      /* Add a new tunnel test to the TNT test */
      if ((sc_tnt_test_tunnel_test_add(tntt, start_addr,
                                       hop->hop_addr, startttl,
                                       TRIG_MTTL, ingress_status)) == -1)
      {
        logerr("Tunnel test could not be added to TNT test\n");
        return -1;
      }
      goto continv;
    }
    
    /* Egress can not be already an egress for another tunnel.
       Triggers are computed on time-exceeded messages. */
    if (SCAMPER_TRACE_HOP_IS_MPLS_EGR(hop) ||
        !SCAMPER_TRACE_HOP_IS_ICMP_TTL_EXP(hop))
    {
      goto continv;
    }
    
    /* Trigger 4: Duplicate IP address -> Invisible, UHP */
    if (prev_hop != NULL &&
        scamper_addr_cmp(prev_hop->hop_addr, hop->hop_addr) == 0)
    {
      /* Add a new tunnel test to the TNT test */
      if ((sc_tnt_test_tunnel_test_add(tntt, start_addr,
                                       hop->hop_addr, startttl,
                                       TRIG_DUP_IP, ingress_status)) == -1)
      {
        logerr("Tunnel test could not be added to TNT test\n");
        return -1;
      }
      goto continv;
    }
    
    /* Test if potential egress is not a duplicate IP */
    if (i+1<trace->hop_count && (tmp_hop = trace->hops[i+1]) != NULL &&
        scamper_addr_cmp(tmp_hop->hop_addr, hop->hop_addr) == 0 &&
        SCAMPER_TRACE_HOP_IS_ICMP_TTL_EXP(tmp_hop))
    {
      goto continv;
    }
    
    /* Trigger 5: RTLA -> Invisible */
    rtla = get_rtla(hop);
    if (rtla >= rtlathresh)
    {
      /* Add a new tunnel test to the TNT test */
      if ((sc_tnt_test_tunnel_test_add(tntt, start_addr,
                                       hop->hop_addr, startttl,
                                       TRIG_RTLA, ingress_status)) == -1)
      {
        logerr("Tunnel test could not be added to TNT test\n");
        return -1;
      }
      goto continv;
    }
    
    /* Trigger 6: FRPLA -> Invisible */
    frpla = get_frpla(hop);
    if (frpla >= frplathresh)
    {
      /* Add a new tunnel test to the TNT test */
      if ((sc_tnt_test_tunnel_test_add(tntt, start_addr,
                                       hop->hop_addr, startttl,
                                       TRIG_FRPLA, ingress_status)) == -1)
      {
        logerr("Tunnel test could not be added to TNT test\n");
        return -1;
      }
    }
    
    /* Brute force, if asked */
    if (brutef == BRUTE_FORCE_ENA)
    {
      /* Add a new tunnel test to the TNT test */
      if ((sc_tnt_test_tunnel_test_add(tntt, start_addr,
                                       hop->hop_addr, startttl,
                                       TRIG_NONE, ingress_status)) == -1)
      {
        logerr("Tunnel test could not be added to TNT test\n");
        return -1;
      }
    }

  continv:
    prev_hop = trace->hops[i];
  }
  return 0;
}

/*
 * Read the ping sent to the address 0 of a /30 prefix to discover a buddy.
 */
static int sc_buddy_test_ping_read(sc_buddy_test_t *bt, scamper_ping_t *ping)
{
  scamper_ping_reply_t *reply;
  sc_buddy_wait_t *bw = NULL;
  sc_buddy_t *buddy;
  sc_tunnel_test_t *tunt;
  int i, rc = -1, resp = 0;
  
  /* Buddy is incomplete */
  if ((buddy = bt->buddy) == NULL)
  {
    logerr("Buddy not found\n");
    goto done;
  }
  
  for (i=0; i<ping->ping_sent; i++)
  {
    if ((reply = ping->ping_replies[i]) == NULL)
      continue;
    /* The address 0 of the prefix responded. The prefix is a /31 */
    if (scamper_addr_cmp(reply->addr, bt->prefix30[0]) == 0)
    {
      resp = 1;
      switch (bt->addr_pos)
      {
        /* Address 1, buddy is address 0 */
        case 1:
          buddy->buddy_addr = scamper_addr_use(bt->prefix30[0]);
          break;
        
        /* Address 2, buddy is address 3 */
        case 2:
          buddy->buddy_addr = scamper_addr_use(bt->prefix30[3]);
          break;
          
        default:
          goto done;
      }
      break;
    }
  }
  
  if (resp == 0)
  {
    /* Did not get a response from the address 0. The prefix is a /30 */
    switch (bt->addr_pos)
    {
        /* Address 1, buddy is address 2 */
      case 1:
        buddy->buddy_addr = scamper_addr_use(bt->prefix30[2]);
        break;
        
        /* Address 2, buddy is address 1 */
      case 2:
        buddy->buddy_addr = scamper_addr_use(bt->prefix30[1]);
        break;
        
      default:
        goto done;
    }
  }
  
  /* Warn the different tunnel tests */
  if ((bw = sc_buddy_wait_find(bt->addr)) == NULL)
  {
    logerr("Buddy wait not found\n");
    goto done;
  }
  
  /* Notifies tunnel_tests awaiting for the ping */
  while ((tunt = slist_head_pop(bw->list)) != NULL)
  {
    if (tunt->target_addr != NULL)
      scamper_addr_free(tunt->target_addr);
    tunt->target_addr = scamper_addr_use(buddy->buddy_addr);
    tunt->buddy_status = BUDDY_IP;
    tunt->probing_mode = PROB_MODE_TRACE_BUDDY;
    if (sc_test_waitlist(TEST_TRACE_DISC, tunt) != 0)
    {
      logerr("Could not add tunnel test to discovery list\n");
      goto done;
    }
  }
  rc = 0;
  
done:
  if (bt != NULL)
  {
    sc_buddy_test_detach(bt);
    sc_buddy_test_free(bt);
  }
  if (bw != NULL)
  {
    sc_buddy_wait_detach(bw);
    sc_buddy_wait_free(bw);
  }
  return rc;
}

/*
 * Get the destination of a TNT test
 */
static scamper_addr_t *do_method_trace_addr(void *data)
{
  sc_tnt_test_t *tntt = data;
  return tntt->addr;
}

/*
 * Get the destination of a tunnel test
 */
static scamper_addr_t *do_method_trace_disc_addr(void *data)
{
  sc_tunnel_test_t *tunt = data;
  return tunt->target_addr;
}

/*
 * Get the scamper command to run paris-traceroute
 */
static int do_method_trace_cmd(void *data, char *cmd, size_t len)
{
  static const char *tm[] =
  {
    "icmp-paris",
    "udp-paris",
  };
  sc_tnt_test_t *tntt = data;
  size_t off = 0;
  char dst[32];
  
  /* Get the trace destination and the command */
  scamper_addr_tostr(tntt->addr, dst, sizeof(dst));
  string_concat(cmd, len, &off,
                "trace -f %d -l 1 -P %s -U %u -w 1 -q 3 -g 5 %s\n",
                startttl, tm[method], tntt->userid, dst);
  return off;
}

/*
 * Get the scamper command to run a paris-traceroute tunnel discovery
 */
static int do_method_trace_disc_cmd(void *data, char *cmd, size_t len)
{
  static const char *tm[] =
  {
    "icmp-paris",
    "udp-paris",
  };
  sc_tunnel_test_t *tunt = data;
  size_t off = 0;
  char dst[32];
  const char *trace_method = tm[method];
  
  /* Force UDP paris for buddy discovery */
  if (tunt->buddy_status == BUDDY_IP)
    trace_method = "udp-paris";
  
  /* Get the trace destination and the command */
  scamper_addr_tostr(tunt->target_addr, dst, sizeof(dst));
  string_concat(cmd, len, &off,
                "trace -f %u -P %s -U %u -w 1 -q 3 -g 5 %s\n",
                tunt->trace_sttl, trace_method, tunt->userid, dst);
  return off;
}

/* 
 * Get the destination of a ping 
 */
static scamper_addr_t *do_method_ping_addr(void *data)
{
  sc_trace_ping_t *pt = data;
  return pt->addr;
}

/*
 * Get the destination of a ping to a buddy
 */
static scamper_addr_t *do_method_ping_buddy_addr(void *data)
{
  sc_buddy_test_t *bt = data;
  return bt->target_addr;
}

/*
 * Get the scamper command to run ping
 */
static int do_method_ping_cmd(void *data, char *cmd, size_t len)
{
  sc_trace_ping_t *pt = data;
  size_t off = 0;
  char dst[32];
  
  /* Get the ping destination and the command */
  scamper_addr_tostr(pt->addr, dst, sizeof(dst));
  string_concat(cmd, len, &off, "ping -P icmp-echo -c %d %s\n",
                pingfpc, dst);
  return off;
}

/*
 * Get the scamper command to run ping to a buddy
 */
static int do_method_ping_buddy_cmd(void *data, char *cmd, size_t len)
{
  sc_buddy_test_t *bt = data;
  size_t off = 0;
  char dst[32];
  
  /* Get the ping destination and the command */
  scamper_addr_tostr(bt->target_addr, dst, sizeof(dst));
  string_concat(cmd, len, &off, "ping -P icmp-echo -c %d %s\n",
                pingfpc, dst);
  return off;
}

/*
 * Run TNT measurements
 */
static int do_method(void)
{
  /* Gets for trace and ping destinations */
  static scamper_addr_t *(*const af[])(void *) =
  {
    do_method_trace_addr,
    do_method_trace_disc_addr,
    do_method_ping_addr,
    do_method_ping_buddy_addr,
  };
  /* Gets for commands that will be sent to the scamper daemon */
  static int (*const cf[])(void *, char *, size_t) =
  {
    do_method_trace_cmd,
    do_method_trace_disc_cmd,
    do_method_ping_cmd,
    do_method_ping_buddy_cmd,
  };
  sc_test_t *t = NULL;
  scamper_addr_t *addr;
  sc_target_t *tg;
  size_t off;
  char cmd[256];
  
  /* Scamper does not ask for more task */
  if (more < 1)
    return 0;
  
  for(;;)
  {
    /* Get a measurement test */
    if (slist_count(waitlist) > 0)
      t = slist_head_pop(waitlist);
    else if (slist_count(probelist) > 0)
      t = probelist_test();
    else
      return 0;
    if (t == NULL)
    {
      if (slist_count(probelist) > 0)
      {
        logerr("do_method: probe list not empty\n");
        return -1;
      }
      else
        return 0;
    }
    
    /* Get the destination address of the test */
    addr = af[t->type](t->data);
    /* Get the corresponding target if existing */
    if ((tg = sc_target_find(addr)) != NULL)
    {
      /* Target with same test, do not measure again */
      if (tg->type == t->type && tg->data == t->data)
        break;
      
      /* Target with different test. Add the current test to blocked list */
      if (sc_target_block(tg, t) != 0)
      {
        logerr("do_method: could not add test to blocklist.\n");
        return -1;
      }
      continue;
    }
    /* Create the corresponding target */
    else if ((tg = sc_target_get(addr, t->type, t->data)) == NULL)
    {
      logerr("do_method: could not get target.\n");
      return -1;
    }
    break;
  }
  
  /* Got a command, send it */
  off = cf[t->type](t->data, cmd, sizeof(cmd));
  sc_test_free(t);
  write_wrap(scamper_fd, cmd, NULL, off);
  probing++;
  more--;
  logprint("p %d, w %d, l %d : %s", probing,
           slist_count(waitlist), slist_count(probelist), cmd);
  printf("p %d, w %d, l %d : %s", probing,
         slist_count(waitlist), slist_count(probelist), cmd);
  return 0;
}

/*
 * Decode and read binary ping 
 */
static int do_decoderead_ping(scamper_ping_t *ping)
{
  sc_tnt_test_t *tntt;
  sc_tunnel_test_t *tunt;
  sc_tunnel_t *tun;
  sc_buddy_test_t *bt;
  scamper_trace_t *trace;
  sc_trace_ping_t *pt;
  sc_target_t *tg = NULL;
  sc_ping_wait_t *pw = NULL;
  char buf[64];
  int rc = -1, nrun;
  uint8_t rttl;
  
  /* Get the target based on the destination */
  if ((tg = sc_target_find(ping->dst)) == NULL)
  {
    logerr("do_decoderead_ping: could not find target for %s\n",
           scamper_addr_tostr(ping->dst, buf, sizeof(buf)));
    goto done;
  }
  
  /* Ping for a buddy */
  if (tg->type == TEST_PING_BUDDY)
  {
    bt = tg->data;
    rc = sc_buddy_test_ping_read(bt, ping);
    goto done;
  }
  
  /* Get the rttl */
  rttl = scamper_ping_reply_ttl_get(ping);
  
  /* Ping for trace or tunnel */
  assert(tg->type == TEST_PING);
  
  pt = tg->data;
  pt->rttl = rttl;
  
  /* Get the ping wait */
  if ((pw = sc_ping_wait_find(ping->dst)) == NULL)
    goto done;
  
  /* Notifies TNT tests awaiting for the ping */
  while ((tntt = slist_head_pop(pw->list_tntt)) != NULL)
  {
    /* Get the trace associated to the TNT test */
    if ((trace = tntt->trace) == NULL)
    {
      logerr("do_decoderead_ping: could not find ttun for hop %s\n",
             scamper_addr_tostr(ping->dst, buf, sizeof(buf)));
      goto done;
    }
    if (scamper_trace_hop_ping_rttl_set(trace, ping->dst, rttl) != 0)
    {
      logerr("do_decoderead_ping: could not find hop %s\n",
             scamper_addr_tostr(ping->dst, buf, sizeof(buf)));
      goto done;
    }
    
    /* Update the TNT tests stats */
    tntt->pingleft--;
    /* All pings were collected */
    if (tntt->pingleft == 0)
    {
      /* Identify and reveal MPLS tunnels */
      if (sc_tnt_test_identify_mpls_tunnels(tntt) == -1 ||
          sc_tnt_test_tunnel_reveal(tntt) == -1)
      {
        goto done;
      }
    }
  }
  
  /* Notifies tunnel tests awaiting for the ping */
  while ((tunt = slist_head_pop(pw->list_tunt)) != NULL)
  {
    /* Get the tunnel associated to the tunnel_test */
    if ((tun = tunt->tunnel) == NULL)
    {
      logerr("do_decoderead_ping: could not find tunnel for hop %s\n",
             scamper_addr_tostr(ping->dst, buf, sizeof(buf)));
      goto done;
    }
    /* Update the rttl */
    if (sc_tunnel_lsr_ping_rttl_set(tun, ping->dst, rttl) != 0)
    {
      logerr("do_decoderead_ping: could not find hop %s\n",
             scamper_addr_tostr(ping->dst, buf, sizeof(buf)));
      goto done;
    }
    
    /* Update the tunnel tests stats */
    tunt->pingleft--;
    /* All pings were collected, notifies TNT tests */
    if (tunt->pingleft == 0)
    {
      /* Notifies TNT tests awaiting for the tunnel */
      if (sc_tnt_tunnel_test_completed(tunt) == -1)
      {
        logerr("Could not notify TNT test of a completion\n");
        goto done;
      }
    }
  }
  rc = 0;

done:
  if (ping != NULL)
    scamper_ping_free(ping);
  if (pw != NULL)
  {
    sc_ping_wait_detach(pw);
    sc_ping_wait_free(pw);
  }
  if (tg != NULL)
  {
    sc_target_detach(tg);
    sc_target_free(tg);
  }
  return rc;
}

/*
 * Decode and read binary trace
 */
static int do_decoderead_trace(scamper_trace_t *trace)
{
  sc_target_t *tg;
  sc_tnt_test_t *tntt = NULL;
  sc_tunnel_test_t *tunt = NULL;
  char buf[64];
  
  /* Get the target corresponding to the trace destination */
  if ((tg = sc_target_find(trace->dst)) == NULL)
  {
    logerr("do_decoderead_trace: target %s could not be found.\n",
           scamper_addr_tostr(trace->dst, buf, sizeof(buf)));
    goto err;
  }
  
  /* Trace for tunnel discovery */
  if (tg->type == TEST_TRACE_DISC)
  {
    tunt = tg->data;
    sc_target_detach(tg);
    sc_target_free(tg);

    /* Update the tunnel test with the new discovered hop, if any */
    if (sc_tunnel_test_update(tunt, trace) == -1)
    {
      logerr("do_decoderead_trace: could not update tunnel test\n");
      goto err;
    }
    return 0;
  }
  
  assert(tg->type == TEST_TRACE);
  tntt = tg->data;
  sc_target_detach(tg);
  sc_target_free(tg);
  tntt->trace = trace;
  
  /* Flag the trace as a tunnel discovery trace */
  trace->flags |= SCAMPER_TRACE_FLAG_TNT;
  
  /* Enter ping mode */
  if (sc_tnt_test_pings(tntt) == -1)
  {
    logerr("do_decoderead_trace: hops could not be read.\n");
    goto err;
  }
  
  /* No need to ping, try to reveal tunnels */
  if (tntt->pingleft == 0)
  {
    if (tntt->trace == NULL ||
        sc_tnt_test_identify_mpls_tunnels(tntt) == -1 ||
        sc_tnt_test_tunnel_reveal(tntt) == -1)
    {
      logerr("do_decoderead_trace: tunnel detection failed.\n");
      goto err;
    }
  }
  return 0;
  
err:
  if (trace != NULL)
    scamper_trace_free(trace);
  if (tntt != NULL)
    sc_tnt_test_free(tntt);
  if (tunt != NULL)
    sc_tunnel_test_free(tunt);
  return -1;
}

/* 
 * Read and decode binary data sent by the scamper daemon.
 * The data may be a trace or a ping.
 */
static int do_decoderead(void)
{
  void     *data;
  uint16_t  type;
  
  /* Try and read from the warts decoder */
  if (scamper_file_read(decode_in, ffilter, &type, &data) != 0)
  {
    logerr("do_decoderead: scamper_file_read errno %d\n", errno);
    return -1;
  }
  if (data == NULL)
    return 0;
  probing--;
  
  /* Decode binary ping */
  if (type == SCAMPER_FILE_OBJ_PING)
    return do_decoderead_ping(data);
  /* Decode binary trace */
  else if (type == SCAMPER_FILE_OBJ_TRACE)
    return do_decoderead_trace(data);
  
  logerr("do_decoderead: object type not expected\n");
  return -1;
}

/* 
 * Read input from the scamper daemon 
 */
static int do_scamperread(void)
{
  ssize_t rc;
  uint8_t uu[64];
  char   *ptr, *head;
  char    buf[512];
  void   *tmp;
  long    l;
  size_t  i, uus, linelen;
  
  /* Read the input and put in in the readbuf */
  if ((rc = read(scamper_fd, buf, sizeof(buf))) > 0)
  {
    if (readbuf_len == 0)
    {
      if ((readbuf = memdup(buf, rc)) == NULL)
      {
        logerr("do_scamperread: could not memdup %d bytes\n", rc);
        return -1;
      }
      readbuf_len = rc;
    }
    else
    {
      if ((tmp = realloc(readbuf, readbuf_len + rc)) != NULL)
      {
        readbuf = tmp;
        memcpy(readbuf+readbuf_len, buf, rc);
        readbuf_len += rc;
      }
      else
      {
        logerr("do_scamperread: could not realloc %d bytes", readbuf_len+rc);
        return -1;
      }
    }
  }
  else if (rc == 0)
  {
    close(scamper_fd);
    scamper_fd = -1;
  }
  else if (errno == EINTR || errno == EAGAIN)
  {
    return 0;
  }
  else
  {
    logerr("could not read: errno %d\n", errno);
    return -1;
  }
  
  /* Process whatever is in the readbuf */
  if (readbuf_len == 0)
    return 0;
  
  head = readbuf;
  for (i=0; i<readbuf_len; i++)
  {
    if (readbuf[i] == '\n')
    {
      /* Skip empty lines */
      if (head == &readbuf[i])
      {
        head = &readbuf[i+1];
        continue;
      }
      
      /* Calculate the length of the line, excluding newline */
      linelen = &readbuf[i] - head;
      
      /* If currently decoding data, then pass it to uudecode */
      if (data_left > 0)
      {
        uus = sizeof(uu);
        if (uudecode_line(head, linelen, uu, &uus) != 0)
        {
          logerr("could not uudecode_line\n");
          return -1;
        }
        
        if (uus != 0)
          write_wrap(decode_out_fd, uu, NULL, uus);
        
        data_left -= (linelen + 1);
      }
      /* If the scamper process is asking for more tasks, give it more */
      else if (linelen == 4 && strncasecmp(head, "MORE", linelen) == 0)
      {
        more++;
        if (do_method() != 0)
          return -1;
      }
      /* New piece of data */
      else if(linelen > 5 && strncasecmp(head, "DATA ", 5) == 0)
      {
        l = strtol(head+5, &ptr, 10);
        if (*ptr != '\n' || l < 1)
        {
          head[linelen] = '\0';
          logerr("could not parse %s\n", head);
          return -1;
        }
        
        data_left = l;
      }
      /* Feedback letting us know that the command was accepted */
      else if (linelen >= 2 && strncasecmp(head, "OK", 2) == 0)
      {
        /* Nothing to do */
      }
      /* Feedback letting us know that the command was not accepted */
      else if (linelen >= 3 && strncasecmp(head, "ERR", 3) == 0)
      {
        more++;
        if (do_method() != 0)
          return -1;
      }
      else
      {
        head[linelen] = '\0';
        logerr("unknown response '%s'\n", head);
        return -1;
      }
      
      head = &readbuf[i+1];
    }
  }
  
  if (head != &readbuf[readbuf_len])
  {
    readbuf_len = &readbuf[readbuf_len] - head;
    ptr = memdup(head, readbuf_len);
    free(readbuf);
    readbuf = ptr;
  }
  else
  {
    readbuf_len = 0;
    free(readbuf);
    readbuf = NULL;
  }
  return 0;
}

/* 
 * Establish a connection with the scamper daemon 
 */
static int do_scamperconnect(void)
{
  struct sockaddr_un sun;
  struct sockaddr_in sin;
  struct in_addr in;
  
  if (options & OPT_PORT)
  {
    inet_aton("127.0.0.1", &in);
    sockaddr_compose((struct sockaddr *)&sin, AF_INET, &in, port);
    if ((scamper_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    {
      logerr("could not allocate new socket\n");
      return -1;
    }
    if (connect(scamper_fd, (const struct sockaddr *)&sin, sizeof(sin)) != 0)
    {
      logerr("could not connect to scamper process\n");
      return -1;
    }
    return 0;
  }
  else if (options & OPT_UNIX)
  {
    if (sockaddr_compose_un((struct sockaddr *)&sun, unix_name) != 0)
    {
      logerr("could not build sockaddr_un\n");
      return -1;
    }
    if ((scamper_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
    {
      logerr("could not allocate unix domain socket\n");
      return -1;
    }
    if (connect(scamper_fd, (const struct sockaddr *)&sun, sizeof(sun)) != 0)
    {
      logerr("could not connect to scamper process\n");
      return -1;
    }
    return 0;
  }
  return -1;
}

/* 
 * Initialize elements to manipulate warts format 
 */
static int do_files(void)
{
  int pair[2];
  
  if((outfile = scamper_file_open(outfile_name, 'w', "warts")) == NULL)
    return -1;
  
  /*
   * setup a socketpair that is used to decode warts from a binary input.
   * pair[0] is used to write to the file, while pair[1] is used by
   * the scamper_file_t routines to parse the warts data.
   */
  if(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0)
    return -1;
  
  decode_in_fd  = pair[0];
  decode_out_fd = pair[1];
  decode_in = scamper_file_openfd(decode_in_fd, NULL, 'r', "warts");
  if(decode_in == NULL)
    return -1;
  
  if(fcntl_set(decode_in_fd, O_NONBLOCK) == -1)
    return -1;
  
  return 0;
}

/* 
 * Read the destinations file 
 */
static int do_addresses(void)
{
  if (options & OPT_ADDRFILE)
  {
    if (file_lines(address, probelist_addr, NULL) != 0)
    {
      logerr("Could not read destination addresses\n");
      return -1;
    }
    slist_shuffle(probelist);
    return 0;
  }
  return probelist_addr(address, NULL);
}

/* 
 * Realize traceroute and ping measurements to reveal MPLS tunnels
 */
static int tnt_measure(void)
{
  sc_tnt_test_t *tntt;
  struct timeval tv, *tv_ptr;
  fd_set rfds;
  int nfds, nt;
  
  gettimeofday_wrap(&tv);
  srandom(tv.tv_usec);
  
  /* Initialize the global data structures */
  if ((targets = splaytree_alloc((splaytree_cmp_t)sc_target_cmp)) == NULL)
    return -1;
  if ((pings = splaytree_alloc((splaytree_cmp_t)sc_trace_ping_cmp)) == NULL)
    return -1;
  if ((ping_waits = splaytree_alloc((splaytree_cmp_t)sc_ping_wait_cmp)) == NULL)
    return -1;
  if ((tunnels = splaytree_alloc((splaytree_cmp_t)sc_tunnel_cmp)) == NULL)
    return -1;
  if ((tunnel_waits = splaytree_alloc((splaytree_cmp_t)sc_tunnel_wait_cmp)) == NULL)
    return -1;
  if ((buddies = splaytree_alloc((splaytree_cmp_t)sc_buddy_cmp)) == NULL)
    return -1;
  if ((buddy_waits = splaytree_alloc((splaytree_cmp_t)sc_buddy_wait_cmp)) == NULL)
    return -1;
  if ((buddytests = splaytree_alloc((splaytree_cmp_t)sc_buddy_test_cmp)) == NULL)
    return -1;
  if ((waitlist = slist_alloc()) == NULL || (probelist = slist_alloc()) == NULL)
    return -1;
  
  /* Read the destinations from the input file */
  if (do_addresses() != 0)
    return -1;
  /* Connect to scamper daemon */
  if (do_scamperconnect() != 0)
    return -1;
  /* Initialize warts manipulation */
  if (do_files() != 0)
    return -1;
  
  /* Attach to scamper process */
  if (write_wrap(scamper_fd, "attach\n", NULL, 7) != 0)
  {
    logerr("could not attach to scamper process\n");
    return -1;
  }
  
  for (;;)
  {
    nfds = 0;
    FD_ZERO(&rfds);
    
    if (scamper_fd < 0 && decode_in_fd < 0)
      break;
    
    if (scamper_fd >= 0)
    {
      FD_SET(scamper_fd, &rfds);
      if (nfds < scamper_fd)
        nfds = scamper_fd;
    }
    
    if (decode_in_fd >= 0)
    {
      FD_SET(decode_in_fd, &rfds);
      if (nfds < decode_in_fd)
        nfds = decode_in_fd;
    }
    
    /*
     * Need to set a timeout on select if scamper's processing window is
     * not full and there is a trace in the waiting queue.
     */
    tv_ptr = NULL;
    if (more > 0)
    {
      gettimeofday_wrap(&now);
      
      /*
       * If there is something ready to probe now, then try and
       * do it.
       */
      if (slist_count(probelist) > 0 || slist_count(waitlist) > 0)
      {
        if (do_method() != 0)
          return -1;
      }
    }
    
    /* Check if all measurements are done */
    if(splaytree_count(targets) == 0 && slist_count(probelist) == 0)
    {
      logprint("done\n");
      printf("done\n");
      break;
    }
    
    if (select(nfds+1, &rfds, NULL, NULL, tv_ptr) < 0)
    {
      if (errno == EINTR)
        continue;
      break;
    }
    
    gettimeofday_wrap(&now);
    
    /* Next measurements */
    if (more > 0)
    {
      if (do_method() != 0)
        return -1;
    }
    
    /* Read input from scamper daemon */
    if (scamper_fd >= 0 && FD_ISSET(scamper_fd, &rfds))
    {
      if (do_scamperread() != 0)
        return -1;
    }
    
    /* Read measurement result from scamper daemon */
    if (decode_in_fd >= 0 && FD_ISSET(decode_in_fd, &rfds))
    {
      if (do_decoderead() != 0)
        return -1;
    }
  }
  
  /* Check if all tests were done */
  if ((nt = splaytree_count(tnttests)) > 0)
  {
    logerr("warning: incomplete tnttests (%d)\n", nt);
    while ((tntt=splaytree_pophead(tnttests)) != NULL)
      scamper_trace_tnt_print(tntt->trace);
  }
  
  return 0;
}

/* 
 * Read a TNT trace
 */
static int tnt_read(void)
{
  scamper_file_t *in;
  char *filename;
  uint16_t type;
  void *data;
  int i;
  
  for (i=0; i<dump_filec; i++)
  {
    filename = dump_files[i];
    if ((in = scamper_file_open(filename, 'r', NULL)) == NULL)
    {
      logerr("Could not open output file\n");
      return -1;
    }
    
    while (scamper_file_read(in, ffilter, &type, &data) == 0)
    {
      // EOF
      if (data == NULL)
        break;
      
      assert(type == SCAMPER_FILE_OBJ_TRACE);
      if (dump_funcs[dump_id].proc_tnt != NULL)
          dump_funcs[dump_id].proc_tnt(data);
    }
    scamper_file_close(in);
  }
  return 0;
}

/*
 * Initialization
 */
static int tnt_init(void)
{
  /* Scamper will run only pings and traces */
  uint16_t types[] =
  {
    SCAMPER_FILE_OBJ_PING,
    SCAMPER_FILE_OBJ_TRACE,
  };
  int typec   = sizeof(types) / sizeof(uint16_t);
  
  if ((ffilter = scamper_file_filter_alloc(types, typec)) == NULL)
    return -1;
  
  return 0;
}

/* 
 * Clean 
 */
static void cleanup(void)
{
  sc_target_t *tg;
  slist_t *list;
  
  if (targets != NULL)
  {
    if ((list = slist_alloc()) != NULL)
    {
      splaytree_inorder(targets, tree_to_slist, list);
      while ((tg = slist_head_pop(list)) != NULL)
      {
        sc_target_detach(tg);
        sc_target_free(tg);
      }
      slist_free(list);
    }
    splaytree_free(targets, NULL);
    targets = NULL;
  }
  
  if (tnttests != NULL)
  {
    splaytree_free(tnttests, (splaytree_free_t)sc_tnt_test_free);
    tnttests = NULL;
  }
  
  if (buddytests != NULL)
  {
    splaytree_free(buddytests, (splaytree_free_t)sc_buddy_test_free);
    buddytests = NULL;
  }
  
  if (buddies != NULL)
  {
    splaytree_free(buddies, (splaytree_free_t)sc_buddy_free);
    buddies = NULL;
  }
  
  if (buddy_waits != NULL)
  {
    splaytree_free(buddy_waits, (splaytree_free_t)sc_buddy_wait_free);
    buddy_waits = NULL;
  }
  
  if (ping_waits != NULL)
  {
    splaytree_free(ping_waits, (splaytree_free_t)sc_ping_wait_free);
    ping_waits = NULL;
  }
  
  if (pings != NULL)
  {
    splaytree_free(pings, (splaytree_free_t)sc_trace_ping_free);
    pings = NULL;
  }

  if (traces != NULL)
  {
    splaytree_free(traces, (splaytree_free_t)scamper_trace_free);
    traces = NULL;
  }
  
  if (tunnels != NULL)
  {
    splaytree_free(tunnels, (splaytree_free_t)sc_tunnel_free);
    tunnels = NULL;
  }
  
  if (tunnel_waits != NULL)
  {
    splaytree_free(tunnel_waits, (splaytree_free_t)sc_tunnel_wait_free);
    tunnel_waits = NULL;
  }
  
  if (readbuf != NULL)
  {
    free(readbuf);
    readbuf = NULL;
  }
  
  if (probelist != NULL)
  {
    probelist_empty();
    slist_free(probelist);
    probelist = NULL;
  }
  
  if (waitlist != NULL)
  {
    slist_free(waitlist);
    waitlist = NULL;
  }
  
  if (outfile != NULL)
  {
    scamper_file_close(outfile);
    outfile = NULL;
  }
  
  if (decode_in != NULL)
  {
    scamper_file_close(decode_in);
    decode_in = NULL;
  }
  
  if (ffilter != NULL)
  {
    scamper_file_filter_free(ffilter);
    ffilter = NULL;
  }
  
  if (logfile != NULL)
  {
    fclose(logfile);
    logfile = NULL;
  }
  return;
}

/*
 * Read a TNT trace and dumps it content
 */
static int process_tnt_1(scamper_trace_t *trace)
{
  int rc = -1;
  
  if (scamper_trace_tnt_print(trace) == 0)
    rc = 0;
  scamper_trace_free(trace);
  return rc;
}

/*
 * Main 
 */
int main(int argc, char *argv[])
{
#if defined(DMALLOC)
  free(malloc(1));
#endif
  
  atexit(cleanup);
  
  /* Check arguments */
  if (check_options(argc, argv) != 0)
    return -1;
  
  /* Start a daemon if asked to */
  if ((options & OPT_DAEMON) != 0 && daemon(1, 0) != 0)
  {
    fprintf(stderr, "could not daemon");
    return -1;
  }
  
  /* Initialization */
  if (tnt_init() != 0)
    return -1;
  
  /* Warts reading or measurements */
  if (options & OPT_DUMP)
    return tnt_read();
  else
    return tnt_measure();
  
  return 0;
}
