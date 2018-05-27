AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_tnt

sc_tnt_SOURCES = \
	sc_tnt.c \
	../../utils.c \
	../../mjl_heap.c \
	../../mjl_list.c \
	../../mjl_splaytree.c \
	../../mjl_prefixtree.c

sc_tnt_LDADD = ../../scamper/libscamperfile.la

man_MANS = sc_tnt.1

CLEANFILES = *~ *.core
