/*
 *  802.11 injection Probe request
 *
 *  Copyright (C) 2015 Mehdi Bezahaf
 *  Copyright (C) 2006-2014 Thomas d'Otreppe
 *  Copyright (C) 2004, 2005 Christophe Devine
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL. *  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so. *  If you
 *  do not wish to do so, delete this exception statement from your
 *  version. *  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */
#include <sys/ioctl.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <netinet/in_systm.h>
#include <ctype.h>

#include "osdep/osdep.h"

#define REQUESTS    30
#define NULL_MAC  (unsigned char*)"\x00\x00\x00\x00\x00\x00"
#define RATES                                                           \
        "\x01\x04\x02\x04\x0B\x16\x32\x08\x0C\x12\x18\x24\x30\x48\x60\x6C"
#define PROBE_REQ                                                       \
        "\x40\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xCC\xCC\xCC\xCC\xCC\xCC" \
        "\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00"

extern unsigned char * getmac(char * macAddress, int strict, unsigned char * mac);

char usage[] =
        "\n"
        "  %s - (C) 2015 Mehdi Bezahaf (based on aircrack-ng tools)\n"
        "\n"
        "  usage: probe <options> <interface>\n"
        "\n"
        "  Replay options:\n"
        "\n"
        "      -e essid  : set target AP SSID\n"
        "      -o npckts : number of packets per burst [1:512] (default: 1)\n"
        "      -c channel  : set channel. You can set multiple channels separated by commas. For example -c 1,3,5\n"
        "      -p txpower  : set txpower. You can set multiple txpowers separated by commas. For example -p 1,3,5\n"
        "      --help              : Displays this usage screen\n"
        "\n";

struct options {
	char r_essid[33];
	char *iface_out;
	int npackets;
} opt;

static struct wif *wi_out;

struct Tx_settings {
	unsigned char len;
	unsigned char essid[255];
	int chan[11];
	int txpower[16];
	unsigned char mac_out[6];
} tx_settings;

unsigned long nb_pkt_sent;
unsigned char h80211[4096];

int maccmp(unsigned char *mac1, unsigned char *mac2)
{
	int i=0;

	if(mac1 == NULL || mac2 == NULL)
		return -1;

	for (i=0; i<6; i++) {
		if (toupper(mac1[i]) != toupper(mac2[i]))
			return -1;
	}
	return 0;
}

int send_packet(void *buf, size_t count)
{
	// struct wif *wi = wi_out; /* XXX globals suck */
	unsigned char *pkt = (unsigned char*) buf;
	if ((count > 24) && (pkt[1] & 0x04) == 0 && (pkt[22] & 0x0F) == 0) {
		pkt[22] = (nb_pkt_sent & 0x0000000F) << 4;
		pkt[23] = (nb_pkt_sent & 0x00000FF0) >> 4;
	}

	if (wi_write(wi_out, buf, count, NULL) == -1) {
		switch (errno) {
		case EAGAIN:
		case ENOBUFS:
			usleep(10000);
			return 0; /* XXX not sure I like this... -sorbo */
		}
		perror("wi_write()");
		return -1;
	}
	nb_pkt_sent++;
	return 0;
}

int do_attack_test()
{
	int len=0, i=0, j, k;
	int essidlen=0;

	essidlen = strlen(opt.r_essid);
	if (essidlen > 250) {
		essidlen = 250;
	} else if (essidlen > 0) {
		tx_settings.len = essidlen;
		memcpy(tx_settings.essid, opt.r_essid, essidlen);
		tx_settings.essid[essidlen] = '\0';
	}


	struct tm *lt;
	time_t tc = time(NULL);
	lt = localtime(&tc);
	printf("%02d:%02d:%02d ", lt->tm_hour, lt->tm_min, lt->tm_sec);
	printf("Broadcasting probe requests with MAC ");
	for (i = 0; i < 6; i++) {
		printf("%x", tx_settings.mac_out[i]);
		printf(i == 5 ? "\n" : ":");
	}

	len = 24;
	memcpy(h80211, PROBE_REQ, len);

	h80211[len] = 0x00;	     //ESSID Tag Number

	h80211[len + 1] = tx_settings.len; //ESSID Tag Length
	memcpy(h80211 + len + 2, tx_settings.essid, tx_settings.len);
	len += tx_settings.len + 2;

	memcpy(h80211 + len, RATES, 16);
	len += 16;

	for (i = 0; i < 11; i++) {
		if (tx_settings.chan[i] == 0)
			break;

		printf("\nSending on Channel %d ", tx_settings.chan[i]);
		if (wi_get_channel(wi_out) != tx_settings.chan[i]) {
			//printf("Different channels: existing %d to %d.\n", wi_get_channel(wi_out), tx_settings.chan[i]);
			wi_set_channel(wi_out, tx_settings.chan[i]);
		}

		for (k = 0; k < 16; k++) {
			if (tx_settings.txpower[k] == 0)
				break;

			wi_set_txpower(wi_out, tx_settings.txpower[k]);
			printf(" tx=%d",tx_settings.txpower[k]);

			for (j = 0; j < opt.npackets; j++) {
				memcpy(h80211 + 10, tx_settings.mac_out, 6);//, wi_out, 6);
				send_packet(h80211, len);
				printf(".");
			}
		}
		printf("\n");
	}
	return 0;
}

int main(int argc, char *argv[])
{
	int i, ret;
	memset(&opt, 0, sizeof(opt));
	opt.npackets = 1;
	char channels[66];
	char txpowers[66];

	for (i = 0; i < 11; i++) {
		tx_settings.chan[i] = 0;
	}

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"help", 0, 0, 'H'},
			{0,      0, 0,  0 }
		};
		int option = getopt_long(argc, argv, "c:e:o:p:", long_options, &option_index);
		// "b:d:s:m:n:u:v:t:T:f:g:w:x:p:a:c:h:e:ji:r:k:l:y:o:q:0:1:2345679HFBDR",
		// "c:h:e:p:o:0:1",
		if (option < 0) break;
		switch (option) {
		case 0:
			break;
		case ':':
			printf("\"%s --help\" for help.\n", argv[0]);
			return 1;
		case '?':
			printf("\"%s --help\" for help.\n", argv[0]);
			return 1;
		case 'o':
			ret = sscanf(optarg, "%d", &opt.npackets);
			if (opt.npackets < 0 || opt.npackets > 512 || ret != 1) {
				printf("Invalid number of packets per burst. [0-512]\n");
				printf("\"%s --help\" for help.\n", argv[0]);
				return 1;
			}
			break;
		case 'c':
			memset(channels, 0, sizeof(channels));
			strncpy(channels, optarg, sizeof(channels) - 1);

			char *str = strdup(channels);
			char *channel;
			i = 0;
			while ((channel = strsep(&str, ","))) {
				tx_settings.chan[i] = (int) strtol(channel, (char **)NULL, 10);
				if (tx_settings.chan[i] < 1 || tx_settings.chan[i] > 11)
				{
					printf("Invalid channel. [1-11]\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return 1;
				}
				i++;
			}
			break;
		case 'p':
			memset(txpowers, 0, sizeof(txpowers));
			strncpy(txpowers, optarg, sizeof(txpowers) - 1);
			str = strdup(txpowers);
			char *txpower;
			i = 0;
			while ((txpower = strsep(&str, ","))) {
				tx_settings.txpower[i] = (int) strtol(txpower, (char **)NULL, 10);
				if (tx_settings.txpower[i] < 0 || tx_settings.txpower[i] > 15) {
					printf( "Invalid txpower value. [0-15]\n" );
					printf("\"%s --help\" for help.\n", argv[0]);
					return 1;
				}
				i++;
			}
			break;
		case 'e':
			memset(opt.r_essid, 0, sizeof(opt.r_essid));
			strncpy(opt.r_essid, optarg, sizeof(opt.r_essid) - 1);
			break;
		default:
			goto usage;
		}
	}

	if (argc - optind != 1)	{
		if (argc == 1) {
		usage:
			printf("%s", usage);
		}
		if (argc - optind == 0) {
			printf("No replay interface specified.\n");
		}
		if (argc > 1) {
			printf("\"%s --help\" for help.\n", argv[0]);
		}
		return 1;
	}
	opt.iface_out = argv[optind];
	printf("%s ", opt.iface_out);

	wi_out = wi_open(opt.iface_out);
	if (!wi_out)
		return 1;

	if (tx_settings.txpower[0] == 0)
		tx_settings.txpower[0] = 15;

	if (tx_settings.chan[0] == 0)
		tx_settings.chan[0] = wi_get_channel(wi_out);

	wi_get_mac(wi_out, tx_settings.mac_out);

	/* drop privileges */
	if (setuid(getuid()) == -1)
		perror("setuid");

	//Mehdi: By default inject and nothing else!
	return do_attack_test();

	/* that's all, folks */
}
