/* mkconfig for f-ftpbnc v1.6 */
/* $Rev: 421 $ $Date: 2008-01-30 22:56:40 +0100 (Wed, 30 Jan 2008) $ */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "sha256.h"
#include "xtea-cipher.h"

#include "f-ftpbnc.h"

#define ENCKEYLEN 	256

int readoption(const char *quest, char *dest, int destlen)
{
    char *inbuff;

    inbuff = malloc(destlen+1);

    printf("%s [%s]: ", quest, dest);
    fflush(stdout);

    fgets(inbuff, destlen, stdin);
    if (strlen(inbuff) > 0) inbuff[strlen(inbuff)-1] = 0;

    if (*inbuff != 0) {
	strncpy(dest, inbuff, destlen);
    }

    free(inbuff);

    return 1;
}

int checkhostname(const char *hostname)
{
    struct in_addr ia;
    struct hostent *he;

    if (inet_aton(hostname, &ia)) {
	return 2;
    }
     
    he = gethostbyname(hostname);
    if (he != NULL) return 1;

    printf("Host %s does not resolve. Check hostname or dns settings.\n", hostname);
    return 0;
}

int hexcharval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'Z') return c - 'A' + 10;
    if (c >= 'a' && c <= 'z') return c - 'a' + 10;
    return -1;
}

int parsehexdata(const char *hex, char *dest, int destlen)
{
    int n = 0;
    const char *p = hex;

    while(*p && n < destlen) {
	if (*p == '0' && *(p+1) == 'x' &&
	    hexcharval(*(p+2)) >= 0 && hexcharval(*(p+3)) >= 0)
	{
	    dest[n++] = hexcharval(*(p+2)) * 16 + hexcharval(*(p+3));
	    p += 4;
	    if (*p == ',') p++;
	}
	else return n;
    }     
    return n;
}

void readconfig(FILE *f, struct CONFIG *cfg, char *enckey)
{
    char buff[1024];
    int ln = 0;
    int state = 0;

    int gotenckey = 0;

    char configbuff[16*1024];
    unsigned int configptr = 0;

    while( fgets(buff, sizeof(buff), f) )
    {
	ln++;

	if (strlen(buff) > 0) buff[strlen(buff)-1] = 0;

	if (state == 0)
	{
	    if (strcmp(buff,"unsigned char configkey[] = {") == 0) {
		state = 1;
	    }
	    else if (strcmp(buff,"unsigned char configdataencrypt[] = {") == 0) {
		state = 2;
	    }
	}
	else if (state == 1) {
	    if (parsehexdata(buff, enckey, 16) == 16)
	    {
		printf("Read configkey from inc-config.h\n");
		gotenckey = 1;
	    }
	    else if (strcmp(buff,"};") == 0) {
		state = 0;
	    }
	    else {
		printf("Bad line in configkey: %s", buff);
		state = 0;
	    }
	}
	else if (state == 2) {
	    if (configptr+16 <= sizeof(configbuff) && 
		parsehexdata(buff, configbuff + configptr, 16) == 16)
	    {
		configptr += 16;
	    }
	    else if (strcmp(buff,"};") == 0) {
		printf("Read encrypted configdata from inc-config.h\n");
		state = 0;
	    }
	    else {
		printf("Bad line in configdataencrypt: %s", buff);
		state = 0;
	    }
	}
    }

    if (gotenckey && configptr > 0) {
	printf("Decrypting inc-config.h data\n");

	if (configptr < sizeof(*cfg)) {
	    printf("Config in inc-config (%d) has smaller length than config block (%d).\n", configptr, sizeof(*cfg));
	}
	else {
	    struct CONFIG *newcfg;

	    xtea_cbc_decipher((unsigned char*)configbuff, sizeof(configbuff),
			      (unsigned long*)enckey, tea_iv);

	    newcfg = (struct CONFIG*)configbuff;

	    if (strncmp(newcfg->signature, "f-ftpbnc", 9) == 0) {
		memcpy(cfg, configbuff, sizeof(*cfg));
		printf("Configuration data loaded.\n");
	    }
	    else {
		printf("Configuration decryption failed?\n");
	    }
	}
	memset(enckey, 0, ENCKEYLEN);
    }
    else if (!gotenckey && configptr > 0) {
	int turn = 3;
	char *inpass;
	unsigned char teakey[16];
	struct CONFIG *newcfg;

	for(turn = 3; turn > 0; turn--) {
	    inpass = getpass("Please supply config decryption password: ");
	    if (!inpass) {
		printf("Could not read password.\n");
	    }
	    else {
		string_to_teakey(inpass, teakey);

		xtea_cbc_decipher((unsigned char*)configbuff, sizeof(configbuff),
				  (unsigned long*)teakey, tea_iv);

		newcfg = (struct CONFIG*)configbuff;

		if (strncmp(newcfg->signature, "f-ftpbnc", 9) == 0) {
		    memcpy(cfg, configbuff, sizeof(*cfg));
		    strncpy(enckey, inpass, ENCKEYLEN);
		    printf("Configuration data loaded.\n");
		    break;
		}
		else {
		    memset(enckey, 0, ENCKEYLEN);
		    printf("Configuration decryption failed. Wrong password?\n");
		}
	    }
	}
	if (turn == 0) {
	    printf("!!!\nStarting with a clean config\n!!!\n");
	}
    }
}

void writehexstruct(FILE *f, const char *structname, const unsigned char *data, int datalen)
{
    int n;
    char buff[128];
    char *buffo = buff;
     
    fprintf(f,"unsigned char %s[] = {\n", structname);

    for(n = 0; n < datalen; n++) {
	       
	buffo += sprintf(buffo, "0x%02X,", data[n]);
	if (n % 16 == 15) {
	    *buffo = 0;
	    if (n == datalen-1) *(buffo-1) = 0;
	    fprintf(f,"%s\n", buff);
	    buffo = buff;
	}
    }

    if (buffo > buff) {
	buffo -= 1;
	*buffo = 0;
	fprintf(f,"%s };\n", buff);
    }
    else {
	fprintf(f,"};\n");
    }
}

int writeconfig(FILE *f, struct CONFIG *cfg, char *enckeystring)
{
    time_t tnow = time(NULL);
    char buff[128];

    fprintf(f, "/* inc-config.h for f-ftpbnc */\n");

    strftime(buff, sizeof(buff), "%Y-%m-%d %H:%M:%S", localtime(&tnow));
    fprintf(f, "/* Generated %s */\n\n", buff);

    {
	unsigned char *encbuff;
	int enclen = sizeof(*cfg) + 64;
	unsigned char enckey[16];

	enclen += 16 - (enclen % 16);

	if (cfg->enctype == 1) {
	    fprintf(f,"#define SCRAMBLE_CONFIG\n\n");

	    memcpy(enckey, enckeystring, 16);

	    writehexstruct(f, "configkey", enckey, sizeof(enckey));
	    fprintf(f, "\n");
	}
	else if (cfg->enctype == 2) {
	    fprintf(f,"#define ENCRYPT_CONFIG\n\n");

	    string_to_teakey(enckeystring, enckey);
	}

	/* encrypt config block */
	encbuff = malloc(enclen);

	memset(encbuff,0,sizeof(encbuff));

	memcpy(encbuff, cfg, sizeof(*cfg));

	xtea_cbc_encipher(encbuff, enclen, (unsigned long*)enckey, tea_iv);

	/* write into config header */
	writehexstruct(f, "configdataencrypt", encbuff, enclen);  
	fprintf(f,"\n");

	if (cfg->proctitlechange) {
	    fprintf(f,"#define CHANGE_PROCTITLE\n\n");
	}
    }

    return 1;
}

int main()
{
    int n;
    char buff[64], *endptr;
    struct CONFIG cfg;
    char enckey[ENCKEYLEN];
    FILE *f;

    memset(&cfg, 0, sizeof(cfg));
    memset(enckey, 0, sizeof(enckey));

    strcpy(cfg.signature, "f-ftpbnc");
    cfg.ident = 1;

    f = fopen("inc-config.h", "r");
    if (f) {
	printf("Reading defaults from inc-config.h\n");
	readconfig(f, &cfg, enckey);
	printf("\n");
	fclose(f);
    }

    printf("1) Configuration name\n");
    printf("   This is an arbitrary string, which is shown when the bnc is started. \n");
    printf("   Just for you if you have multiple bncs on one machine.\n\n");

    readoption("Configuration name:", cfg.configname, sizeof(cfg.configname));
    printf("\n");

    printf("2) Local IP\n");
    printf("   This can either be * or one of the ips on your maschine.\n");
    printf("   Useful only if you have a box with multiple ips eg for vhosts and\n");
    printf("   you wish to pick a specific one.\n\n");

    if (!*cfg.localip) strcpy(cfg.localip,"*");

    readoption("Local IP:", cfg.localip, sizeof(cfg.localip));
    printf("\n");

    printf("3) Local Port\n");
    printf("   Important setting: the port to listen to on the ip above.\n");
    printf("   As always ports < 1024 need root access to use, so pick a large one.\n");
    printf("   Note: Ports >= 65536 don't exist.\n\n");

    do {
	sprintf(buff, "%d", cfg.localport);
	readoption("Local Port:", buff, sizeof(buff));
	cfg.localport = strtol(buff, &endptr, 10);
    }
    while(*endptr != 0 || cfg.localport < 23 || cfg.localport > 65535);
    printf("\n");

    printf("4) Destination Host\n");
    printf("   Important setting: the dns hostname or ip of the glftpd\n");
    printf("   site to which to bounce connections to. This can be a dns name,\n");
    printf("   in which case you can specify a dns-reload time below.\n\n");

    do {
	readoption("Destination Host:", cfg.desthostname, sizeof(cfg.desthostname));
    } while (!checkhostname(cfg.desthostname));
    printf("\n");

    printf("5) Destination Port\n");
    printf("   Important setting: the port of the destination hosts on which \n");
    printf("   glftpd is running.\n\n");

    do {
	sprintf(buff, "%d", cfg.destport);
	readoption("Destination Port:", buff, sizeof(buff));
	cfg.destport = strtol(buff, &endptr, 10);
    }
    while(*endptr != 0 || cfg.destport < 10 || cfg.destport > 65535);
    printf("\n");

    if (checkhostname(cfg.desthostname) == 1) {
	printf("6) Destination DNS Resolve Time\n");
	printf("   DNS resolving is always slow and hinders performance, so the bnc will reuse\n");
	printf("   the resolved ip for this period of time. The value is in seconds.\n");
	printf("   If you dont know what this is leave 3600 = 1 hour.\n\n");

	if (cfg.destresolvetime == 0) cfg.destresolvetime = 3600;

	do {	
	    sprintf(buff, "%d", cfg.destresolvetime);
	    readoption("Destination DNS Resolve Time:", buff, sizeof(buff));
	    cfg.destresolvetime = strtol(buff, &endptr, 10);
	}
	while(*endptr != 0 || cfg.destresolvetime < 1);
	printf("\n");
    }
    else {
	printf("6) Destination DNS Resolve Time. Skipped because destination host is an ip.\n\n");
	cfg.destresolvetime = 3600;
    }

    printf("7) Request and send ident\n");
    printf("   Usually the bnc requests the ident from the connecting client's ip. The \n");
    printf("   value is forwarded to the server glftpd for checking against the userdb.\n");
    printf("   You can disable this and turn f-ftpbnc into a pure port forwarder.\n\n");

    do {
	sprintf(buff, "%c", cfg.ident ? 'y' : 'n');
	readoption("Ident", buff, sizeof(buff));
    }
    while(strcmp(buff,"n") != 0 && strcmp(buff,"y") != 0);
    printf("\n");

    cfg.ident = (*buff == 'y');

    printf("8) Destination Bind IP\n");
    printf("   When connecting to the destination host, use this _local_ interface.\n");
    printf("   Only useful on boxes with multiple ips. Normally keep * = default interface\n\n");

    if (!*cfg.destbindip) strcpy(cfg.destbindip,"*");
    readoption("Bind IP towards Destination:", cfg.destbindip, sizeof(cfg.destbindip));
    printf("\n");

    printf("9) Hammer Protection\n");
    printf("   This will enable hammer protection in the bnc: An ip can only connect\n");
    printf("   to the bnc x times within y seconds. All following connection requests\n");
    printf("   will immediately be dropped without contacting the site.\n");
    printf("   0:0 disables the protection.\n");
    printf("   3:60 (3 connects in 60 seconds) is a good value.\n\n");

    do {
	sprintf(buff, "%d:%d", cfg.hammercount, cfg.hammertime);
	readoption("Hammer (count:secs)", buff, sizeof(buff));
    }
    while(sscanf(buff, "%d:%d", &cfg.hammercount, &cfg.hammertime) != 2);
    printf("\n");

    printf("10) Status in ps\n");
    printf("    The bnc can be configed to change its proc title in a ps listing. This \n");
    printf("    can be used to a static text of e.g. another executable's name. Or it can\n");
    printf("    be used to display the current number of connections the bnc is serving.\n\n");

    do {
	sprintf(buff, "%c", cfg.proctitlechange ? 'y' : 'n');
	readoption("Change Proctitle", buff, sizeof(buff));
    }
    while(strcmp(buff,"n") != 0 && strcmp(buff,"y") != 0);

    if (*buff == 'y') {
	printf("10a) Proctitle text\n");
	printf("     The text for the proc title. Use may use %%d to insert the current \n");
	printf("     number of clients in the text. Use only one %%d and no other replacements.\n");
	printf("     Otherwise the bnc will crash!\n\n");

	if (!cfg.proctitlechange) strcpy(cfg.proctitletext,"f-ftpbnc: [ %d users ]");

	readoption("Proctitle text", cfg.proctitletext, sizeof(cfg.proctitletext));

	cfg.proctitlechange = 1;
    }
    else {
	cfg.proctitlechange = 0;
    }

    printf("\n");

    printf("11) Configuration Encryption Type\n");
    printf("    f-ftpbnc will always compile its configuration into the binary. This\n");
    printf("    means it does not need a bnc.conf lying around. The configuration block\n");
    printf("    inside the binary program image is encrypted with xTEA.\n");
    printf("    There are two methods available:\n");
    printf("    a) Include the password needed for decryption inside the binary. This\n");
    printf("       enables the bnc to start by itself from a crontab. But the configuration\n");
    printf("       is not really safe, as it is easy to trace the decryption instructions\n");
    printf("       and thereby read the config.\n");
    printf("       I repeat: this is not real encryption, just a manner of hiding\n");
    printf("       the config.\n");
    printf("    b) The encryption key will not be stored inside the binary, the bnc \n");
    printf("       will demand it from the console when you start it. Be warned that it\n");
    printf("       therefore cannot be started by cron. But the configuration is\n");
    printf("       really safe this way.\n\n");
     
    do {
	sprintf(buff, "%c", cfg.enctype == 2 ? 'b' : 'a');  
	readoption("Encryption Type:", buff, sizeof(buff));
	  
    } while (strcmp(buff,"a") != 0 && strcmp(buff,"b") != 0);
    printf("\n");
     
    if (*buff == 'a') {
	unsigned char *uenckey = (unsigned char *)enckey;
	cfg.enctype = 1;

	srand(time(NULL));

	printf("Generating random encryption key (you dont need to save this)...\n");

	memset(uenckey, 0, sizeof(uenckey));
	for(n = 0; n < 64; n++) {
	    uenckey[n % 16] ^= rand() % 256;
	}

	printf("Key: ");
	for(n = 0;n < 16; n++) {
	    printf("%02X ", uenckey[n]);
	}
	printf("\n\n");
    }
    else {
	cfg.enctype = 2;

	do {
	    readoption("Encryption Key:", enckey, sizeof(enckey));
	    if (strlen(enckey) <= 8) {
		printf("Well. It really ought to be longer than 8 characters.\n");
	    }
	} while (strlen(enckey) <= 8);
	printf("\n");
    }

    printf("Configuration Summary:\n\n");
    printf("Name: %s\n", cfg.configname);
    printf("Local IP and Port: %s:%d\n", cfg.localip, cfg.localport);
    printf("Destination: %s:%d\n", cfg.desthostname, cfg.destport);
    printf("Destination Bind IP: %s\n", cfg.destbindip);
    printf("Destination DNS Resolve Time: %d\n", cfg.destresolvetime);
    printf("Hammer Protection: %d:%d\n", cfg.hammercount, cfg.hammertime);
    if (cfg.enctype == 1) {
	printf("Scrambling configuration with random key.\n");
    }
    else {
	printf("Encryptiong configuration with the password you supplied.\n");
    }
    printf("\n");

    strcpy(buff, "n");
    readoption("Save Configuration to incconfig.h?", buff, sizeof(buff));
    if (strcmp(buff,"y") != 0) {
	printf("Oke i wont push you.\n");
	return 1;
    }

    f = fopen("inc-config.h", "w");
    if (!f) {
	printf("Could not open inc-config.h\n");
	return 1;
    }
     
    writeconfig(f, &cfg, enckey);

    fclose(f);

    printf("\nConfiguration saved in inc-config.h\n\n");

    return 0;
}
