/**
 *  keepalink: Command-line tool to renew WinLink accounts
 *  Copyright (C) 2019 Darryl Pogue
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DEBUG 1

#ifdef WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>

    #define SHUT_RDWR SD_BOTH
#else
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <sys/socket.h>
#endif

#define WL2K_HOST "server.winlink.org"
#define WL2K_PORT 8772

#define SID "[Keepalink-0.1-B2FIHM$]\r"

typedef int (*csvhandler)(const char*, const char*);

struct sockaddr_in serveraddr;


/* Salt for Winlink 2000 secure login */
static const uint8_t sl_salt[] = {
  0x4D, 0xC5, 0x65, 0xCE,   0xBE, 0xF9, 0x5D, 0xC8,
  0x33, 0xF3, 0x5D, 0xED,   0x47, 0x5E, 0xEF, 0x8A,
  0x44, 0x6C, 0x46, 0xB9,   0xE1, 0x89, 0xD9, 0x10,
  0x33, 0x7A, 0xC1, 0x30,   0xC2, 0xC3, 0xC6, 0xAF,
  0xAC, 0xA9, 0x46, 0x54,   0x3D, 0x3E, 0x68, 0xBA,
  0x72, 0x34, 0x3D, 0xA8,   0x42, 0x81, 0xC0, 0xD0,
  0xBB, 0xF9, 0xE8, 0xC1,   0x29, 0x71, 0x29, 0x2D,
  0xF0, 0x10, 0x1D, 0xE4,   0xD0, 0xE4, 0x3D, 0x14
};


/* MD5
 * Constants are the integer part of the sines of integers (in radians) * 2^32.
 */
const uint32_t K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

/* MD5: s specifies the per-round shift amounts */
const uint32_t s[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

#define leftrotate(x, c) (((x) << c) | ((x) >> (32-c)))


void md5(
        const unsigned char* input,
        size_t length,
        unsigned char* digest
    )
{
    uint8_t message[128];
    uint32_t M[16];

    uint32_t a0 = 0x67452301;
    uint32_t b0 = 0xefcdab89;
    uint32_t c0 = 0x98badcfe;
    uint32_t d0 = 0x10325476;

    uint32_t A = 0;
    uint32_t B = 0;
    uint32_t C = 0;
    uint32_t D = 0;
    uint32_t F = 0;
    uint32_t dTemp = 0;

    int i = 0;
    int g = 0;

    size_t offset = 0;
    uint64_t bit_len = length * 8;

    memcpy(message, input, length);
    message[length] = 0x80;

    for (length++; length % (512/8) != 448/8; length++) {
        message[length] = 0x00;
    }

    message[length + 0] = bit_len;
    message[length + 1] = bit_len >> 8;
    message[length + 2] = bit_len >> 16;
    message[length + 3] = bit_len >> 24;
    message[length + 4] = bit_len >> 32;
    message[length + 5] = bit_len >> 40;
    message[length + 6] = bit_len >> 48;
    message[length + 7] = bit_len >> 56;


    for (offset = 0; offset < length; offset += (512/8)) {
        for (i = 0, g = offset; i < 16; i++, g += 4) {
            M[i] =  (message[g + 0] <<  0) +
                    (message[g + 1] <<  8) +
                    (message[g + 2] << 16) +
                    (message[g + 3] << 24);
        }

        A = a0;
        B = b0;
        C = c0;
        D = d0;

        for (i = 0; i < 64; i++) {
            if (i <= 15) {
                F = (B & C) | (~B & D);
                g = i;
            } else if(i <= 31) {
                F = (D & B) | (~D & C);
                g = (5*i + 1) % 16;
            } else if(i <= 47) {
                F = B ^ C ^ D;
                g = (3*i + 5) % 16;
            } else {
                F = C ^ (B | ~D);
                g = (7*i) % 16;
            }

            dTemp = D;
            D = C;
            C = B;
            B = B + leftrotate(A + F + K[i] + M[g], s[i]);
            A = dTemp;
        }

        a0 += A;
        b0 += B;
        c0 += C;
        d0 += D;
    }

    for (i = 0; i < 4; i++) {
        digest[i]       = (a0 >> (i * 8)) & 0x000000ff;
        digest[i + 4]   = (b0 >> (i * 8)) & 0x000000ff;
        digest[i + 8]   = (c0 >> (i * 8)) & 0x000000ff;
        digest[i + 12]  = (d0 >> (i * 8)) & 0x000000ff;
    }
}



void usage(
        const char* appname
    )
{
    printf("Usage: %s MAPFILE\n\n", appname);
    printf("Renews the WinLink account subscription for every callsign listed "
           "in MAPFILE,\nwhich should be a newline delineated listed of "
           "callsigns and WinLink account\npasswords, separated by a comma "
           "(CSV format).\n\n");
    printf("Copyright © 2019 Darryl Pogue (VA7DPO) <darryl@dpogue.ca>\n");
    printf("Released under the GNU General Public Licence, version 3 or "
           "later.\n");
}


struct sockaddr_in* wlresolve(
        struct sockaddr_in* addr,
        const char* hostname,
        unsigned short port
    )
{
    struct hostent* hp;

    memset(addr, 0, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);

    if ((hp = gethostbyname(hostname)) == NULL) {
        return NULL;
    }

    memcpy(&addr->sin_addr, hp->h_addr, hp->h_length);

    return addr;
}


int wlsecauth(
        const char* challenge,
        const char* passwd,
        char* response
    )
{
    /* This is taken fairly literally from paclink-unix */
    unsigned char* hash_input;
    unsigned char hash_sig[16];
    size_t m;
    size_t n;
    int pr;
    char pr_str[20];

    memset(hash_sig, 0, sizeof(hash_sig));

    m = strlen(challenge) + strlen(passwd);
    n = m + sizeof(sl_salt);

    hash_input = (unsigned char*)malloc(n);
    memcpy(hash_input, challenge, strlen(challenge));
    memcpy(hash_input + strlen(challenge), passwd, strlen(passwd));
    memcpy(hash_input + m, sl_salt, sizeof(sl_salt));

    // MD5 it
    md5(hash_input, n, hash_sig);

    free(hash_input);

    pr = hash_sig[3] & 0x3F;
    pr = (pr << 8) | hash_sig[2];
    pr = (pr << 8) | hash_sig[1];
    pr = (pr << 8) | hash_sig[0];

    sprintf(pr_str, "%08d", pr);
    n = strlen(pr_str);
    snprintf(response, 32, ";PR: ");

    if (n > 8) {
        strcat(response, pr_str + (n - 8));
    } else {
        strcat(response, pr_str);
    }

    strcat(response, "\r");

    return 0;
}


int debugprint(
        const char* callsign,
        const char* passwd
    )
{
    printf("%s,%s\n", callsign, passwd);
    return 0;
}


int wlrenew(
        const char* callsign,
        const char* passwd
    )
{
    int sd = -1;
    ssize_t i = 0;
    ssize_t length = 0;
    char buffer[128];
    char* ptr = NULL;
    char reply[32];
    char challenge[32];
    ssize_t proposals = 0;
    int error = 0;

    buffer[0] = '\0';
    reply[0] = '\0';
    challenge[0] = '\0';

    if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        return 1;
    }

    if (connect(sd, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) == -1) {
        return 1;
    }


    while ((length = read(sd, buffer, sizeof(buffer))) > 0) {
        buffer[length] = '\0';
        ptr = buffer + 0;

        if (*ptr == '\r') {
            ptr++;
        }

        for (i = ptr - buffer; i < length; i++) {
            if (buffer[i] == '\r') {
                buffer[i] = '\0';
                length = i;
                break;
            }
        }

        #if DEBUG
        printf(">debug] %s\n", ptr);
        #endif

        if (!strncmp("Callsign :", ptr, 10)) {
            snprintf(reply, 32, ".%s\r", callsign);
            write(sd, reply, strlen(reply));
            #if DEBUG
            printf("<reply] %s\n", reply);
            #endif
            continue;
        }

        if (!strncmp("Password :", ptr, 10)) {
            snprintf(reply, 32, "CMSTELNET\r");
            write(sd, reply, strlen(reply));
            #if DEBUG
            printf("<reply] %s\n", reply);
            #endif
            continue;
        }

        if (!strncmp("[WL2K", ptr, 5) || !strncmp("Disconnecting", ptr, 13)) {
            /* This is the SID line, let's ignore it */
            continue;
        }

        if (!strncmp(";PQ: ", ptr, 5)) {
            /* Secure Login Challenge */
            strcpy(challenge, ptr+5);
            continue;
        }

        if (!strncmp("FC ", ptr, 3)) {
            proposals++;
            continue;
        }

        if (!strncmp("FQ", ptr, 2)) {
            /* Time to disconnect */
            break;
        }

        if (!strncmp("F>", ptr, 2)) {
            if (proposals) {
                snprintf(reply, 32, "FS ");
                /* Defer decisions about any messages being offered */
                for (i = 0; i < proposals; i++) {
                    strcat(reply, "=");
                }
                strcat(reply, "\r");

                write(sd, reply, strlen(reply));
                #if DEBUG
                printf("<reply] %s\n", reply);
                #endif
            } else {
                snprintf(reply, 32, "FQ\r");
                write(sd, reply, strlen(reply));
                #if DEBUG
                printf("<reply] %s\n", reply);
                #endif
            }
            continue;
        }

        if (buffer[length - 1] == '>') {
            /* Got the CMS Prompt, reply with the secure login */
            if (strlen(challenge) > 0) {
                snprintf(reply, 32, ";FW: %s\r", callsign);
                write(sd, reply, strlen(reply));
                #if DEBUG
                printf("<reply] %s\n", reply);
                #endif

                wlsecauth(challenge, passwd, reply);

                write(sd, SID, strlen(SID));
                #if DEBUG
                printf("<reply] %s\n", SID);
                #endif

                write(sd, reply, strlen(reply));
                #if DEBUG
                printf("<reply] %s\n", reply);
                #endif

                challenge[0] = '\0';

                snprintf(reply, 32, "FF\r");
                write(sd, reply, strlen(reply));
                #if DEBUG
                printf("<reply] %s\n", reply);
                #endif
            } else {
                snprintf(reply, 32, "BYE\r");
                write(sd, reply, strlen(reply));
                #if DEBUG
                printf("<reply] %s\n", reply);
                #endif
            }
            continue;
        }

        if (!strncmp("***", ptr, 3)) {
            error++;

            #if !DEBUG
            printf("%s > %s\n", callsign, ptr);
            #endif
        }
    }

    if (!error) {
        if (proposals) {
            printf("Renewed %s \x1b[33m(%ld messages pending)\x1b[0m\n", callsign, proposals);
        } else {
            printf("Renewed %s\n", callsign);
        }
    }

    if (shutdown(sd, SHUT_RDWR) != 0) {
        perror("shutdown");
        return 1;
    }

    if (close(sd) != 0) {
        perror("close");
        return 1;
    }

    return 0;
}


int csvprocess(
        FILE* fd,
        csvhandler handler
    )
{
    char buffer[32];
    size_t i = 0;
    size_t len = 0;
    const char* callp = NULL;
    const char* passp = NULL;

    while ((len = fread(buffer, 1, 31, fd)) > 0) {
        buffer[len] = '\0';
        callp = buffer + 0;

        for (i = 0; i < len; i++) {
            if (buffer[i] == ',') {
                buffer[i] = '\0';
                i++;

                while (isspace(buffer[i])) {
                    i++;
                }

                passp = buffer + i;
            }

            if (buffer[i] == '\r' || buffer[i] == '\n' || buffer[i] == '\0') {
                if (buffer[i] == '\r' && buffer[i+1] == '\n') {
                    buffer[i] = '\0';
                    i++;
                }

                if (buffer[i] != '\0') {
                    buffer[i] = '\0';
                    i++;
                }

                break;
            }
        }

        if (fseek(fd, i - len, SEEK_CUR) == -1) {
            perror("fseek");
            return -1;
        }

        if (!strncmp("#", callp, 1)) {
            /* Allow "commenting out" callsigns for testing */
            callp = NULL;
            passp = NULL;
        }

        if (callp == NULL || passp == NULL) {
            continue;
        }

        if (handler(callp, passp) != 0) {
            return -1;
        }

        callp = NULL;
        passp = NULL;
    }


    return 0;
}


int main(
        int argc,
        char** argv
    )
{
    FILE* fd;
    char* filename;

#ifdef WIN32
    WSADATA ws;
    int err;

    if ((err = WSAStartup(MAKEWORD(2, 2), &ws)) != 0) {
        printf("WSAStartup failed with error: %d\n", err);
        return 5;
    }

    if (ws.wVersion != MAKEWORD(2, 2)) {
        printf("Could not find a usable version of Winsock.dll\n");
        WSACleanup();
        return 5;
    }
#endif

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
        usage(argv[0]);
        return 0;
    }

    filename = argv[1];

    if (!strcmp(argv[1], "--test")) {
        char buffer[16];

        wlsecauth("23753528", "FOOBAR", buffer);

        printf("Auth Test: Expected \";PR: 72768415\" and got %s\n", buffer);

        if (argc > 2) {
            filename = argv[2];
        } else {
            filename = "test.csv";
        }
    }

    if ((fd = fopen(filename, "r")) == NULL) {
        perror(argv[1]);
        return 2;
    }

    if (wlresolve(&serveraddr, WL2K_HOST, WL2K_PORT) == NULL) {
        return 3;
    }

    // Read from the CSV file
    if (!strcmp(argv[1], "--test")) {
        csvprocess(fd, &debugprint);
    } else {
        csvprocess(fd, &wlrenew);
    }

    if (fclose(fd) == EOF) {
        perror(argv[1]);
        return 4;
    }

#ifdef WIN32
    WSACleanup();
#endif

    return 0;
}
