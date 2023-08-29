#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#include "utils.h"

uint32_t integervalue(const char *intstr) {
  if (strlen(intstr) > 1 && intstr[0] == '0') {
    if (intstr[1] == 'x' || intstr[1] == 'X') {
      return strtoul(intstr, 0, 16);
    } else if (intstr[1] == 'o') {
      return strtoul(intstr, 0, 8);
    } else if (intstr[1] == 'b') {
      return strtoul(intstr, 0, 2);
    } else {
      return strtoul(intstr, 0, 10);
    }
  }
  return strtoul(intstr, 0, 10);
}

int macstr2addr(char *macstr, uint8_t addr[ETH_ALEN],
                       uint8_t mask[ETH_ALEN]) {
  char *token = NULL;
  char *rest = NULL;
  char *macCopy = strdup(macstr);
  char *maskstr = NULL;
  token = strtok_r(macCopy, "/", &rest);

  if (rest && strlen(rest) > 0) {
    for (int i = ETH_ALEN - 1; i >= 0; i--) {
      maskstr = strtok_r(rest, ":", &rest);
      sscanf(maskstr, "%hhx", &mask[i]);
    }
  }

  rest = token;
  for (int i = ETH_ALEN - 1; i >= 0; i--) {
    token = strtok_r(rest, ":", &rest);
    sscanf(token, "%hhx", &addr[i]);
  }

  free(macCopy);
  return 0;
}

int ipstr2addr(char *ipstr, uint32_t *ip, uint32_t *mask) {
  char *rest = NULL;
  char *ipCopy = strdup(ipstr);
  char *token = strtok_r(ipCopy, "/", &rest);

  inet_pton(AF_INET, token, ip);
  *ip = htonl(*ip);
  *mask = 0xFFFFFFFF;
  if (rest && strlen(rest)) {
    if (strstr(rest, ".")) {
      inet_pton(AF_INET, rest, mask);
      *mask = htonl(*mask);
    } else {
      *mask = integervalue(rest);
      if (*mask < 32) {
        *mask = ~(0xFFFFFFFF >> *mask);
      } else {
        *mask = 0xFFFFFFFF;
      }
    }
  }

  free(ipCopy);
  return 0;
}

int ip6str2addr(char *ipstr, uint32_t ip[4], uint32_t mask[4]) {
  char *rest = NULL;
  char *ipCopy = strdup(ipstr);
  char *token = strtok_r(ipCopy, "/", &rest);

  inet_pton(AF_INET6, token, ip);
  ip[0] = htonl(ip[0]);
  ip[1] = htonl(ip[1]);
  ip[2] = htonl(ip[2]);
  ip[3] = htonl(ip[3]);
  memset(mask, 0xFF, 4 * sizeof(uint32_t));
  if (rest && strlen(rest)) {
    if (strstr(rest, ":")) {
      inet_pton(AF_INET6, rest, mask);
      mask[0] = htonl(mask[0]);
      mask[1] = htonl(mask[1]);
      mask[2] = htonl(mask[2]);
      mask[3] = htonl(mask[3]);
    } else {
      mask[3] = integervalue(rest);
      if (mask[3] < 32) {
        mask[0] = ~(0xFFFFFFFF >> mask[3]);
        mask[1] = 0;
        mask[2] = 0;
        mask[3] = 0;
      } else if (mask[3] < 64) {
        mask[1] = ~(0xFFFFFFFF >> (mask[3] - 32));
        mask[2] = 0;
        mask[3] = 0;
      } else if (mask[3] < 96) {
        mask[2] = ~(0xFFFFFFFF >> (mask[3] - 64));
        mask[3] = 0;
      } else if (mask[3] < 128) {
        mask[3] = ~(0xFFFFFFFF >> (mask[3] - 96));
      } else if (mask[3] == 128) {
        mask[3] = 0xFFFFFFFF;
      }
    }
  }

  free(ipCopy);
  return 0;
}