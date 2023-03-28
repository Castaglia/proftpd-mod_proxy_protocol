/*
 * ProFTPD - mod_proxy_protocol
 * Copyright (c) 2013-2022 TJ Saunders
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 */

#include "conf.h"
#include "privs.h"

#if defined(HAVE_SYS_UIO_H)
# include <sys/uio.h>
#endif /* HAVE_SYS_UIO_H */

#define MOD_PROXY_PROTOCOL_VERSION	"mod_proxy_protocol/0.6.1"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030507
# error "ProFTPD 1.3.5a or later required"
#endif

/* From response.c.  XXX Need to provide these symbols another way. */
extern pr_response_t *resp_list;

module proxy_protocol_module;

#define PROXY_PROTOCOL_BUFSZ			128

#define PROXY_PROTOCOL_TIMEOUT_DEFAULT		3
static int proxy_protocol_timeout = PROXY_PROTOCOL_TIMEOUT_DEFAULT;

#define PROXY_PROTOCOL_VERSION_HAPROXY_V1	1
#define PROXY_PROTOCOL_VERSION_HAPROXY_V2	2
static unsigned int proxy_protocol_version = PROXY_PROTOCOL_VERSION_HAPROXY_V1;

/* mod_proxy_protocol option flags */
#define PROXY_PROTOCOL_OPT_USE_PROXIED_SERVER_ADDR	0x0001

static unsigned long proxy_protocol_opts = 0UL;

static const char *trace_channel = "proxy_protocol";

static int poll_sock(int sockfd) {
  fd_set rfds;
  int res = 0;
  struct timeval tv;

  memset(&tv, 0, sizeof(tv));
  tv.tv_sec = proxy_protocol_timeout;
  tv.tv_usec = 0;

  pr_trace_msg(trace_channel, 19,
    "waiting for max of %lu secs while polling socket %d using select(2)",
    (unsigned long) tv.tv_sec, sockfd);

  while (TRUE) {
    pr_signals_handle();

    FD_ZERO(&rfds);
    FD_SET(sockfd, &rfds);

    res = select(sockfd + 1, &rfds, NULL, NULL, &tv);
    if (res < 0) {
      int xerrno = errno;

      if (xerrno == EINTR) {
        pr_signals_handle();
        continue;
      }

      pr_trace_msg(trace_channel, 18, "error calling select(2) on fd %d: %s",
        sockfd, strerror(xerrno));

      errno = xerrno;
      return -1;

    } else if (res == 0) {
      memset(&tv, 0, sizeof(tv));
      tv.tv_sec = proxy_protocol_timeout;
      tv.tv_usec = 0;

      pr_trace_msg(trace_channel, 18,
        "polling on socket %d timed out after %lu sec, trying again", sockfd,
        (unsigned long) tv.tv_sec);
      continue;
    }

    break;
  }

  return 0;
}

static int read_sock(int sockfd, void *buf, size_t reqlen) {
  void *ptr = NULL;
  size_t remainlen = 0;

  if (reqlen == 0) {
    return 0;
  }

  errno = 0;
  ptr = buf;
  remainlen = reqlen;

  while (remainlen > 0) {
    int res, xerrno = 0;

    if (poll_sock(sockfd) < 0) {
      return -1;
    }

    res = read(sockfd, ptr, remainlen);
    xerrno = errno;

    while (res <= 0) {
      if (res < 0) {
        if (xerrno == EINTR) {
          pr_signals_handle();
          continue;
        }

        pr_trace_msg(trace_channel, 16,
          "error reading from client (fd %d): %s", sockfd, strerror(xerrno));
        pr_log_debug(DEBUG5, MOD_PROXY_PROTOCOL_VERSION
          ": error reading from client (fd %d): %s", sockfd, strerror(xerrno));

        /* We explicitly disconnect the client here because the errors below
         * all indicate a problem with the TCP connection.
         */
        if (xerrno == ECONNRESET ||
            xerrno == ECONNABORTED ||
#if defined(ETIMEDOUT)
            xerrno == ETIMEDOUT ||
#endif /* ETIMEDOUT */
#if defined(ENOTCONN)
            xerrno == ENOTCONN ||
#endif /* ENOTCONN */
#if defined(ESHUTDOWN)
            xerrno == ESHUTDOWN ||
#endif /* ESHUTDOWNN */
            xerrno == EPIPE) {
          errno = xerrno;

          pr_trace_msg(trace_channel, 16,
            "disconnecting client (%s)", strerror(xerrno));
          pr_log_debug(DEBUG0, MOD_PROXY_PROTOCOL_VERSION
            ": disconnecting client (%s)", strerror(xerrno));
          pr_session_disconnect(&proxy_protocol_module,
            PR_SESS_DISCONNECT_CLIENT_EOF, strerror(xerrno));
        }

        return -1;

      } else {
        /* If we read zero bytes here, treat it as an EOF and hang up on
         * the uncommunicative client.
         */

        pr_trace_msg(trace_channel, 16, "%s",
          "disconnecting client (received EOF)");
        pr_log_debug(DEBUG0, MOD_PROXY_PROTOCOL_VERSION
          ": disconnecting client (received EOF)");
        pr_session_disconnect(&proxy_protocol_module,
          PR_SESS_DISCONNECT_CLIENT_EOF, NULL);
      }
    }

    /* Generate an event for any interested listeners. */
    pr_event_generate("core.ctrl-read", buf);

    session.total_raw_in += reqlen;

    if ((size_t) res == remainlen) {
      break;
    }

    pr_trace_msg(trace_channel, 20, "read %lu bytes, expected %lu bytes; "
      "reading more", (unsigned long) res, (unsigned long) remainlen);
    ptr = ((char *) ptr + res);
    remainlen -= res;
  }

  return reqlen;
}

static int readv_sock(int sockfd, const struct iovec *iov, int count) {
  int res, xerrno = 0;

  if (poll_sock(sockfd) < 0) {
    return -1;
  }

  res = readv(sockfd, iov, count);
  xerrno = errno;

  while (res <= 0) {
    if (res < 0) {
      if (xerrno == EINTR) {
        pr_signals_handle();

        if (poll_sock(sockfd) < 0) {
          return -1;
        }

        res = readv(sockfd, iov, count);
        xerrno = errno;
        continue;
      }

      pr_trace_msg(trace_channel, 16,
        "error reading from client (fd %d): %s", sockfd, strerror(xerrno));
      pr_log_debug(DEBUG5, MOD_PROXY_PROTOCOL_VERSION
        ": error reading from client (fd %d): %s", sockfd, strerror(xerrno));

      /* We explicitly disconnect the client here because the errors below
       * all indicate a problem with the TCP connection.
       */
      if (xerrno == ECONNRESET ||
          xerrno == ECONNABORTED ||
#if defined(ETIMEDOUT)
          xerrno == ETIMEDOUT ||
#endif /* ETIMEDOUT */
#if defined(ENOTCONN)
          xerrno == ENOTCONN ||
#endif /* ENOTCONN */
#if defined(ESHUTDOWN)
          xerrno == ESHUTDOWN ||
#endif /* ESHUTDOWNN */
          xerrno == EPIPE) {

        pr_trace_msg(trace_channel, 16,
          "disconnecting client (%s)", strerror(xerrno));
        pr_log_debug(DEBUG0, MOD_PROXY_PROTOCOL_VERSION
          ": disconnecting client (%s)", strerror(xerrno));
        pr_session_disconnect(&proxy_protocol_module,
          PR_SESS_DISCONNECT_CLIENT_EOF, strerror(xerrno));

        return -1;
      }
    }

    /* If we read zero bytes here, treat it as an EOF and hang up on
     * the uncommunicative client.
     */

    pr_trace_msg(trace_channel, 16, "%s",
      "disconnecting client (received EOF)");
    pr_log_debug(DEBUG0, MOD_PROXY_PROTOCOL_VERSION
      ": disconnecting client (received EOF)");
    pr_session_disconnect(&proxy_protocol_module,
      PR_SESS_DISCONNECT_CLIENT_EOF, NULL);

    errno = ENOENT;
    return -1;
  }

  session.total_raw_in += res;
  return res;
}

static int is_tls_handshake(const unsigned char *buf, size_t buflen) {
  /* We can't tell if it's a TLS handshake record without at least 3 bytes of
   * data.
   */
  if (buflen < 3) {
    return -1;
  }

  if (buf[0] == 22 &&
      buf[1] == 3 &&
      (buf[2] == 0 || buf[2] == 1)) {
    /* SSLv3, TLSv1+ */
    return 0;
  }

  if (buf[0] == 128 &&
      buf[1] == 43 &&
      buf[2] == 1) {
    /* SSLv2 */
    return 0;
  }

  return -1;
}

static unsigned int strtou(const char **str, const char *last) {
  const char *ptr = *str;
  unsigned int i = 0, j, k;

  while (ptr < last) {
    pr_signals_handle();

    j = *ptr - '0';
    k = i * 10;

    if (j > 9) {
      break;
    }

    i = k + j;
    ptr++;
  }

  *str = ptr;
  return i;
}

/* This function waits for a PROXY protocol header at the beginning of the
 * raw data stream. The header looks like this:
 *
 *   "PROXY" <sp> PROTO <sp> SRC3 <sp> DST3 <sp> SRC4 <sp> <DST4> "\r\n"
 *
 * There must be exactly one space between each field. Fields are :
 *
 *  - PROTO: layer 4 protocol, which must be "TCP4" or "TCP6".
 *  - SRC3:  layer 3 (e.g. IP) source address in standard text form
 *  - DST3:  layer 3 (e.g. IP) destination address in standard text form
 *  - SRC4:  layer 4 (e.g. TCP port) source port in standard text form
 *  - DST4:  layer 4 (e.g. TCP port) destination port in standard text form
 */
static int read_haproxy_v1(pool *p, conn_t *conn,
    const pr_netaddr_t **proxied_src_addr, unsigned int *proxied_src_port,
    const pr_netaddr_t **proxied_dst_addr, unsigned int *proxied_dst_port) {
  register unsigned int i;
  char buf[PROXY_PROTOCOL_BUFSZ], *last = NULL, *ptr = NULL;
  int have_cr = FALSE, have_nl = FALSE, have_tcp4 = FALSE, have_tcp6 = FALSE;
  size_t buflen = 0;

  /* Read until we find the expected PROXY string. */

  memset(buf, '\0', sizeof(buf));
  ptr = buf;

  for (i = 0; i < sizeof(buf)-1; i++) {
    int res, xerrno;

    pr_signals_handle();

    res = read_sock(conn->rfd, &buf[i], 1);
    xerrno = errno;

    while (res <= 0) {
      if (xerrno == EINTR) {
        pr_signals_handle();

        res = read_sock(conn->rfd, &buf[i], 1);
        xerrno = errno;

        continue;
      }

      if (res < 0) {
        pr_log_debug(DEBUG5, MOD_PROXY_PROTOCOL_VERSION
          ": error reading from client socket: %s", strerror(xerrno));
        errno = xerrno;
        return -1;
      }
    }

    /* Decode a possible PROXY request as early as we can, and fail
     * early if it does not match.
     */
    if (i == 6) {
      if (strncmp(ptr, "PROXY ", 6) != 0) {
        /* Check for a common error, that of TLS handshake bytes instead of
         * PROXY bytes, to provide for a better diagnostic/log message.
         */
        if (is_tls_handshake((const unsigned char *) ptr, i) == 0) {
          pr_log_debug(DEBUG0, MOD_PROXY_PROTOCOL_VERSION
            ": received unexpected TLS handshake bytes from %s",
            pr_netaddr_get_ipstr(conn->remote_addr));
        }

        goto bad_proto;
      }

      ptr += 6;
    }

    /* We continue reading until the client has sent the terminating
     * CRLF sequence.
     */
    if (buf[i] == '\r') {
        have_cr = TRUE;
        buf[i] = '\0';
      continue;
    }

    if (have_cr == TRUE &&
        buf[i] == '\n') {
        have_nl = TRUE;
        buf[i] = '\0';
      break;
    }

    buflen++;
  }

  buf[sizeof(buf)-1] = '\0';

  pr_trace_msg(trace_channel, 7,
    "read %lu bytes of proxy data (minus CRLF): '%.100s'",
    (unsigned long) buflen, buf);

  if (have_nl == FALSE) {
    pr_log_debug(DEBUG5, MOD_PROXY_PROTOCOL_VERSION
      ": missing expected CRLF termination");
    goto bad_proto;
  }

  if (buflen == 0) {
    pr_log_debug(DEBUG0, MOD_PROXY_PROTOCOL_VERSION
      ": missing expected PROXY protocol data");
    goto bad_proto;
  }

  last = buf + buflen;

  /* Check the PROTO field: "TCP4" or "TCP6" are supported. */
  if (strncmp(ptr, "TCP4 ", 5) == 0) {
    have_tcp4 = TRUE;

#if defined(PR_USE_IPV6)
  } else if (strncmp(ptr, "TCP6 ", 5) == 0) {
    if (pr_netaddr_use_ipv6()) {
      have_tcp6 = TRUE;
    }

#endif /* PR_USE_IPV6 */
  }

  if (have_tcp4 == FALSE &&
      have_tcp6 == FALSE) {
    if (strncmp(ptr, "UNKNOWN", 7) == 0) {
      pr_log_debug(DEBUG5, MOD_PROXY_PROTOCOL_VERSION
        ": client cannot provide proxied address: '%.100s'", buf);
      errno = ENOENT;
      return 0;
    }

    pr_log_debug(DEBUG5, MOD_PROXY_PROTOCOL_VERSION
      ": unknown/unsupported PROTO field");
    goto bad_proto;

  } else {
    const pr_netaddr_t *src_addr = NULL, *dst_addr = NULL;
    char *ptr2 = NULL;
    unsigned int src_port, dst_port;
    int flags = PR_NETADDR_GET_ADDR_FL_EXCL_DNS;

    ptr += 5;

    ptr2 = strchr(ptr, ' ');
    if (ptr2 == NULL) {
      goto bad_proto;
    }

    *ptr2 = '\0';
    pr_trace_msg(trace_channel, 9,
      "resolving source address field '%s'", ptr);
    src_addr = pr_netaddr_get_addr2(p, ptr, NULL, flags);

    if (src_addr == NULL) {
      pr_log_debug(DEBUG0, MOD_PROXY_PROTOCOL_VERSION
        ": unable to resolve source address '%s': %s", ptr, strerror(errno));
      *ptr2 = ' ';
      goto bad_proto;

    } else {
      *ptr2 = ' ';
      pr_trace_msg(trace_channel, 9, "resolve source address '%s': %s",
        ptr, pr_netaddr_get_ipstr(src_addr));
    }

    ptr = ptr2 + 1;
    ptr2 = strchr(ptr, ' ');
    if (ptr2 == NULL) {
      goto bad_proto;
    }

    *ptr2 = '\0';
    pr_trace_msg(trace_channel, 9,
      "resolving destination address field '%s'", ptr);
    dst_addr = pr_netaddr_get_addr2(p, ptr, NULL, flags);

    if (dst_addr == NULL) {
      pr_log_debug(DEBUG0, MOD_PROXY_PROTOCOL_VERSION
        ": unable to resolve destination address '%s': %s", ptr,
        strerror(errno));
      *ptr2 = ' ';
      goto bad_proto;

    } else {
      *ptr2 = ' ';
      pr_trace_msg(trace_channel, 9, "resolve destination address '%s': %s",
        ptr, pr_netaddr_get_ipstr(dst_addr));
    }

    /* Check the address family against what the PROTO field says it should
     * be.  This is to pedantically guard against IPv6 addresses in a
     * "TCP4" PROXY line, or IPv4 addresses in a "TCP6" line.
     */

    /* TODO: Technically, it's possible that the remote client sent us DNS
     * names, rather than IP addresses, and we resolved them.  To pedantically
     * check for this, scan the given address fields for illegal (e.g.
     * alphabetic) characters, keeping in mind that IPv6 addresses can use
     * hex.
     */

    if (have_tcp4 == TRUE) {
      if (pr_netaddr_get_family(src_addr) != AF_INET) {
        pr_log_debug(DEBUG8, MOD_PROXY_PROTOCOL_VERSION
          ": expected IPv4 source address for '%s', got IPv6",
          pr_netaddr_get_ipstr(src_addr));
        errno = EINVAL;
        return -1;
      }

      if (pr_netaddr_get_family(dst_addr) != AF_INET) {
        pr_log_debug(DEBUG8, MOD_PROXY_PROTOCOL_VERSION
          ": expected IPv4 destination address for '%s', got IPv6",
          pr_netaddr_get_ipstr(dst_addr));
        errno = EINVAL;
        return -1;
      }

#if defined(PR_USE_IPV6)
    } else {
      if (pr_netaddr_get_family(src_addr) != AF_INET6) {
        pr_log_debug(DEBUG8, MOD_PROXY_PROTOCOL_VERSION
          ": expected IPv6 source address for '%s', got IPv4",
          pr_netaddr_get_ipstr(src_addr));
        errno = EINVAL;
        return -1;
      }

      if (pr_netaddr_get_family(dst_addr) != AF_INET6) {
        pr_log_debug(DEBUG8, MOD_PROXY_PROTOCOL_VERSION
          ": expected IPv6 destination address for '%s', got IPv4",
          pr_netaddr_get_ipstr(dst_addr));
        errno = EINVAL;
        return -1;
      }

      /* Handle IPv4-mapped IPv6 addresses as IPv4 addresses. */
      if (pr_netaddr_is_v4mappedv6(src_addr) == TRUE) {
        src_addr = pr_netaddr_v6tov4(p, src_addr);
      }

      if (pr_netaddr_is_v4mappedv6(dst_addr) == TRUE) {
        dst_addr = pr_netaddr_v6tov4(p, dst_addr);
      }
#endif /* PR_USE_IPV6 */
    }

    ptr = ptr2 + 1;
    ptr2 = strchr(ptr, ' ');
    if (ptr2 == NULL) {
      goto bad_proto;
    }

    *ptr2 = '\0';
    pr_trace_msg(trace_channel, 9,
      "resolving source port field '%s'", ptr);
    src_port = strtou((const char **) &ptr, last);

    if (src_port == 0) {
      pr_log_debug(DEBUG0, MOD_PROXY_PROTOCOL_VERSION
        ": invalid source port '%s' provided", ptr);
      *ptr2 = ' ';
      goto bad_proto;

    } else {
      *ptr2 = ' ';
      pr_trace_msg(trace_channel, 9, "resolved source port: %u", src_port);
    }

    if (src_port > 65535) {
      pr_log_debug(DEBUG0, MOD_PROXY_PROTOCOL_VERSION
        ": out-of-range source port provided: %u", src_port);
      goto bad_proto;
    }

    ptr = ptr2 + 1;
    pr_trace_msg(trace_channel, 9,
      "resolving destination port field '%s'", ptr);
    dst_port = strtou((const char **) &ptr, last);

    if (dst_port == 0) {
      pr_log_debug(DEBUG0, MOD_PROXY_PROTOCOL_VERSION
        ": invalid destination port '%s' provided", ptr);
      *ptr2 = ' ';
      goto bad_proto;

    } else {
      *ptr2 = ' ';
      pr_trace_msg(trace_channel, 9, "resolved destination port: %u", dst_port);
    }

    if (dst_port > 65535) {
      pr_log_debug(DEBUG0, MOD_PROXY_PROTOCOL_VERSION
        ": out-of-range destination port provided: %u", dst_port);
      goto bad_proto;
    }

    if (ptr > last) {
      goto bad_proto;
    }

    /* Paranoidly check the given source address/port against the
     * destination address/port.  If the two tuples match, then the remote
     * client is lying to us (it's not possible to have a TCP connection
     * FROM an address/port tuple which is identical to the destination
     * address/port tuple).
     */
    if (pr_netaddr_cmp(src_addr, dst_addr) == 0 &&
        src_port == dst_port) {
      pr_log_debug(DEBUG0, MOD_PROXY_PROTOCOL_VERSION
        ": source/destination address/port are IDENTICAL: %s#%u",
        pr_netaddr_get_ipstr(src_addr), src_port);
      goto bad_proto;
    }

    /* Set the source port for the source address. */
    pr_netaddr_set_port((pr_netaddr_t *) src_addr, htons(src_port));

    *proxied_src_addr = src_addr;
    *proxied_src_port = src_port;

    *proxied_dst_addr = dst_addr;
    *proxied_dst_port = dst_port;
  }

  return 1;

bad_proto:
  pr_log_debug(DEBUG0, MOD_PROXY_PROTOCOL_VERSION
    ": Bad/unsupported proxy protocol data '%.100s' from %s", buf,
    pr_netaddr_get_ipstr(conn->remote_addr));

  errno = EINVAL;
  return -1;
}

static void add_tlv_session_note(const char *key, const char *tlv_val,
    size_t tlv_valsz) {
  void *val;
  size_t valsz;

  /* TLVs are NOT null-terminated strings, but we want to store their
   * session notes as such.
   */
  valsz = tlv_valsz + 1;
  val = pr_table_pcalloc(session.notes, valsz);
  memcpy(val, tlv_val, tlv_valsz);

  pr_trace_msg(trace_channel, 17,
    "adding session note: %s = '%s'", key, (char *) val);
  (void) pr_table_add(session.notes, key, val, valsz);
}

static const char haproxy_v2_sig[12] = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";

/* See: https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-target-groups.html#proxy-protocol
 */
static int read_haproxy_v2_aws_tlv(pool *p, void *tlv_val, size_t tlv_valsz) {
  unsigned char *ptr;
  size_t len;

  ptr = tlv_val;
  len = tlv_valsz;

  while (len > 0) {
    uint8_t aws_type;
    uint16_t aws_len;
    void *aws_val;
    size_t aws_valsz;

    pr_signals_handle();

    memcpy(&aws_type, ptr, sizeof(aws_type));
    ptr += sizeof(aws_type);
    len -= sizeof(aws_type);

    memcpy(&aws_len, ptr, sizeof(aws_len));
    ptr += sizeof(aws_len);
    len -= sizeof(aws_len);

    aws_valsz = ntohs(aws_len);
    aws_val = ptr;
    len -= aws_valsz;

    switch (aws_type) {
      /* VPC Endpoint ID */
      case 0x01:
        pr_trace_msg(trace_channel, 19,
          "AWS TLV: VPC Endpoint ID: %.*s", (int) aws_valsz, (char *) aws_val);
        add_tlv_session_note("mod_proxy_protocol.aws.vpc-endpoint-id", aws_val,
          aws_valsz);
        break;

      default:
        pr_trace_msg(trace_channel, 3,
          "unsupported AWS TLV: %0x", aws_type);
    }

    /* Don't forget to advance ptr, for any more encapsulated TLVs. */
    ptr += aws_valsz;
  }

  return 0;
}

/* See: https://github.com/MicrosoftDocs/azure-docs/blob/main/articles/private-link/private-link-service-overview.md#getting-connection-information-using-tcp-proxy-v2
 */
static int read_haproxy_v2_azure_tlv(pool *p, void *tlv_val, size_t tlv_valsz) {
  unsigned char *ptr;
  size_t len;

  ptr = tlv_val;
  len = tlv_valsz;

  while (len > 0) {
    uint8_t azure_type;
    uint16_t azure_len;
    void *azure_val;
    size_t azure_valsz;

    pr_signals_handle();

    memcpy(&azure_type, ptr, sizeof(azure_type));
    ptr += sizeof(azure_type);
    len -= sizeof(azure_type);

    memcpy(&azure_len, ptr, sizeof(azure_len));
    ptr += sizeof(azure_len);
    len -= sizeof(azure_len);

    azure_valsz = ntohs(azure_len);
    azure_val = ptr;
    len -= azure_valsz;

    switch (azure_type) {
      /* Private Endpoint LinkID */
      case 0x01: {
        if (azure_valsz == 4) {
          uint32_t link_id;
          char *link_id_text;
          size_t link_id_textsz;

          /* Since the LinkID value is little-endian (per docs), we need not
           * worry about converting its encoding.
           */
          memcpy(&link_id, azure_val, azure_valsz);

          pr_trace_msg(trace_channel, 19,
            "Azure TLV: Private Endpoint LinkID: %lu", (unsigned long) link_id);

          link_id_textsz = 32;
          link_id_text = pcalloc(p, link_id_textsz);
          (void) snprintf(link_id_text, link_id_textsz-1, "%u", link_id);

          add_tlv_session_note("mod_proxy_protocol.azure.private-endpoint-linkid",
            link_id_text, strlen(link_id_text)-1);

        } else {
          pr_trace_msg(trace_channel, 1,
            "Azure TLV: Private Endpoint LinkID: invalid value length (%u), "
            "expected 4, ignoring value", (unsigned int) azure_valsz);
        }

        break;
      }

      default:
        pr_trace_msg(trace_channel, 3,
          "unsupported Azure TLV: %0x", azure_type);
    }

    /* Don't forget to advance ptr, for any more encapsulated TLVs. */
    ptr += azure_valsz;
  }

  return 0;
}

/* The TLS TLV is convoluted enough to warrant its own special function. */
static int read_haproxy_v2_tls_tlv(pool *p, void *tlv_val, size_t tlv_valsz) {
  uint8_t client;
  uint32_t verify;
  unsigned char *ptr;
  size_t len;

  ptr = tlv_val;
  len = tlv_valsz;

  memcpy(&client, ptr, sizeof(client));
  ptr += sizeof(client);
  len -= sizeof(client);

  memcpy(&verify, ptr, sizeof(verify));
  ptr += sizeof(verify);
  len -= sizeof(verify);
  verify = ntohl(verify);

  if (client > 0) {
    /* CLIENT_CERT_CONN */
    if (client & 0x02) {
      pr_trace_msg(trace_channel, 19,
        "TLS TLV: client provided certificate over current connection");

    /* CLIENT_CERT_SESS */
    } else if (client & 0x04) {
      pr_trace_msg(trace_channel, 19,
        "TLS TLV: client provided certificate over current TLS session");

    } else {
      pr_trace_msg(trace_channel, 19, "TLS TLV: client connected using TLS");
    }

  } else {
    pr_trace_msg(trace_channel, 19,
      "TLS TLV: client did not connect using TLS");
  }

  if (verify == 0) {
    pr_trace_msg(trace_channel, 19,
      "TLS TLV: client provided verified certificate");

  } else {
    pr_trace_msg(trace_channel, 19,
      "TLS TLV: client did not provide verified certificate");
  }

  while (len > 0) {
    uint8_t tls_type;
    uint16_t tls_len;
    void *tls_val;
    size_t tls_valsz;

    pr_signals_handle();

    memcpy(&tls_type, ptr, sizeof(tls_type));
    ptr += sizeof(tls_type);
    len -= sizeof(tls_type);

    memcpy(&tls_len, ptr, sizeof(tls_len));
    ptr += sizeof(tls_len);
    len -= sizeof(tls_len);

    tls_valsz = ntohs(tls_len);
    tls_val = ptr;
    len -= tls_valsz;

    switch (tls_type) {
      /* TLS version */
      case 0x21:
        pr_trace_msg(trace_channel, 19,
          "TLS TLV: TLS version: %.*s", (int) tls_valsz, (char *) tls_val);
        add_tlv_session_note("mod_proxy_protocol.tls.version", tls_val,
          tls_valsz);
        break;

      /* TLS CN */
      case 0x22:
        pr_trace_msg(trace_channel, 19,
          "TLS TLV: TLS CN: %*.s", (int) tls_valsz, (char *) tls_val);
        add_tlv_session_note("mod_proxy_protocol.tls.common-name", tls_val,
          tls_valsz);
        break;

      /* TLS cipher */
      case 0x23:
        pr_trace_msg(trace_channel, 19,
          "TLS TLV: TLS cipher: %.*s", (int) tls_valsz, (char *) tls_val);
        add_tlv_session_note("mod_proxy_protocol.tls.cipher", tls_val,
          tls_valsz);
        break;

      /* TLS signature algorithm */
      case 0x24:
        pr_trace_msg(trace_channel, 19,
          "TLS TLV: TLS signature algorithm: %.*s", (int) tls_valsz,
          (char *) tls_val);
        add_tlv_session_note("mod_proxy_protocol.tls.signature-algo", tls_val,
          tls_valsz);
        break;

      /* TLS key algorithm */
      case 0x25:
        pr_trace_msg(trace_channel, 19,
          "TLS TLV: TLS key algorithm: %.*s", (int) tls_valsz,
          (char *) tls_val);
        add_tlv_session_note("mod_proxy_protocol.tls.key-algo", tls_val,
          tls_valsz);
        break;

      default:
        pr_trace_msg(trace_channel, 3,
          "unsupported TLS TLV: %0x", tls_type);
    }

    /* Don't forget to advance ptr, for any more encapsulated TLVs. */
    ptr += tls_valsz;
  }

  return 0;
}

static int read_haproxy_v2_tlvs(pool *p, conn_t *conn, size_t len) {
  while (len > 0) {
    int res;
    uint8_t tlv_type;
    uint16_t tlv_len;
    size_t tlv_valsz;
    void *tlv_val;
    struct iovec tlv_hdr[2];

    pr_signals_handle();

    tlv_hdr[0].iov_base = (void *) &tlv_type;
    tlv_hdr[0].iov_len = sizeof(tlv_type);
    tlv_hdr[1].iov_base = (void *) &tlv_len;
    tlv_hdr[1].iov_len = sizeof(tlv_len);

    res = readv_sock(conn->rfd, tlv_hdr, 2);
    if (res < 0) {
      return -1;
    }

    if (res != 3) {
      pr_trace_msg(trace_channel, 20, "read %lu TLV bytes, expected %lu bytes",
        (unsigned long) res, (unsigned long) 3);
      errno = EPERM;
      return -1;
    }

    len -= res;

    tlv_valsz = ntohs(tlv_len);
    tlv_val = palloc(p, tlv_valsz);

    /* TODO: Handle short reads, interrupted reads better? */
    res = read(conn->rfd, tlv_val, tlv_valsz);
    if (res < 0) {
      return -1;
    }

    if ((size_t) res != tlv_valsz) {
      pr_trace_msg(trace_channel, 20, "read %lu TLV bytes, expected %lu bytes",
        (unsigned long) res, (unsigned long) tlv_valsz);
      errno = EPERM;
      return -1;
    }

    len -= res;

    switch (tlv_type) {
      /* ALPN */
      case 0x01:
        pr_trace_msg(trace_channel, 19,
          "received proxy protocol V2 ALPN: %.*s", (int) tlv_valsz,
          (char *) tlv_val);
        add_tlv_session_note("mod_proxy_protocol.alpn", tlv_val, tlv_valsz);
        break;

      /* "Authority" (server name, ala SNI) */
      case 0x02:
        pr_trace_msg(trace_channel, 19,
          "received proxy protocol V2 Authority (SNI): %.*s", (int) tlv_valsz,
          (char *) tlv_val);
        add_tlv_session_note("mod_proxy_protocol.authority", tlv_val,
          tlv_valsz);
        break;

      /* CRC32 */
      case 0x03:
        pr_trace_msg(trace_channel, 19,
          "received proxy protocol V2 CRC32 TLV (%lu bytes)",
          (unsigned long) tlv_valsz);
        break;

      /* NOOP */
      case 0x04:
        pr_trace_msg(trace_channel, 19,
          "received proxy protocol V2 NOOP TLV (%lu bytes)",
          (unsigned long) tlv_valsz);
        break;

      /* Unique ID */
      case 0x05:
        pr_trace_msg(trace_channel, 19,
          "received proxy protocol V2 Unique ID TLV (%lu bytes)",
          (unsigned long) tlv_valsz);
        add_tlv_session_note("mod_proxy_protocol.unique-id", tlv_val,
          tlv_valsz);
        break;

      /* TLS */
      case 0x20:
        pr_trace_msg(trace_channel, 19,
          "received proxy protocol V2 TLS TLV (%lu bytes)",
          (unsigned long) tlv_valsz);
        if (read_haproxy_v2_tls_tlv(p, tlv_val, tlv_valsz) < 0) {
          return -1;
        }
        break;

      /* Network namespace */
      case 0x30:
        pr_trace_msg(trace_channel, 19,
          "received proxy protocol V2 Network Namespace: %.*s",
          (int) tlv_valsz, (char *) tlv_val);
        break;

      /* AWS custom TLVs */
      case 0xEA:
        pr_trace_msg(trace_channel, 19,
          "received proxy protocol V2 AWS custom TLV: %.*s",
          (int) tlv_valsz, (char *) tlv_val);
        if (read_haproxy_v2_aws_tlv(p, tlv_val, tlv_valsz) < 0) {
          return -1;
        }
        break;

      /* Azure custom TLVs */
      case 0xEE:
        pr_trace_msg(trace_channel, 19,
          "received proxy protocol V2 Azure custom TLV: %.*s",
          (int) tlv_valsz, (char *) tlv_val);
        if (read_haproxy_v2_azure_tlv(p, tlv_val, tlv_valsz) < 0) {
          return -1;
        }
        break;

      default:
        pr_trace_msg(trace_channel, 3,
          "unsupported proxy protocol TLV: %0x", tlv_type);
    }
  }

  return 0;
}

static int read_haproxy_v2(pool *p, conn_t *conn,
    const pr_netaddr_t **proxied_src_addr, unsigned int *proxied_src_port,
    const pr_netaddr_t **proxied_dst_addr, unsigned int *proxied_dst_port) {
  int res = 0;
  uint8_t v2_sig[12], ver_cmd, trans_fam;
  uint16_t v2_len;
  struct iovec v2_hdr[4];
  const pr_netaddr_t *src_addr = NULL, *dst_addr = NULL;

  v2_hdr[0].iov_base = (void *) v2_sig;
  v2_hdr[0].iov_len = sizeof(v2_sig);
  v2_hdr[1].iov_base = (void *) &ver_cmd;
  v2_hdr[1].iov_len = sizeof(ver_cmd);
  v2_hdr[2].iov_base = (void *) &trans_fam;
  v2_hdr[2].iov_len = sizeof(trans_fam);
  v2_hdr[3].iov_base = (void *) &v2_len;
  v2_hdr[3].iov_len = sizeof(v2_len);

  res = readv_sock(conn->rfd, v2_hdr, 4);
  if (res < 0) {
    return -1;
  }

  if (res != 16) {
    pr_trace_msg(trace_channel, 20, "read %lu V2 bytes, expected %lu bytes",
      (unsigned long) res, (unsigned long) 16);
    errno = EPERM;
    return -1;
  }

  /* Validate the obtained data. */
  if (memcmp(v2_sig, haproxy_v2_sig, sizeof(haproxy_v2_sig)) != 0) {
    pr_trace_msg(trace_channel, 3,
      "invalid proxy protocol V2 signature, rejecting");

    /* Check for a common error, that of TLS handshake bytes instead of
     * PROXY bytes, to provide for a better diagnostic/log message.
     */
    if (is_tls_handshake(v2_sig, sizeof(v2_sig)) == 0) {
      pr_log_debug(DEBUG0, MOD_PROXY_PROTOCOL_VERSION
        ": received unexpected TLS handshake bytes from %s",
        pr_netaddr_get_ipstr(conn->remote_addr));
    }

    errno = EINVAL;
    return -1;
  }

  if ((ver_cmd & 0xF0) != 0x20) {
    pr_trace_msg(trace_channel, 3,
      "PROXY V2 version/command value (%0x) did not match expected protocol "
      "version (0x20)", ver_cmd);
    errno = EINVAL;
    return -1;
  }

  switch (ver_cmd & 0xF) {
    /* PROXY command */
    case 0x01:
      switch (trans_fam) {
        /* TCP, IPv4 */
        case 0x11: {
          uint32_t src_ipv4, dst_ipv4;
          uint16_t src_port, dst_port;
          struct iovec ipv4[4];
          struct sockaddr_in *saddr;
          size_t tlv_len = 0;

          pr_trace_msg(trace_channel, 17,
            "received proxy protocol V2 TCP/IPv4 transport family (%lu bytes)",
            (unsigned long) ntohs(v2_len));

          if (ntohs(v2_len) > 12) {
            /* The addresses are followed by TLVs. */
            tlv_len = ntohs(v2_len) - 12;
            pr_trace_msg(trace_channel, 3,
              "proxy protocol V2 TCP/IPv4 transport family received %lu bytes "
              "of TLV data", (unsigned long) tlv_len);
          }

          ipv4[0].iov_base = (void *) &src_ipv4;
          ipv4[0].iov_len = sizeof(src_ipv4);
          ipv4[1].iov_base = (void *) &dst_ipv4;
          ipv4[1].iov_len = sizeof(dst_ipv4);
          ipv4[2].iov_base = (void *) &src_port;
          ipv4[2].iov_len = sizeof(src_port);
          ipv4[3].iov_base = (void *) &dst_port;
          ipv4[3].iov_len = sizeof(dst_port);

          res = readv_sock(conn->rfd, ipv4, 4);
          if (res < 0) {
            return -1;
          }

          if (tlv_len > 0) {
            if (read_haproxy_v2_tlvs(p, conn, tlv_len) < 0) {
              return -1;
            }
          }

          src_addr = pr_netaddr_alloc(p);
          pr_netaddr_set_family((pr_netaddr_t *) src_addr, AF_INET);
          saddr = (struct sockaddr_in *) pr_netaddr_get_sockaddr(src_addr);
          saddr->sin_family = AF_INET;
          saddr->sin_addr.s_addr = src_ipv4;
          saddr->sin_port = src_port;
          pr_netaddr_set_port((pr_netaddr_t *) src_addr, src_port);

          dst_addr = pr_netaddr_alloc(p);
          pr_netaddr_set_family((pr_netaddr_t *) dst_addr, AF_INET);
          saddr = (struct sockaddr_in *) pr_netaddr_get_sockaddr(dst_addr);
          saddr->sin_family = AF_INET;
          saddr->sin_addr.s_addr = dst_ipv4;
          saddr->sin_port = dst_port;
          pr_netaddr_set_port((pr_netaddr_t *) dst_addr, dst_port);

          pr_trace_msg(trace_channel, 17,
            "received proxy protocol V2 TCP/IPv4 transport family: "
            "source address %s#%d, destination address %s#%d",
            pr_netaddr_get_ipstr(src_addr), ntohs(src_port),
            pr_netaddr_get_ipstr(dst_addr), ntohs(dst_port));

          break;
        }

        /* TCP, IPv6 */
        case 0x21: {
          uint8_t src_ipv6[16], dst_ipv6[16];
          uint16_t src_port, dst_port;
          struct iovec ipv6[4];
          struct sockaddr_in6 *saddr;
          size_t tlv_len = 0;

          pr_trace_msg(trace_channel, 17,
            "received proxy protocol V2 TCP/IPv6 transport family (%lu bytes)",
            (unsigned long) ntohs(v2_len));

          if (ntohs(v2_len) > 36) {
            /* The addresses are followed by TLVs. */
            tlv_len = ntohs(v2_len) - 36;
            pr_trace_msg(trace_channel, 3,
              "proxy protocol V2 TCP/IPv4 transport family received %lu bytes "
              "of TLV data", (unsigned long) tlv_len);
          }

#if defined(PR_USE_IPV6)
          ipv6[0].iov_base = (void *) &src_ipv6;
          ipv6[0].iov_len = sizeof(src_ipv6);
          ipv6[1].iov_base = (void *) &dst_ipv6;
          ipv6[1].iov_len = sizeof(dst_ipv6);
          ipv6[2].iov_base = (void *) &src_port;
          ipv6[2].iov_len = sizeof(src_port);
          ipv6[3].iov_base = (void *) &dst_port;
          ipv6[3].iov_len = sizeof(dst_port);

          res = readv_sock(conn->rfd, ipv6, 4);
          if (res < 0) {
            return -1;
          }

          if (tlv_len > 0) {
            if (read_haproxy_v2_tlvs(p, conn, tlv_len) < 0) {
              return -1;
            }
          }

          src_addr = pr_netaddr_alloc(p);
          pr_netaddr_set_family((pr_netaddr_t *) src_addr, AF_INET6);
          saddr = (struct sockaddr_in6 *) pr_netaddr_get_sockaddr(src_addr);
          saddr->sin6_family = AF_INET6;
          memcpy(&(saddr->sin6_addr), src_ipv6, sizeof(src_ipv6));
          saddr->sin6_port = src_port;
          pr_netaddr_set_port((pr_netaddr_t *) src_addr, src_port);

          dst_addr = pr_netaddr_alloc(p);
          pr_netaddr_set_family((pr_netaddr_t *) dst_addr, AF_INET6);
          saddr = (struct sockaddr_in6 *) pr_netaddr_get_sockaddr(dst_addr);
          saddr->sin6_family = AF_INET6;
          memcpy(&(saddr->sin6_addr), dst_ipv6, sizeof(dst_ipv6));
          saddr->sin6_port = dst_port;
          pr_netaddr_set_port((pr_netaddr_t *) dst_addr, dst_port);

          /* Handle IPv4-mapped IPv6 addresses as IPv4 addresses. */
          if (pr_netaddr_is_v4mappedv6(src_addr) == TRUE) {
            src_addr = pr_netaddr_v6tov4(p, src_addr);
          }

          if (pr_netaddr_is_v4mappedv6(dst_addr) == TRUE) {
            dst_addr = pr_netaddr_v6tov4(p, dst_addr);
          }

          pr_trace_msg(trace_channel, 17,
            "received proxy protocol V2 TCP/IPv6 transport family: "
            "source address %s#%d, destination address %s#%d",
            pr_netaddr_get_ipstr(src_addr), ntohs(src_port),
            pr_netaddr_get_ipstr(dst_addr), ntohs(dst_port));
#else
          /* Avoid compiler warnings about unused variables. */
          (void) src_ipv6;
          (void) dst_ipv6;
          (void) src_port;
          (void) dst_port;
          (void) ipv6;
          (void) saddr;

          pr_trace_msg(trace_channel, 3,
            "IPv6 support disabled, ignoring proxy protocol V2 data");
#endif /* PR_USE_IPV6 */
          break;
        }

        /* Unix */
        case 0x31: {
          unsigned char src_path[108];
          unsigned char dst_path[108];

          pr_trace_msg(trace_channel, 17,
            "received proxy protocol V2 Unix transport family "
            "(%lu bytes), ignoring", (unsigned long) ntohs(v2_len));

          if (ntohs(v2_len) != 216) {
            pr_trace_msg(trace_channel, 3,
              "proxy protocol V2 Unix transport family sent %lu bytes, "
              "expected %lu bytes", (unsigned long) ntohs(v2_len),
              (unsigned long) 216);
            errno = EINVAL;
            return -1;
          }

          res = read_sock(conn->rfd, src_path, sizeof(src_path));
          if (res > 0) {
            pr_trace_msg(trace_channel, 15,
              "received proxy protocol V2 Unix source path: '%s'", src_path);
          }

          res = read_sock(conn->rfd, dst_path, sizeof(dst_path));
          if (res > 0) {
            pr_trace_msg(trace_channel, 15,
              "received proxy protocol V2 Unix destination path: '%s'",
             dst_path);
          }

          break;
        }

        /* Unspecified */
        case 0x00: {
          pool *tmp_pool;
          unsigned char *buf;
          size_t buflen;

          buflen = ntohs(v2_len);

          pr_trace_msg(trace_channel, 17,
            "received proxy protocol V2 unspecified transport family "
            "(%lu bytes), ignoring", (unsigned long) buflen);

          tmp_pool = make_sub_pool(p);
          buf = palloc(tmp_pool, buflen);
          (void) read_sock(conn->rfd, buf, buflen);
          destroy_pool(tmp_pool);
          break;
        }

        default:
          pr_trace_msg(trace_channel, 3,
            "unsupported proxy protocol V2 transport family: %u", trans_fam);
          errno = EINVAL;
          return -1;
      }
      break;

    /* LOCAL command */
    case 0x00:
      /* Keep local connection address for LOCAL commands. */
      pr_trace_msg(trace_channel, 17,
        "received proxy protocol V2 LOCAL command, ignoring");
      return 0;

    default:
      pr_trace_msg(trace_channel, 3,
        "unsupported proxy protocol V2 command: %u", ver_cmd);
      errno = EINVAL;
      return -1;
  }

  if (src_addr == NULL &&
      dst_addr == NULL) {
    return 0;
  }

  /* Paranoidly check the given source address/port against the
   * destination address/port.  If the two tuples match, then the remote
   * client is lying to us (it's not possible to have a TCP connection
   * FROM an address/port tuple which is identical to the destination
   * address/port tuple).
   */
  if (pr_netaddr_cmp(src_addr, dst_addr) == 0 &&
      pr_netaddr_get_port(src_addr) == pr_netaddr_get_port(dst_addr)) {
    pr_log_debug(DEBUG0, MOD_PROXY_PROTOCOL_VERSION
      ": source/destination address/port are IDENTICAL: %s#%u",
      pr_netaddr_get_ipstr(src_addr), ntohs(pr_netaddr_get_port(src_addr)));
    errno = EPERM;
    return -1;
  }

  *proxied_src_addr = src_addr;
  *proxied_src_port = ntohs(pr_netaddr_get_port(src_addr));

  *proxied_dst_addr = dst_addr;
  *proxied_dst_port = ntohs(pr_netaddr_get_port(dst_addr));

  return 0;
}

static int read_proxied_addrs(pool *p, conn_t *conn,
   const pr_netaddr_t **proxied_src_addr, unsigned int *proxied_src_port,
   const pr_netaddr_t **proxied_dst_addr, unsigned int *proxied_dst_port) {
  int res;

  /* Note that in theory, we could auto-detect the protocol version. */

  switch (proxy_protocol_version) {
    case PROXY_PROTOCOL_VERSION_HAPROXY_V1:
      pr_trace_msg(trace_channel, 19, "reading PROXY V1 message");
      res = read_haproxy_v1(p, conn, proxied_src_addr, proxied_src_port,
        proxied_dst_addr, proxied_dst_port);
      break;

    case PROXY_PROTOCOL_VERSION_HAPROXY_V2:
      pr_trace_msg(trace_channel, 19, "reading PROXY V2 message");
      res = read_haproxy_v2(p, conn, proxied_src_addr, proxied_src_port,
        proxied_dst_addr, proxied_dst_port);
      break;

    default:
      errno = ENOSYS;
      res = -1;
  }

  return res;
}

static int proxy_protocol_timeout_cb(CALLBACK_FRAME) {
  pr_event_generate("proxy_protocol.timeout", NULL);

  pr_log_debug(DEBUG0, MOD_PROXY_PROTOCOL_VERSION
    ": proxy protocol timeout (%d %s) reached, disconnecting client",
    proxy_protocol_timeout, proxy_protocol_timeout != 1 ? "secs" : "sec");
  pr_session_disconnect(&proxy_protocol_module, PR_SESS_DISCONNECT_TIMEOUT,
    "ProxyProtocolTimeout");

  return 0;
}

/* Configuration handlers
 */

/* usage: ProxyProtocolEngine on|off */
MODRET set_proxyprotocolengine(cmd_rec *cmd) {
  int engine = 0;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  engine = get_boolean(cmd, 1);
  if (engine == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = engine;

  return PR_HANDLED(cmd);
}

/* usage: ProxyProtocolIgnore on|off */
MODRET set_proxyprotocolignore(cmd_rec *cmd) {
  int ignore = 0;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  ignore = get_boolean(cmd, 1);
  if (ignore == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = ignore;

  return PR_HANDLED(cmd);
}

/* usage: ProxyProtocolOptions opt1 ... */
MODRET set_proxyprotocoloptions(cmd_rec *cmd) {
  register unsigned int i;
  unsigned long opts = 0UL;
  config_rec *c = NULL;

  if (cmd->argc-1 == 0) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param(cmd->argv[0], 1, NULL);

  for (i = 1; i < cmd->argc; i++) {
    if (strcmp(cmd->argv[i], "UseProxiedServerAddress") == 0) {
      opts |= PROXY_PROTOCOL_OPT_USE_PROXIED_SERVER_ADDR;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown ProxyProtocolOption '",
        cmd->argv[i], "'", NULL));
    }
  }

  c->argv[0] = pcalloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = opts;

  return PR_HANDLED(cmd);
}

/* usage: ProxyProtocolTimeout nsecs */
MODRET set_proxyprotocoltimeout(cmd_rec *cmd) {
  int timeout = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (pr_str_get_duration(cmd->argv[1], &timeout) < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error parsing timeout value '",
      cmd->argv[1], "': ", strerror(errno), NULL));
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = timeout;

  return PR_HANDLED(cmd);
}

/* usage: ProxyProtocolVersion protocol */
MODRET set_proxyprotocolversion(cmd_rec *cmd) {
  int proto_version = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (strcasecmp(cmd->argv[1], "haproxyV1") == 0) {
    proto_version = PROXY_PROTOCOL_VERSION_HAPROXY_V1;

  } else if (strcasecmp(cmd->argv[1], "haproxyV2") == 0) {
    proto_version = PROXY_PROTOCOL_VERSION_HAPROXY_V2;

  } else {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unknown protocol/version: ",
      cmd->argv[1], NULL));
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = proto_version;

  return PR_HANDLED(cmd);
}

/* Initialization routines
 */

static int proxy_protocol_sess_init(void) {
  config_rec *c;
  int engine = 0, ignore = FALSE, res = 0, timerno = -1, xerrno;
  const pr_netaddr_t *proxied_src_addr = NULL, *proxied_dst_addr = NULL;
  unsigned int proxied_src_port = 0, proxied_dst_port = 0;
  const char *remote_ip = NULL, *remote_name = NULL;
  pr_netio_t *tls_netio = NULL;

  c = find_config(main_server->conf, CONF_PARAM, "ProxyProtocolEngine", FALSE);
  if (c != NULL) {
    engine = *((int *) c->argv[0]);
  }

  if (engine == FALSE) {
    return 0;
  }

  /* ProxyProtocolIgnore */
  c = find_config(main_server->conf, CONF_PARAM, "ProxyProtocolIgnore", FALSE);
  if (c != NULL) {
    ignore = *((int *) c->argv[0]);
  }

  /* ProxyProtocolOptions */
  c = find_config(main_server->conf, CONF_PARAM, "ProxyProtocolOptions", FALSE);
  while (c != NULL) {
    unsigned long opts = 0;

    pr_signals_handle();

    opts = *((unsigned long *) c->argv[0]);
    proxy_protocol_opts |= opts;

    c = find_config_next(c, c->next, CONF_PARAM, "ProxyProtocolOptions", FALSE);
  }

  c = find_config(main_server->conf, CONF_PARAM, "ProxyProtocolTimeout", FALSE);
  if (c != NULL) {
    proxy_protocol_timeout = *((int *) c->argv[0]);
  }

  c = find_config(main_server->conf, CONF_PARAM, "ProxyProtocolVersion", FALSE);
  if (c != NULL) {
    proxy_protocol_version = *((int *) c->argv[0]);
  }

  if (proxy_protocol_timeout > 0) {
    timerno = pr_timer_add(proxy_protocol_timeout, -1,
      &proxy_protocol_module, proxy_protocol_timeout_cb,
      "ProxyProtocolTimeout");
  }

  /* If the mod_tls module is in effect, then we need to work around its
   * use of the NetIO API.  Otherwise, trying to read the proxied addresses
   * on the control connection will cause problems, e.g. for FTPS clients
   * using implicit TLS.
   */
  tls_netio = pr_get_netio(PR_NETIO_STRM_CTRL);
  if (tls_netio == NULL ||
      tls_netio->owner_name == NULL ||
      strncmp(tls_netio->owner_name, "tls", 4) != 0) {

    /* Not a mod_tls netio; ignore it. */
    tls_netio = NULL;

  } else {
    /* Unregister it; we'll put it back after reading the proxied addresses. */
    pr_unregister_netio(PR_NETIO_STRM_CTRL);
  }

  res = read_proxied_addrs(session.pool, session.c, &proxied_src_addr,
    &proxied_src_port, &proxied_dst_addr, &proxied_dst_port);
  xerrno = errno;

  if (tls_netio != NULL) {
    if (pr_register_netio(tls_netio, PR_NETIO_STRM_CTRL) < 0) {
      pr_log_debug(DEBUG1, MOD_PROXY_PROTOCOL_VERSION
        ": unable to re-register TLS control NetIO: %s", strerror(errno));
    }
  }

  if (proxy_protocol_timeout > 0) {
    pr_timer_remove(timerno, &proxy_protocol_module);
  }

  if (res < 0) {
    pr_log_debug(DEBUG0, MOD_PROXY_PROTOCOL_VERSION
      ": error reading proxy info: %s", strerror(xerrno));

    errno = EPERM;
    return -1;
  }

  if (ignore == TRUE) {
    pr_log_debug(DEBUG10, MOD_PROXY_PROTOCOL_VERSION
      ": ProxyProtocolIgnore is in effect, ignoring proxied source "
      "address '%s'", pr_netaddr_get_ipstr(proxied_src_addr));
    return 0;
  }

  if (proxied_src_addr != NULL) {
    remote_ip = pstrdup(session.pool,
      pr_netaddr_get_ipstr(pr_netaddr_get_sess_remote_addr()));
    remote_name = pstrdup(session.pool,
      pr_netaddr_get_sess_remote_name());

    pr_log_debug(DEBUG9, MOD_PROXY_PROTOCOL_VERSION
      ": using proxied source address: %s",
      pr_netaddr_get_ipstr(proxied_src_addr));

    session.c->remote_addr = proxied_src_addr;
    session.c->remote_port = proxied_src_port;

    /* Now perform reverse DNS lookups. */
    if (ServerUseReverseDNS) {
      int reverse_dns;

      reverse_dns = pr_netaddr_set_reverse_dns(ServerUseReverseDNS);
      session.c->remote_name = pr_netaddr_get_dnsstr(session.c->remote_addr);

      pr_netaddr_set_reverse_dns(reverse_dns);

    } else {
      session.c->remote_name = pr_netaddr_get_ipstr(session.c->remote_addr);
    }

    pr_log_debug(DEBUG0, MOD_PROXY_PROTOCOL_VERSION
      ": UPDATED client remote address/name: %s/%s (WAS %s/%s)",
      pr_netaddr_get_ipstr(pr_netaddr_get_sess_remote_addr()),
      pr_netaddr_get_sess_remote_name(), remote_ip, remote_name);

    if (proxy_protocol_opts & PROXY_PROTOCOL_OPT_USE_PROXIED_SERVER_ADDR) {
      server_rec *proxied_server = NULL;

      /* Add "mod_proxy_protocol.proxied_server_addr" session note.  With, or
       * without, port?
       */

      if (pr_netaddr_cmp(session.c->local_addr, proxied_dst_addr) != 0 ||
          session.c->local_port != proxied_dst_port) {

        /* Notify any listeners (e.g. mod_autohost) of the proxied address, to
         * give them a chance to update/modify the configuration.
         */
        pr_event_generate("mod_proxy_protocol.proxied-server-address",
          proxied_dst_addr);

        proxied_server = pr_ipbind_get_server(proxied_dst_addr,
          proxied_dst_port);
      }

      if (proxied_server != NULL &&
          proxied_server != main_server) {
        pool *tmp_pool = NULL;
        cmd_rec *host_cmd = NULL;

        pr_log_debug(DEBUG0,
          "Changing to server '%s' (%s:%d) due to PROXY protocol",
          proxied_server->ServerName, pr_netaddr_get_ipstr(proxied_dst_addr),
          proxied_dst_port);

        pr_log_debug(DEBUG0, MOD_PROXY_PROTOCOL_VERSION
          ": UPDATED local server address/port: %s:%d (WAS %s:%d)",
          pr_netaddr_get_ipstr(pr_netaddr_get_sess_local_addr()),
          session.c->local_port, pr_netaddr_get_ipstr(proxied_dst_addr),
          proxied_dst_port);

        session.c->local_addr = proxied_dst_addr;
        session.c->local_port = proxied_dst_port;

        /* Set a session flag indicating that the main_server pointer
         * changed.
         */
        session.prev_server = main_server;
        main_server = proxied_server;

        pr_event_generate("core.session-reinit", proxied_server);

        /* Now we need to inform the modules of the changed config, to let them
         * do their checks.
         */
        tmp_pool = make_sub_pool(session.pool);
        pr_pool_tag(tmp_pool, "ProxyProtocol UseProxiedServerAddress pool");

        host_cmd = pr_cmd_alloc(tmp_pool, 2, pstrdup(tmp_pool, C_HOST),
          pstrdup(tmp_pool, pr_netaddr_get_ipstr(proxied_dst_addr)), NULL);
        pr_cmd_dispatch_phase(host_cmd, POST_CMD, 0);
        pr_cmd_dispatch_phase(host_cmd, LOG_CMD, 0);
        pr_response_clear(&resp_list);

        destroy_pool(tmp_pool);
      }
    }

    /* Note that we set the session addresses (remote and local) only after
     * possible processing of the proxied destination address.
     */
    pr_netaddr_set_sess_addrs();

    /* Find the new class for this session. */
    session.conn_class = pr_class_match_addr(session.c->remote_addr);
    if (session.conn_class != NULL) {
      pr_log_debug(DEBUG2, MOD_PROXY_PROTOCOL_VERSION
        ": session requested from proxied client in '%s' class",
        session.conn_class->cls_name);

    } else {
      pr_log_debug(DEBUG5, MOD_PROXY_PROTOCOL_VERSION
        ": session requested from proxied client in unknown class");
    }
  }

  return 0;
}

/* Module API tables
 */

static conftable proxy_protocol_conftab[] = {
  { "ProxyProtocolEngine",	set_proxyprotocolengine,	NULL },
  { "ProxyProtocolIgnore",	set_proxyprotocolignore,	NULL },
  { "ProxyProtocolOptions",	set_proxyprotocoloptions,	NULL },
  { "ProxyProtocolTimeout",	set_proxyprotocoltimeout,	NULL },
  { "ProxyProtocolVersion",	set_proxyprotocolversion,	NULL },

  { NULL }
};

module proxy_protocol_module = {
  /* Always NULL */
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "proxy_protocol",

  /* Module configuration handler table */
  proxy_protocol_conftab,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  NULL,

  /* Module initialization */
  NULL,

  /* Session initialization */
  proxy_protocol_sess_init,

  /* Module version */
  MOD_PROXY_PROTOCOL_VERSION
};
