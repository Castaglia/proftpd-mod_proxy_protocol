/*
 * ProFTPD - mod_proxy_protocol
 * Copyright (c) 2013 TJ Saunders
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

#define MOD_PROXY_PROTOCOL_VERSION	"mod_proxy_protocol/0.0"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030504
# error "ProFTPD 1.3.5rc4 or later required"
#endif

module proxy_protocol_module;

#define PROXY_PROTOCOL_BUFSZ			128

#define PROXY_PROTOCOL_TIMEOUT_DEFAULT		3
static int proxy_protocol_timeout = PROXY_PROTOCOL_TIMEOUT_DEFAULT;

#define PROXY_PROTOCOL_VERSION_HAPROXY_V1	1
#define PROXY_PROTOCOL_VERSION_HAPROXY_V2	2
static unsigned int proxy_protocol_version = PROXY_PROTOCOL_VERSION_HAPROXY_V1;

static const char *trace_channel = "proxy_protocol";

static int poll_sock(int sockfd) {
  fd_set rfds;
  int res;
  struct timeval tv;

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
  void *ptr;
  size_t remainlen;

  if (reqlen == 0) {
    return 0;
  }

  errno = 0;
  ptr = buf;
  remainlen = reqlen;

  while (remainlen > 0) {
    int res;

    if (poll_sock(sockfd) < 0) {
      return -1;
    }

    res = read(sockfd, ptr, remainlen);
    while (res <= 0) {
      if (res < 0) {
        int xerrno = errno;

        if (xerrno == EINTR) {
          pr_signals_handle();
          continue;
        }

        pr_trace_msg(trace_channel, 16,
          "error reading from client (fd %d): %s", sockfd, strerror(xerrno));
        pr_log_debug(DEBUG5, MOD_PROXY_PROTOCOL_VERSION
          ": error reading from client (fd %d): %s", sockfd, strerror(xerrno));

        errno = xerrno;

        /* We explicitly disconnect the client here because the errors below
         * all indicate a problem with the TCP connection.
         */
        if (errno == ECONNRESET ||
            errno == ECONNABORTED ||
#ifdef ETIMEDOUT
            errno == ETIMEDOUT ||
#endif /* ETIMEDOUT */
#ifdef ENOTCONN
            errno == ENOTCONN ||
#endif /* ENOTCONN */
#ifdef ESHUTDOWN
            errno == ESHUTDOWN ||
#endif /* ESHUTDOWNN */
            errno == EPIPE) {
          xerrno = errno;

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

    if (res == remainlen) {
      break;
    }

    pr_trace_msg(trace_channel, 20, "read %lu bytes, expected %lu bytes; "
      "reading more", (unsigned long) res, (unsigned long) remainlen);
    ptr = ((char *) ptr + res);
    remainlen -= res;
  }

  return reqlen;
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

/* This function waits a PROXY protocol header at the beginning of the
 * raw data stream. The header looks like this :
 *
 *   "PROXY" <sp> PROTO <sp> SRC3 <sp> DST3 <sp> SRC4 <sp> <DST4> "\r\n"
 *
 * There must be exactly one space between each field. Fields are :
 *
 *  - PROTO: layer 4 protocol, which must be "TCP4" or "TCP6".
 *  - SRC3:  layer 3 (e.g. IP) source address in standard text form
 *  - DST3:  layer 3 (e.g. IP) destination address in standard text form
 *  - SRC4:  layer 4 (e.g. TCP port) source address in standard text form
 *  - DST4:  layer 4 (e.g. TCP port) destination address in standard text form
 */
static int read_haproxy_v1(pool *p, conn_t *conn, pr_netaddr_t **proxied_addr,
    unsigned int *proxied_port) {
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

  last = buf + buflen;

  /* Check the PROTO field: "TCP4" or "TCP6" are supported. */
  if (strncmp(ptr, "TCP4 ", 5) == 0) {
    have_tcp4 = TRUE;

#ifdef PR_USE_IPV6
  } else if (strncmp(ptr, "TCP6 ", 5) == 0) {
    if (pr_netaddr_use_ipv6()) {
      have_tcp6 = TRUE;
    }

#endif /* PR_USE_IPV6 */
  }

  if (have_tcp4 || have_tcp6) {
    pr_netaddr_t *src_addr = NULL, *dst_addr = NULL;
    char *ptr2 = NULL;
    unsigned int src_port, dst_port;
    int flags = PR_NETADDR_GET_ADDR_FL_ADDRS_ONLY;

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

    if (have_tcp4) {
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

#ifdef PR_USE_IPV6
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
    pr_netaddr_set_port(src_addr, htons(src_port));

    /* TODO: Check the destination address against our remote address.
     * If they do not match, then it suggests that the proxy is multi-homed,
     * which might be useful information.
     */

    *proxied_addr = src_addr;
    *proxied_port = src_port;

  } else if (strncmp(ptr, "UNKNOWN", 7) == 0) {
    pr_log_debug(DEBUG5, MOD_PROXY_PROTOCOL_VERSION
      ": client cannot provide proxied address: '%.100s'", buf);
    errno = ENOENT;
    return 0;

  } else {
    pr_log_debug(DEBUG5, MOD_PROXY_PROTOCOL_VERSION
      ": unknown/unsupported PROTO field");
    goto bad_proto;
  }
 
  return 1;

bad_proto:
  pr_log_debug(DEBUG0, MOD_PROXY_PROTOCOL_VERSION
    ": Bad/unsupported proxy protocol data '%.100s' from %s", buf,
    pr_netaddr_get_ipstr(conn->remote_addr));

  errno = EINVAL;
  return -1;
}

static int read_proxied_addr(pool *p, conn_t *conn,
   pr_netaddr_t **proxied_addr, unsigned int *proxied_port) {
  int res;

  switch (proxy_protocol_version) {
    case PROXY_PROTOCOL_VERSION_HAPROXY_V1:
      res = read_haproxy_v1(p, conn, proxied_addr, proxied_port);
      break;

    case PROXY_PROTOCOL_VERSION_HAPROXY_V2:
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
  int engine = 0, res = 0, timerno = -1, xerrno;
  pr_netaddr_t *proxied_addr = NULL;
  unsigned int proxied_port = 0;
  const char *remote_ip = NULL, *remote_name = NULL;
  pr_netio_t *tls_ctrl_netio = NULL;

  c = find_config(main_server->conf, CONF_PARAM, "ProxyProtocolEngine", FALSE);
  if (c != NULL) {
    engine = *((int *) c->argv[0]);
  }

  if (engine == FALSE) {
    return 0;
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

  /* If the mod_tls module is loaded, then we need to work around its
   * use of the NetIO API.  Otherwise, trying to read the proxied address
   * on the control connection will cause problems, e.g. for FTPS clients
   * using implicit TLS.
   */
  if (pr_module_exists("mod_tls.c")) {
    tls_ctrl_netio = pr_get_netio(PR_NETIO_STRM_CTRL);

    if (tls_ctrl_netio != NULL) {
      /* Unregister it; we'll put it back after reading the proxied address.
       */
      pr_unregister_netio(PR_NETIO_STRM_CTRL);
    }
  }

  res = read_proxied_addr(session.pool, session.c, &proxied_addr,
    &proxied_port);
  xerrno = errno;

  if (tls_ctrl_netio != NULL) {
    if (pr_register_netio(tls_ctrl_netio, PR_NETIO_STRM_CTRL) < 0) {
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

  if (proxied_addr != NULL) {
    remote_ip = pstrdup(session.pool,
      pr_netaddr_get_ipstr(pr_netaddr_get_sess_remote_addr()));
    remote_name = pstrdup(session.pool,
      pr_netaddr_get_sess_remote_name());

    pr_log_debug(DEBUG9, MOD_PROXY_PROTOCOL_VERSION
      ": using proxied source address: %s", pr_netaddr_get_ipstr(proxied_addr));

    session.c->remote_addr = proxied_addr;
    session.c->remote_port = proxied_port;

    /* Now perform reverse DNS lookups. */
    if (ServerUseReverseDNS) {
      int reverse_dns;

      reverse_dns = pr_netaddr_set_reverse_dns(ServerUseReverseDNS);
      session.c->remote_name = pr_netaddr_get_dnsstr(session.c->remote_addr);

      pr_netaddr_set_reverse_dns(reverse_dns);

    } else {
      session.c->remote_name = pr_netaddr_get_ipstr(session.c->remote_addr);
    }

    pr_netaddr_set_sess_addrs();

    pr_log_debug(DEBUG0, MOD_PROXY_PROTOCOL_VERSION
      ": UPDATED client remote address/name: %s/%s (WAS %s/%s)",
      pr_netaddr_get_ipstr(pr_netaddr_get_sess_remote_addr()),
      pr_netaddr_get_sess_remote_name(), remote_ip, remote_name);

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

