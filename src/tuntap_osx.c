/**
 * (C) 2007-22 - ntop.org and contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */


#include "n2n.h"


#ifdef __APPLE__


#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/bpf.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/ndrv.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/types.h>
#include <unistd.h>


/*
 * macOS TAP backend based on the in-kernel feth (fake ethernet) clone driver,
 * which needs no third party kernel extension.
 *
 * Every tuntap_open() creates a fresh pair of feth interfaces:
 *
 *   fethN (primary)  carries the IP address, netmask and MAC address of the
 *                    community member and is the interface the host stack
 *                    sends to and receives from
 *   fethM (peer)     is unconfigured and only used by this process for the
 *                    n2n side of the data path
 *
 * Host to n2n:  frames transmitted on fethN come out of fethM, where a BPF
 *               capture socket (device->fd, the descriptor select() waits on)
 *               receives them.
 * n2n to host:  frames are injected into fethM through an AF_NDRV socket
 *               (device->write_fd) and arrive on the host stack via fethN.
 *               BPF cannot be used for that direction: its injected frames are
 *               limited to 2048 bytes, which is not enough for our MTU range.
 *
 * Root privileges are required for interface creation and configuration, for
 * opening /dev/bpf* and for the feth pairing ioctl, so the whole process has to
 * keep them for its lifetime.
 */

#define N2N_OSX_FETH_DEV_NAME      "feth"
#define N2N_OSX_BPF_DEV_PREFIX     "/dev/bpf"
#define N2N_OSX_BPF_DEV_MAX        256
#define N2N_OSX_BPF_BUFFER_REQ     131072
/* upper bound of kernel batches drained by a single tuntap_read() call, only
 * there to never spin forever if the driver keeps handing out unusable data */
#define N2N_OSX_BPF_READ_TRIES     64

/* feth driver private command, see bsd/net/if_fake_var.h: IF_FAKE_S_CMD_SET_PEER */
#define N2N_OSX_FETH_CMD_SET_PEER  1

/* struct if_fake_request from bsd/net/if_fake_var.h:
 *     uint64_t iffr_reserved[4];
 *     union { char iffru_buf[128]; ... } iffr_u;
 * The kernel rejects non-zero reserved words, so the whole request is zeroed
 * and only the peer name is filled in. */
#define N2N_OSX_FETH_PEER_OFFSET   32
#define N2N_OSX_FETH_PEER_UNION_LEN 128

typedef struct n2n_osx_feth_request {
    uint64_t reserved[4];
    char     buf[N2N_OSX_FETH_PEER_UNION_LEN];
} n2n_osx_feth_request_t;

_Static_assert(sizeof(n2n_osx_feth_request_t) == N2N_OSX_FETH_PEER_OFFSET + N2N_OSX_FETH_PEER_UNION_LEN,
               "feth request size must match struct if_fake_request");
_Static_assert(offsetof(n2n_osx_feth_request_t, buf) == N2N_OSX_FETH_PEER_OFFSET,
               "feth peer name must live in the if_fake_request union");

/* The kernel reports bh_hdrlen in every record and it may be smaller than
 * sizeof(struct bpf_hdr) because the header length depends on the alignment of
 * the following payload. This is the shortest prefix we have to be able to read
 * to trust a record. */
#define N2N_OSX_BPF_HDR_MIN  (offsetof(struct bpf_hdr, bh_hdrlen) + sizeof(((struct bpf_hdr *)0)->bh_hdrlen))


static int fd_cloexec (int fd) {

    int flags;

    if((flags = fcntl(fd, F_GETFD)) < 0)
        return -1;

    return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}


static int if_name_valid (const char *name) {

    size_t len;

    if(!name)
        return 0;

    len = strlen(name);

    return (len > 0) && (len < IFNAMSIZ);
}


static void ifreq_name (struct ifreq *ifr, const char *name) {

    memset(ifr, 0, sizeof(*ifr));
    strncpy(ifr->ifr_name, name, IFNAMSIZ - 1);
}


static int mac_str_valid (const char *s) {

    size_t i;

    if(!s || (strlen(s) != 17))
        return 0;

    for(i = 0; i < 17; i++) {
        if((i % 3) == 2) {
            if(s[i] != ':')
                return 0;
        } else if(!isxdigit((unsigned char)s[i])) {
            return 0;
        }
    }

    return 1;
}


/* The address is only written to the interface if n2n really owns it, i.e. for
 * statically configured and for supernode assigned addresses. In DHCP mode the
 * address is managed by a DHCP client outside of n2n and must not be touched,
 * and an all-zero address is never a valid static configuration. */
static int conf_wants_static_address (const char *address_mode, const char *device_ip) {

    if(!device_ip || (device_ip[0] == '\0'))
        return 0;

    if(address_mode && (strcmp("dhcp", address_mode) == 0))
        return 0;

    if(strcmp("0.0.0.0", device_ip) == 0)
        return 0;

    return 1;
}


static int feth_create (int ctl_fd, char *out_name, size_t out_len) {

    struct ifreq ifr;

    /* the clone driver is addressed by its own name without a unit, the kernel
     * appends the unit it picked to ifr_name; interfaces which already exist are
     * never reused or taken over */
    ifreq_name(&ifr, N2N_OSX_FETH_DEV_NAME);

    if(ioctl(ctl_fd, SIOCIFCREATE, &ifr) < 0) {
        traceEvent(TRACE_ERROR, "unable to create a %s interface [%d/%s]",
                   N2N_OSX_FETH_DEV_NAME, errno, strerror(errno));
        return -1;
    }

    if(!if_name_valid(ifr.ifr_name)) {
        traceEvent(TRACE_ERROR, "kernel reported an unusable %s interface name",
                   N2N_OSX_FETH_DEV_NAME);
        errno = EINVAL;
        return -1;
    }

    snprintf(out_name, out_len, "%s", ifr.ifr_name);

    return 0;
}


/* Returns 0 if the interface is gone, -1 with errno set if it could not be
 * destroyed. */
static int feth_destroy (int ctl_fd, const char *name) {

    struct ifreq ifr;

    if(!if_name_valid(name)) {
        errno = EINVAL;
        return -1;
    }

    ifreq_name(&ifr, name);

    if(ioctl(ctl_fd, SIOCIFDESTROY, &ifr) < 0) {
        int err = errno;

        if((err == ENXIO) || (err == ENOENT)) {
            errno = err;
            return 0;
        }

        errno = err;
        return -1;
    }

    return 0;
}


/* Pairs both freshly created interfaces with each other. The ioctl is a driver
 * specific one, it is sent to peer_name and carries the name of the interface
 * it shall be connected with. */
static int feth_set_peer (int ctl_fd, const char *peer_name, const char *other_name) {

    struct ifdrv ifd;
    n2n_osx_feth_request_t req;

    if(!if_name_valid(peer_name) || !if_name_valid(other_name)) {
        errno = EINVAL;
        return -1;
    }

    memset(&req, 0, sizeof(req));
    snprintf(req.buf, sizeof(req.buf), "%s", other_name);

    memset(&ifd, 0, sizeof(ifd));
    strncpy(ifd.ifd_name, peer_name, IFNAMSIZ - 1);
    ifd.ifd_cmd = N2N_OSX_FETH_CMD_SET_PEER;
    ifd.ifd_len = sizeof(req);
    ifd.ifd_data = &req;

    if(ioctl(ctl_fd, SIOCSDRVSPEC, &ifd) < 0) {
        traceEvent(TRACE_ERROR, "unable to pair %s with %s [%d/%s]",
                   peer_name, other_name, errno, strerror(errno));
        return -1;
    }

    return 0;
}


static int if_set_lladdr (int ctl_fd, const char *name, const n2n_mac_t mac) {

    struct ifreq ifr;

    ifreq_name(&ifr, name);
    ifr.ifr_addr.sa_len = N2N_MAC_SIZE;
    ifr.ifr_addr.sa_family = AF_LINK;
    memcpy(ifr.ifr_addr.sa_data, mac, N2N_MAC_SIZE);

    if(ioctl(ctl_fd, SIOCSIFLLADDR, &ifr) < 0) {
        traceEvent(TRACE_ERROR, "unable to set MAC address on %s [%d/%s]",
                   name, errno, strerror(errno));
        return -1;
    }

    return 0;
}


static int if_get_lladdr (const char *name, n2n_mac_t mac) {

    struct ifaddrs *ifap = NULL;
    struct ifaddrs *ifa;
    int found = -1;

    if(getifaddrs(&ifap) < 0) {
        traceEvent(TRACE_ERROR, "unable to enumerate interfaces [%d/%s]",
                   errno, strerror(errno));
        return -1;
    }

    for(ifa = ifap; ifa; ifa = ifa->ifa_next) {
        struct sockaddr_dl *sdl;

        if(!ifa->ifa_addr || (ifa->ifa_addr->sa_family != AF_LINK))
            continue;
        if(!ifa->ifa_name || (strcmp(ifa->ifa_name, name) != 0))
            continue;

        sdl = (struct sockaddr_dl *)ifa->ifa_addr;
        /* sdl_nlen counts the interface name stored in front of the address */
        if((sdl->sdl_alen == N2N_MAC_SIZE) &&
           ((size_t)(sdl->sdl_nlen + sdl->sdl_alen) <= sizeof(sdl->sdl_data))) {
            memcpy(mac, sdl->sdl_data + sdl->sdl_nlen, N2N_MAC_SIZE);
            found = 0;
        }
        break;
    }

    freeifaddrs(ifap);

    if(found < 0) {
        traceEvent(TRACE_ERROR, "unable to read back the MAC address of %s", name);
        errno = ENOENT;
    }

    return found;
}


static int if_set_mtu (int ctl_fd, const char *name, int mtu) {

    struct ifreq ifr;

    ifreq_name(&ifr, name);
    ifr.ifr_mtu = mtu;

    if(ioctl(ctl_fd, SIOCSIFMTU, &ifr) < 0) {
        traceEvent(TRACE_ERROR, "unable to set MTU %d on %s [%d/%s]",
                   mtu, name, errno, strerror(errno));
        return -1;
    }

    return 0;
}


static int if_set_up (int ctl_fd, const char *name) {

    struct ifreq ifr;

    ifreq_name(&ifr, name);

    if(ioctl(ctl_fd, SIOCGIFFLAGS, &ifr) < 0) {
        traceEvent(TRACE_ERROR, "unable to read flags of %s [%d/%s]",
                   name, errno, strerror(errno));
        return -1;
    }

    ifr.ifr_flags = (short)(ifr.ifr_flags | IFF_UP);

    if(ioctl(ctl_fd, SIOCSIFFLAGS, &ifr) < 0) {
        traceEvent(TRACE_ERROR, "unable to bring %s up [%d/%s]",
                   name, errno, strerror(errno));
        return -1;
    }

    return 0;
}


static int if_set_ipv4 (int ctl_fd, const char *name, const char *addr, const char *mask) {

    struct ifaliasreq ifra;
    struct sockaddr_in *sin;
    struct in_addr ip;
    struct in_addr netmask;

    if(inet_pton(AF_INET, addr, &ip) != 1) {
        traceEvent(TRACE_ERROR, "invalid IPv4 address '%s'", addr ? addr : "(null)");
        errno = EINVAL;
        return -1;
    }

    if(inet_pton(AF_INET, mask, &netmask) != 1) {
        traceEvent(TRACE_ERROR, "invalid netmask '%s'", mask ? mask : "(null)");
        errno = EINVAL;
        return -1;
    }

    memset(&ifra, 0, sizeof(ifra));
    strncpy(ifra.ifra_name, name, IFNAMSIZ - 1);

    sin = (struct sockaddr_in *)&ifra.ifra_addr;
    sin->sin_len = sizeof(struct sockaddr_in);
    sin->sin_family = AF_INET;
    sin->sin_addr = ip;

    sin = (struct sockaddr_in *)&ifra.ifra_mask;
    sin->sin_len = sizeof(struct sockaddr_in);
    sin->sin_family = AF_INET;
    sin->sin_addr = netmask;

    if(ioctl(ctl_fd, SIOCAIFADDR, &ifra) < 0) {
        traceEvent(TRACE_ERROR, "unable to assign %s/%s to %s [%d/%s]",
                   addr, mask, name, errno, strerror(errno));
        return -1;
    }

    return 0;
}


/* Opens the first free BPF device. EBUSY means the device is taken by another
 * process, ENOENT means the numbered device range ends here. Any other error,
 * in particular a permission problem, is reported to the caller. */
static int bpf_open (void) {

    char path[sizeof(N2N_OSX_BPF_DEV_PREFIX) + 8];
    int fd;
    int i;

    for(i = 0; i < N2N_OSX_BPF_DEV_MAX; i++) {
        snprintf(path, sizeof(path), "%s%d", N2N_OSX_BPF_DEV_PREFIX, i);

        fd = open(path, O_RDWR | O_NONBLOCK);

        if(fd >= 0) {
            if(fd_cloexec(fd) < 0) {
                traceEvent(TRACE_ERROR, "unable to make %s close-on-exec [%d/%s]",
                           path, errno, strerror(errno));
                close(fd);
                return -1;
            }
            traceEvent(TRACE_INFO, "using %s for reading", path);
            return fd;
        }

        if(errno == EBUSY)
            continue;

        if(errno == ENOENT) {
            traceEvent(TRACE_ERROR, "no %s device available, all %d units are in use or missing",
                       N2N_OSX_BPF_DEV_PREFIX, i);
            errno = ENOENT;
            return -1;
        }

        traceEvent(TRACE_ERROR, "unable to open %s [%d/%s]; is this process running as root?",
                   path, errno, strerror(errno));
        return -1;
    }

    traceEvent(TRACE_ERROR, "no free %s device found in the first %d units",
               N2N_OSX_BPF_DEV_PREFIX, N2N_OSX_BPF_DEV_MAX);
    errno = EBUSY;

    return -1;
}


/* Configures the capture socket for the peer interface and reports the buffer
 * size the kernel actually granted; that size, not our n2n packet buffer, is
 * what the read buffer has to be dimensioned for. */
static int bpf_configure (int fd, const char *name, size_t *buf_size) {

    struct ifreq ifr;
    u_int len = N2N_OSX_BPF_BUFFER_REQ;
    u_int enable = 1;
    u_int disable = 0;
    u_int dlt = 0;

    /* must happen before the socket is bound to an interface */
    if(ioctl(fd, BIOCSBLEN, &len) < 0) {
        traceEvent(TRACE_ERROR, "unable to request a %u byte BPF buffer [%d/%s]",
                   N2N_OSX_BPF_BUFFER_REQ, errno, strerror(errno));
        return -1;
    }

    ifreq_name(&ifr, name);

    if(ioctl(fd, BIOCSETIF, &ifr) < 0) {
        traceEvent(TRACE_ERROR, "unable to bind the BPF socket to %s [%d/%s]",
                   name, errno, strerror(errno));
        return -1;
    }

    if(ioctl(fd, BIOCGBLEN, &len) < 0) {
        traceEvent(TRACE_ERROR, "unable to read the BPF buffer size of %s [%d/%s]",
                   name, errno, strerror(errno));
        return -1;
    }

    if((len == 0) || (len > (1u << 22))) {
        traceEvent(TRACE_ERROR, "BPF reported an unusable buffer size of %u bytes for %s", len, name);
        errno = EINVAL;
        return -1;
    }

    /* hand frames to us one at a time instead of waiting for the buffer to fill
     * up, and do not capture the frames we inject ourselves */
    if((ioctl(fd, BIOCIMMEDIATE, &enable) < 0) ||
       (ioctl(fd, BIOCSSEESENT, &disable) < 0) ||
       (ioctl(fd, BIOCPROMISC) < 0)) {
        traceEvent(TRACE_ERROR, "unable to configure the BPF socket on %s [%d/%s]",
                   name, errno, strerror(errno));
        return -1;
    }

    if(ioctl(fd, BIOCGDLT, &dlt) < 0) {
        traceEvent(TRACE_ERROR, "unable to read the BPF link type of %s [%d/%s]",
                   name, errno, strerror(errno));
        return -1;
    }

    if(dlt != DLT_EN10MB) {
        traceEvent(TRACE_ERROR, "unexpected BPF link type %u on %s, ethernet expected",
                   dlt, name);
        errno = EINVAL;
        return -1;
    }

    *buf_size = (size_t)len;

    return 0;
}


/* Opens the AF_NDRV socket used to inject frames into the peer interface. */
static int ndrv_open (const char *name) {

    struct sockaddr_ndrv sa;
    size_t name_len;
    int fd;

    if(!if_name_valid(name)) {
        errno = EINVAL;
        return -1;
    }

    name_len = strlen(name);

    if(name_len >= sizeof(sa.snd_name)) {
        traceEvent(TRACE_ERROR, "interface name '%s' does not fit into a sockaddr_ndrv", name);
        errno = ENAMETOOLONG;
        return -1;
    }

    if((fd = socket(AF_NDRV, SOCK_RAW, 0)) < 0) {
        traceEvent(TRACE_ERROR, "unable to open an AF_NDRV socket [%d/%s]",
                   errno, strerror(errno));
        return -1;
    }

    if(fd_cloexec(fd) < 0) {
        traceEvent(TRACE_ERROR, "unable to make the AF_NDRV socket close-on-exec [%d/%s]",
                   errno, strerror(errno));
        close(fd);
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.snd_len = (unsigned char)sizeof(sa);
    sa.snd_family = AF_NDRV;
    memcpy(sa.snd_name, name, name_len); /* the zeroed remainder terminates the name */

    if(bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        traceEvent(TRACE_ERROR, "unable to bind the AF_NDRV socket to %s [%d/%s]",
                   name, errno, strerror(errno));
        close(fd);
        return -1;
    }

    if(connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        traceEvent(TRACE_ERROR, "unable to connect the AF_NDRV socket to %s [%d/%s]",
                   name, errno, strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}


/* Rounds a record size up to the next word boundary the way BPF does, while
 * refusing to wrap around. */
static int bpf_record_step (size_t hdrlen, size_t caplen, size_t *step) {

    size_t sum;

    if(caplen > (SIZE_MAX - hdrlen))
        return -1;

    sum = hdrlen + caplen;

    if(sum > (SIZE_MAX - (BPF_ALIGNMENT - 1)))
        return -1;

    *step = BPF_WORDALIGN(sum);

    return 0;
}


int tuntap_bpf_parse_frame (const unsigned char *batch,
                            size_t batch_len,
                            size_t *offset,
                            const unsigned char **frame,
                            size_t *frame_len) {

    size_t off;

    if(!batch || !offset || !frame || !frame_len)
        return -1;

    off = *offset;

    if(off > batch_len)
        return -1;

    while((batch_len - off) >= N2N_OSX_BPF_HDR_MIN) {
        const unsigned char *record = batch + off;
        uint32_t caplen;
        uint32_t datalen;
        uint16_t hdrlen;
        size_t step;
        size_t next;

        /* the records are not aligned to anything the compiler knows about */
        memcpy(&caplen, record + offsetof(struct bpf_hdr, bh_caplen), sizeof(caplen));
        memcpy(&datalen, record + offsetof(struct bpf_hdr, bh_datalen), sizeof(datalen));
        memcpy(&hdrlen, record + offsetof(struct bpf_hdr, bh_hdrlen), sizeof(hdrlen));

        /* bh_hdrlen is authoritative and can be shorter than sizeof(struct bpf_hdr) */
        if((hdrlen < N2N_OSX_BPF_HDR_MIN) || (hdrlen > (batch_len - off))) {
            traceEvent(TRACE_WARNING, "broken BPF record header at offset %u", (unsigned int)off);
            *offset = batch_len;
            return -1;
        }

        if(caplen > (batch_len - off - hdrlen)) {
            traceEvent(TRACE_WARNING, "truncated BPF record at offset %u (%u of %u bytes captured)",
                       (unsigned int)off, caplen, datalen);
            *offset = batch_len;
            return -1;
        }

        if(bpf_record_step(hdrlen, caplen, &step) < 0) {
            traceEvent(TRACE_WARNING, "broken BPF record size at offset %u", (unsigned int)off);
            *offset = batch_len;
            return -1;
        }

        /* the last record of a batch may come without its trailing padding, so
         * the next offset is allowed to end up beyond the batch */
        next = off + step;

        /* frames the capture length cut short, oversized frames and frames too
         * short to carry an ethernet header are dropped, not passed on */
        if((caplen == datalen) &&
           (caplen >= ETH_FRAMESIZE) &&
           (caplen <= N2N_PKT_BUF_SIZE)) {
            *offset = (next > batch_len) ? batch_len : next;
            *frame = record + hdrlen;
            *frame_len = (size_t)caplen;

            return 1;
        }

        traceEvent(TRACE_DEBUG, "dropping unusable BPF record (%u of %u bytes)", caplen, datalen);

        if(next >= batch_len) {
            *offset = batch_len;
            return 0;
        }

        off = next;
        *offset = next;
    }

    *offset = batch_len;

    return 0;
}


int tuntap_has_pending (struct tuntap_dev *tuntap) {

    if(!tuntap || (tuntap->fd < 0) || !tuntap->bpf_buf)
        return 0;

    return (tuntap->bpf_buf_pos < tuntap->bpf_buf_len) ? 1 : 0;
}


/* Reads and configures the two interfaces this device consists of, allocates
 * the batch buffer and opens the capture and injection sockets. On failure
 * everything that was acquired is released again. */
static int tuntap_setup (tuntap_dev *device,
                         char *device_ip, char *device_mask,
                         const n2n_mac_t mac, int mtu, int static_address) {

    int ctl_fd = -1;
    int failed_errno;

    if((ctl_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        traceEvent(TRACE_ERROR, "unable to open a control socket [%d/%s]",
                   errno, strerror(errno));
        return -1;
    }

    if(fd_cloexec(ctl_fd) < 0)
        traceEvent(TRACE_WARNING, "unable to make the control socket close-on-exec [%d/%s]",
                   errno, strerror(errno));

    if((feth_create(ctl_fd, device->dev_name, sizeof(device->dev_name)) < 0) ||
       (feth_create(ctl_fd, device->peer_name, sizeof(device->peer_name)) < 0))
        goto fail;

    if(feth_set_peer(ctl_fd, device->peer_name, device->dev_name) < 0)
        goto fail;

    /* the host facing interface carries the MAC address of this community
     * member, the peer stays unconfigured apart from MTU and up state */
    if(if_set_lladdr(ctl_fd, device->dev_name, mac) < 0)
        goto fail;

    if(if_set_mtu(ctl_fd, device->dev_name, mtu) < 0)
        goto fail;

    if(if_set_mtu(ctl_fd, device->peer_name, mtu) < 0)
        goto fail;

    if(static_address) {
        if(if_set_ipv4(ctl_fd, device->dev_name, device_ip, device_mask) < 0)
            goto fail;

        device->ip_addr = inet_addr(device_ip);
        device->device_mask = inet_addr(device_mask);
    } else {
        device->ip_addr = 0;
        device->device_mask = 0;
    }

    if(if_set_up(ctl_fd, device->dev_name) < 0)
        goto fail;

    if(if_set_up(ctl_fd, device->peer_name) < 0)
        goto fail;

    if((device->fd = bpf_open()) < 0)
        goto fail;

    {
        size_t buf_size = 0;

        if(bpf_configure(device->fd, device->peer_name, &buf_size) < 0)
            goto fail;

        if((device->bpf_buf = malloc(buf_size)) == NULL) {
            traceEvent(TRACE_ERROR, "unable to allocate a %u byte BPF batch buffer [%d/%s]",
                       (unsigned int)buf_size, errno, strerror(errno));
            goto fail;
        }

        device->bpf_buf_size = buf_size;
        device->bpf_buf_len = 0;
        device->bpf_buf_pos = 0;
    }

    if((device->write_fd = ndrv_open(device->peer_name)) < 0)
        goto fail;

    device->if_idx = if_nametoindex(device->dev_name);

    close(ctl_fd);

    return 0;

fail:
    failed_errno = errno;

    if(device->write_fd >= 0) {
        close(device->write_fd);
        device->write_fd = -1;
    }

    if(device->fd >= 0) {
        close(device->fd);
        device->fd = -1;
    }

    free(device->bpf_buf);
    device->bpf_buf = NULL;
    device->bpf_buf_size = 0;
    device->bpf_buf_len = 0;
    device->bpf_buf_pos = 0;

    {
        /* destroy what was created, in the reverse order of creation */
        int err;

        if(device->peer_name[0] != '\0') {
            if(feth_destroy(ctl_fd, device->peer_name) < 0) {
                err = errno;
                traceEvent(TRACE_ERROR, "unable to destroy feth interface %s [%d/%s]; "
                           "destroy it manually with 'ifconfig %s destroy'",
                           device->peer_name, err, strerror(err), device->peer_name);
            }
            device->peer_name[0] = '\0';
        }

        if(device->dev_name[0] != '\0') {
            if(feth_destroy(ctl_fd, device->dev_name) < 0) {
                err = errno;
                traceEvent(TRACE_ERROR, "unable to destroy feth interface %s [%d/%s]; "
                           "destroy it manually with 'ifconfig %s destroy'",
                           device->dev_name, err, strerror(err), device->dev_name);
            }
            device->dev_name[0] = '\0';
        }
    }

    close(ctl_fd);

    errno = failed_errno;

    return -1;
}


/** @brief  Create and configure the TAP device for packet read/write.
 *
 *  This routine creates a pair of feth interfaces and configures the one that
 *  is visible to the host stack.
 *
 *  @param device      - [inout] a device info holder object
 *  @param dev         - user-defined name for the new iface; not used on macOS,
 *                       the kernel assigns the feth unit
 *  @param address_mode - "static", "dhcp" or empty for supernode assignment
 *  @param device_ip   - address of iface
 *  @param device_mask - netmask for device_ip
 *  @param device_mac  - MAC address of iface, random if not given
 *  @param mtu         - MTU for iface
 *
 *  @return - negative value on error
 *          - non-negative file-descriptor on success
 */
int tuntap_open (tuntap_dev *device,
                 char *dev,
                 const char *address_mode,
                 char *device_ip,
                 char *device_mask,
                 const char *device_mac,
                 int mtu,
                 int ignored) {

    n2n_mac_t mac;
    macstr_t mac_buf;
    int static_address;

    (void)ignored;

    if(!device || !device_ip || !device_mask) {
        traceEvent(TRACE_ERROR, "tuntap_open called with incomplete device configuration");
        errno = EINVAL;
        return -1;
    }

    device->fd = -1;
    device->write_fd = -1;
    device->if_idx = 0;
    device->ip_addr = 0;
    device->device_mask = 0;
    device->mtu = 0;
    device->dev_name[0] = '\0';
    device->peer_name[0] = '\0';
    device->bpf_buf = NULL;
    device->bpf_buf_size = 0;
    device->bpf_buf_len = 0;
    device->bpf_buf_pos = 0;

    if((mtu <= 0) || (mtu > (N2N_PKT_BUF_SIZE - ETH_FRAMESIZE))) {
        traceEvent(TRACE_ERROR, "unsupported MTU %d: the macOS feth backend handles at most %d bytes "
                   "(n2n packet buffer of %d bytes minus the %d byte ethernet header)",
                   mtu, N2N_PKT_BUF_SIZE - ETH_FRAMESIZE, N2N_PKT_BUF_SIZE, ETH_FRAMESIZE);
        errno = EINVAL;
        return -1;
    }

    if(device_mac && (device_mac[0] != '\0')) {
        if(!mac_str_valid(device_mac) || (str2mac(mac, device_mac) != 0)) {
            traceEvent(TRACE_ERROR, "invalid MAC address '%s', expected the form XX:XX:XX:XX:XX:XX", device_mac);
            errno = EINVAL;
            return -1;
        }
    } else {
        /* the default feth MAC is derived from the unit number and is therefore
         * not unique across hosts; use a random locally administered unicast one */
        memrnd(mac, N2N_MAC_SIZE);
        mac[0] &= ~0x01;
        mac[0] |= 0x02;
    }

    static_address = conf_wants_static_address(address_mode, device_ip);

    if(static_address) {
        struct in_addr probe;

        if(inet_pton(AF_INET, device_ip, &probe) != 1) {
            traceEvent(TRACE_ERROR, "invalid IPv4 address '%s'", device_ip);
            errno = EINVAL;
            return -1;
        }

        if(inet_pton(AF_INET, device_mask, &probe) != 1) {
            traceEvent(TRACE_ERROR, "invalid netmask '%s'", device_mask);
            errno = EINVAL;
            return -1;
        }
    }

    if(geteuid() != 0) {
        traceEvent(TRACE_ERROR, "the macOS feth backend requires root privileges: creating, configuring and "
                   "destroying feth interfaces, pairing them, opening a BPF device and the feth ioctl are all "
                   "restricted to root");
        errno = EPERM;
        return -1;
    }

    if(dev && (dev[0] != '\0'))
        traceEvent(TRACE_INFO, "macOS feth backend ignores the requested interface name '%s', "
                   "the kernel assigns the feth unit instead", dev);

    if(tuntap_setup(device, device_ip, device_mask, mac, mtu, static_address) < 0)
        return -1;

    /* the capture descriptor is the one select() waits on, so it has to fit
     * into the descriptor set; refuse instead of silently never reading */
    if(device->fd >= FD_SETSIZE) {
        traceEvent(TRACE_ERROR, "BPF descriptor %d does not fit into select()'s limit of %d descriptors",
                   device->fd, FD_SETSIZE);
        tuntap_close(device);
        errno = EMFILE;
        return -1;
    }

    if(if_get_lladdr(device->dev_name, device->mac_addr) < 0) {
        int err = errno;

        tuntap_close(device);
        errno = err;
        return -1;
    }

    device->mtu = (uint16_t)mtu;

    if(static_address)
        traceEvent(TRACE_NORMAL, "interface %s up and running (%s/%s), peer %s, MTU %d, MAC %s",
                   device->dev_name, device_ip, device_mask, device->peer_name, mtu,
                   macaddr_str(mac_buf, device->mac_addr));
    else
        traceEvent(TRACE_NORMAL, "interface %s up and running, peer %s, MTU %d, MAC %s",
                   device->dev_name, device->peer_name, mtu,
                   macaddr_str(mac_buf, device->mac_addr));

    return device->fd;
}


int tuntap_read (struct tuntap_dev *tuntap, unsigned char *buf, int len) {

    int tries;

    if(!tuntap || !buf || (tuntap->fd < 0) || !tuntap->bpf_buf) {
        errno = EBADF;
        return -1;
    }

    if(len <= 0) {
        errno = EINVAL;
        return -1;
    }

    for(tries = 0; tries < N2N_OSX_BPF_READ_TRIES; tries++) {
        const unsigned char *frame = NULL;
        size_t frame_len = 0;
        int rc;

        rc = tuntap_bpf_parse_frame(tuntap->bpf_buf, tuntap->bpf_buf_len,
                                    &tuntap->bpf_buf_pos, &frame, &frame_len);

        if(rc < 0) {
            /* the batch cannot be resynchronised, drop the rest of it */
            tuntap->bpf_buf_len = 0;
            tuntap->bpf_buf_pos = 0;
            errno = EAGAIN;
            return -1;
        }

        if(rc == 0) {
            ssize_t got;

            tuntap->bpf_buf_len = 0;
            tuntap->bpf_buf_pos = 0;

            got = read(tuntap->fd, tuntap->bpf_buf, tuntap->bpf_buf_size);

            if(got < 0) {
                if(errno == EINTR)
                    continue;
                return -1;
            }

            if(got == 0) {
                /* spurious wakeup without any data, not an error */
                errno = EAGAIN;
                return -1;
            }

            tuntap->bpf_buf_len = (size_t)got;
            tuntap->bpf_buf_pos = 0;
            continue;
        }

        if(frame_len > (size_t)len) {
            traceEvent(TRACE_WARNING, "dropping a %u byte frame, the packet buffer holds %d bytes",
                       (unsigned int)frame_len, len);
            continue;
        }

        memcpy(buf, frame, frame_len);

        return (int)frame_len;
    }

    errno = EAGAIN;

    return -1;
}


int tuntap_write (struct tuntap_dev *tuntap, unsigned char *buf, int len) {

    if(!tuntap || (tuntap->write_fd < 0) || (len <= 0)) {
        errno = EBADF;
        return -1;
    }

    /* the AF_NDRV socket submits the complete ethernet frame to the peer
     * interface, from where it reaches the host stack through the primary one */
    return (int)write(tuntap->write_fd, buf, len);
}


void tuntap_close (struct tuntap_dev *tuntap) {

    int ctl_fd;

    if(!tuntap)
        return;

    if(tuntap->write_fd >= 0) {
        close(tuntap->write_fd);
        tuntap->write_fd = -1;
    }

    if(tuntap->fd >= 0) {
        close(tuntap->fd);
        tuntap->fd = -1;
    }

    free(tuntap->bpf_buf);
    tuntap->bpf_buf = NULL;
    tuntap->bpf_buf_size = 0;
    tuntap->bpf_buf_len = 0;
    tuntap->bpf_buf_pos = 0;
    tuntap->if_idx = 0;

    if((tuntap->dev_name[0] == '\0') && (tuntap->peer_name[0] == '\0'))
        return;

    if((ctl_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        traceEvent(TRACE_ERROR, "unable to open a control socket to destroy feth interfaces %s/%s [%d/%s]; "
                   "destroy them manually with 'ifconfig <name> destroy'",
                   tuntap->dev_name, tuntap->peer_name, errno, strerror(errno));
        tuntap->dev_name[0] = '\0';
        tuntap->peer_name[0] = '\0';
        return;
    }

    if(tuntap->dev_name[0] != '\0') {
        if(feth_destroy(ctl_fd, tuntap->dev_name) < 0)
            traceEvent(TRACE_ERROR, "unable to destroy feth interface %s [%d/%s]; "
                       "destroy it manually with 'ifconfig %s destroy'",
                       tuntap->dev_name, errno, strerror(errno), tuntap->dev_name);
        tuntap->dev_name[0] = '\0';
    }

    if(tuntap->peer_name[0] != '\0') {
        if(feth_destroy(ctl_fd, tuntap->peer_name) < 0)
            traceEvent(TRACE_ERROR, "unable to destroy feth interface %s [%d/%s]; "
                       "destroy it manually with 'ifconfig %s destroy'",
                       tuntap->peer_name, errno, strerror(errno), tuntap->peer_name);
        tuntap->peer_name[0] = '\0';
    }

    close(ctl_fd);
}


// fill out the ip_addr value from the interface, called to pick up dynamic address changes
void tuntap_get_address (struct tuntap_dev *tuntap) {

    struct ifreq ifr;
    int fd;

    if(!tuntap || (tuntap->dev_name[0] == '\0'))
        return;

    if((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        traceEvent(TRACE_ERROR, "unable to open a control socket [%d/%s]",
                   errno, strerror(errno));
        return;
    }

    ifreq_name(&ifr, tuntap->dev_name);

    if(ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
        tuntap->ip_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

        ifreq_name(&ifr, tuntap->dev_name);

        if(ioctl(fd, SIOCGIFNETMASK, &ifr) == 0)
            tuntap->device_mask = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
    } else if(errno == EADDRNOTAVAIL) {
        /* reflects the real state of the interface instead of keeping a stale
         * address around */
        traceEvent(TRACE_INFO, "interface %s currently has no IPv4 address", tuntap->dev_name);
        tuntap->ip_addr = 0;
    } else {
        traceEvent(TRACE_WARNING, "unable to read the IPv4 address of %s [%d/%s]",
                   tuntap->dev_name, errno, strerror(errno));
    }

    close(fd);
}


#endif /* __APPLE__ */
