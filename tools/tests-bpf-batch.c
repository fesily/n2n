/*
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>
 *
 */


#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "n2n.h"


#ifndef __APPLE__

int main (int argc, char * argv[]) {
    (void)argc;
    (void)argv;

    printf("BPF batch parsing is part of the macOS feth backend\n");

    return 0;
}

#else /* __APPLE__ */

#include <net/bpf.h>

/* shortest prefix of a capture record the backend is willing to read: the SDK
 * header carries bh_hdrlen and the value reported by the kernel may differ from
 * sizeof(struct bpf_hdr) */
#define HDR_MIN  (offsetof(struct bpf_hdr, bh_hdrlen) + sizeof(((struct bpf_hdr *)0)->bh_hdrlen))
#define PAYLOAD  0xAA

static uint8_t batch[8192];


/* appends one capture record, returns the offset behind it */
static size_t add_record (size_t off, size_t hdrlen, uint32_t caplen, uint32_t datalen, int pad) {

    uint16_t h = (uint16_t)hdrlen;

    memcpy(batch + off + offsetof(struct bpf_hdr, bh_caplen), &caplen, sizeof(caplen));
    memcpy(batch + off + offsetof(struct bpf_hdr, bh_datalen), &datalen, sizeof(datalen));
    memcpy(batch + off + offsetof(struct bpf_hdr, bh_hdrlen), &h, sizeof(h));

    memset(batch + off + hdrlen, PAYLOAD, caplen);

    if(pad)
        return off + BPF_WORDALIGN(hdrlen + caplen);

    return off + hdrlen + caplen;
}


/* parses the next frame of the batch and documents the outcome; the payload
 * check catches a frame taken from the wrong offset in the record */
static void next_frame (const char *name, size_t batch_len, size_t *off) {

    const unsigned char *frame = NULL;
    size_t frame_len = 0;
    const char *payload = "-";
    int rc;

    rc = tuntap_bpf_parse_frame(batch, batch_len, off, &frame, &frame_len);

    if(rc == 1) {
        payload = "ok";

        if(!frame || (frame < batch) || (frame + frame_len > batch + batch_len))
            payload = "outside batch";
        else if((frame[0] != PAYLOAD) || (frame[frame_len - 1] != PAYLOAD))
            payload = "wrong offset";
    }

    printf("%-32s rc=%2d len=%4zu offset=%4zu payload=%s\n",
           name, rc, frame_len, *off, payload);
}


int main (int argc, char * argv[]) {
    size_t off;
    size_t len;

    (void)argc;
    (void)argv;

    /* only the parser output is compared, the warnings it emits for the broken
     * batches carry timestamps and would make the comparison unstable */
    setTraceFile(stderr);
    setTraceLevel(TRACE_ERROR);

    printf("bpf_hdr: sizeof=%2zu minimum=%2zu\n", sizeof(struct bpf_hdr), (size_t)HDR_MIN);
    printf("\n");

    /* a plain frame in a padded batch */
    memset(batch, 0, sizeof(batch));
    len = add_record(0, HDR_MIN, 64, 64, 1);
    off = 0;
    next_frame("single frame", len, &off);

    /* two frames in one batch: draining has to find the second one as well,
     * even though no new kernel event happens after the first */
    memset(batch, 0, sizeof(batch));
    len = add_record(0, HDR_MIN, 64, 64, 1);
    len = add_record(len, HDR_MIN, 128, 128, 1);
    off = 0;
    next_frame("batch of two, first", len, &off);
    next_frame("batch of two, second", len, &off);
    next_frame("batch of two, drained", len, &off);

    /* the last record of a batch may come without its trailing padding */
    memset(batch, 0, sizeof(batch));
    len = add_record(0, HDR_MIN, 61, 61, 0);
    off = 0;
    next_frame("last record without padding", len, &off);

    /* the kernel reports a header length which differs from the struct size in
     * either direction, the payload follows the reported value */
    memset(batch, 0, sizeof(batch));
    len = add_record(0, HDR_MIN + 2, 61, 61, 1);
    off = 0;
    next_frame("header longer than needed", len, &off);

    /* unusable frames are dropped and the batch continues with the next record */
    memset(batch, 0, sizeof(batch));
    len = add_record(0, HDR_MIN, 10, 10, 1);
    len = add_record(len, HDR_MIN, 64, 64, 1);
    off = 0;
    next_frame("frame shorter than ethernet", len, &off);

    memset(batch, 0, sizeof(batch));
    len = add_record(0, HDR_MIN, 64, 128, 1);
    len = add_record(len, HDR_MIN, 64, 64, 1);
    off = 0;
    next_frame("frame cut by capture length", len, &off);

    memset(batch, 0, sizeof(batch));
    len = add_record(0, HDR_MIN, 0, 0, 1);
    len = add_record(len, HDR_MIN, 64, 64, 1);
    off = 0;
    next_frame("empty record", len, &off);

    memset(batch, 0, sizeof(batch));
    len = add_record(0, HDR_MIN, N2N_PKT_BUF_SIZE + 2, N2N_PKT_BUF_SIZE + 2, 1);
    off = 0;
    next_frame("oversized frame", len, &off);

    /* structurally broken batches end the batch instead of looping or reading
     * out of bounds */
    memset(batch, 0, sizeof(batch));
    len = add_record(0, HDR_MIN, 64, 64, 1);
    off = 0;
    next_frame("capture length beyond batch", len - 10, &off);

    memset(batch, 0, sizeof(batch));
    len = add_record(0, 0, 64, 64, 1);
    off = 0;
    next_frame("zero header length", len, &off);

    memset(batch, 0, sizeof(batch));
    len = add_record(0, HDR_MIN, 64, 64, 1);
    off = 0;
    next_frame("valid batch, one frame", len, &off);
    next_frame("valid batch, drained", len, &off);

    off = 0;
    next_frame("empty batch", 0, &off);

    off = 0;
    next_frame("trailing partial header", HDR_MIN - 1, &off);

    return 0;
}

#endif /* __APPLE__ */
