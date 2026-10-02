/* Разбор ServerHelloDone в TLS 1.2: сообщения через границы записей. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int d2k_resp_scan12(const uint8_t *buf, size_t have, int *done);

static size_t rec(uint8_t *o, uint8_t type, const uint8_t *p, size_t n)
{
    o[0] = type; o[1] = 3; o[2] = 3; o[3] = (uint8_t)(n >> 8); o[4] = (uint8_t)n;
    memcpy(o + 5, p, n);
    return 5 + n;
}

static uint8_t stream[40000], out[50000];

int main(void)
{
    size_t n = 0, o = 0, certlen = 20000;
    int done, fails = 0, r;

    /* ServerHello(4+10) | Certificate 20000 | ServerHelloDone */
    stream[n++] = 2; stream[n++] = 0; stream[n++] = 0; stream[n++] = 10; n += 10;
    stream[n++] = 11; stream[n++] = 0; stream[n++] = (uint8_t)(certlen >> 8);
    stream[n++] = (uint8_t)certlen;
    memset(stream + n, 0xab, certlen); n += certlen;
    stream[n++] = 14; stream[n++] = 0; stream[n++] = 0; stream[n++] = 0;
    o += rec(out + o, 22, stream, 16384);
    o += rec(out + o, 22, stream + 16384, n - 16384);
    r = d2k_resp_scan12(out, o, &done);
    if (r != 1 || !done) { printf("FAIL split cert: r=%d done=%d\n", r, done); fails++; }

    /* 0e 00 00 00 внутри тела Certificate на границе записей — не конец */
    memset(stream, 0xab, sizeof(stream)); n = 0;
    stream[n++] = 11; stream[n++] = 0; stream[n++] = (uint8_t)(certlen >> 8);
    stream[n++] = (uint8_t)certlen;
    memset(stream + n, 0xab, certlen);
    stream[4 + 16380 - 4] = 0x0e; stream[4 + 16380 - 3] = 0; stream[4 + 16380 - 2] = 0; stream[4 + 16380 - 1] = 0;
    n += certlen; o = 0;
    o += rec(out + o, 22, stream, 16384);
    o += rec(out + o, 22, stream + 16384, n - 16384);
    r = d2k_resp_scan12(out, o, &done);
    if (r != 0 || done) { printf("FAIL embedded 0e: r=%d done=%d\n", r, done); fails++; }

    /* заголовок сообщения разорван между записями: 0e | 00 00 00 */
    o = 0;
    o += rec(out + o, 22, (const uint8_t *)"\x0e", 1);
    o += rec(out + o, 22, (const uint8_t *)"\x00\x00\x00", 3);
    r = d2k_resp_scan12(out, o, &done);
    if (r != 1 || !done) { printf("FAIL split header: r=%d done=%d\n", r, done); fails++; }

    if (fails) return 1;
    printf("test_response: ok\n");
    return 0;
}
