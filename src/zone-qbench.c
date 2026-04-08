/*
    Quick benchmarks
 */
#include "zone-fast-classify.h"
#include "zone-scan.h"
#include "zone-atom-name.h"
#include "zone-parse.h"
#include "zone-atom.h"
#include "zone.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#ifndef _WIN32
#include <sys/time.h>
#endif

#ifdef _WIN32
 // Source - https://stackoverflow.com/a/26085827
 // Posted by Michaelangel007, modified by community. See post 'Timeline' for change history
 // Retrieved 2026-03-17, License - CC BY-SA 3.0
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdint.h> // portable: uint64_t   MSVC: __int64 

// MSVC defines this in winsock2.h!?
typedef struct timeval {
    long tv_sec;
    long tv_usec;
} timeval;

static int gettimeofday(struct timeval* tp, struct timezone* tzp)
{
    // Note: some broken versions only have 8 trailing zero's, the correct epoch has 9 trailing zero's
    // This magic number is the number of 100 nanosecond intervals since January 1, 1601 (UTC)
    // until 00:00:00 January 1, 1970 
    static const uint64_t EPOCH = ((uint64_t)116444736000000000ULL);

    SYSTEMTIME  system_time;
    FILETIME    file_time;
    uint64_t    time;

    GetSystemTime(&system_time);
    SystemTimeToFileTime(&system_time, &file_time);
    time = ((uint64_t)file_time.dwLowDateTime);
    time += ((uint64_t)file_time.dwHighDateTime) << 32;

    tp->tv_sec = (long)((time - EPOCH) / 10000000L);
    tp->tv_usec = (long)(system_time.wMilliseconds * 1000);
    return 0;
}
#endif


const char *bench_data =
"acrosswestie.se.    7200    IN    NSEC    acrostat.se. NS RRSIG NSEC\n"
"acrostat.se.        86400    IN    NS    ns1.simply.com.\n"
"acrostat.se.        86400    IN    NS    ns2.simply.com.\n"
"acrostat.se.        86400    IN    NS    ns3.simply.com.\n"
"acrostat.se.        86400    IN    NS    ns4.simply.com.\n"
"acrostat.se.        3600    IN    DS    20247 13 2 3D79BC7DE76DA1ABDFE98D3C27CB9082468D9A099901ED3F76FB2E42 A8BED7CB\n"
"acrostat.se.        3600    IN    RRSIG    DS 8 2 3600 20260116184920 20260102171920 60409 se. gOtO+DiKQo0C9S5HQL1Qg73V6PXFq7JEWgjwmIcKcL+60FANr4l0CTLJ GviFGBh/gTgLALTMCpQhHPcwZMuFrM4GglKVUsBYEqU1yvgWW0pMP4Kv 0PX8XpHT8ZmpsSMd+GM393dbEVMOFfWfME1MTgYVUa5d69dK5Y/+wTqe k134ynagZZmlgITgG8dr0uWZUQZ5dgVX12Q1Px6vBvOr1GpAIEy8pSvC LjemvR7IelmUDRfzGDVqJLk7F3l3E1G7RskJfikE70GDiYS6V2sQQoUc WwTLwH6As1Cj7gJQi51V21t/iRUolfYgxMcRtLRxSO1i3dKVYw8eGDfM +UYY/A==\n"
"acrostat.se.        7200    IN    RRSIG    NSEC 8 2 7200 20260116184920 20260102171920 60409 se. fqZJWyDY6jktwuCjWxOFiM4ry7H+zFqN0XH/XOsolnZ9m91tGyJvkkhG KYkFAooD4uz3UTJqodHlwfh3EVTjorWsOooL7ILf0B47CH7sxAVHgxXb akjmqVmAKQeOsgWfYypOnQe4cJy6i9R38B9cGx7kZwXZlqroHdCq9TYf lsQT+lCdC2yti7c4DUdI3032nXSTI2h92t9motp1LQIOePFXPnl17kQK 6JvcUc5vxkCL8+12DvhCOemUOSh7GNulRDc7l4VOGJ6axn/g5uwOHq44 bcTvh8lIBPHe5FYrOZcj5UfesnFSdQummEuZYFsmjblhvULo3m1dCAji /hK3ow==\n"
"acrostat.se.        7200    IN    NSEC    acroud.se. NS DS RRSIG NSEC\n"
"acroud.se.        86400    IN    NS    erin.ns.cloudflare.com.\n"
"acroud.se.        86400    IN    NS    derek.ns.cloudflare.com.\n"
"acroud.se.        7200    IN    RRSIG    NSEC 8 2 7200 20260116184920 20260102171920 60409 se. UBYeGUGPqripBomqmV2l0ndoGcpILgdYbIOm5dQWPrqMY7HAaiOHuKzF COXcUx2NVoXs8eK18Xx+UT2ucQos3O2qG8G98ILj0JHdY8h+W072RyRX 0VYNbmv7HJtcEYjKDOW+DFR0WvuK9GitOjQEVmn1NlxCWeS9wxza4Ie2 rVf/cu+tfFtl31BJX3jJHUvlOiEo/WLO6B8djU9SQYWg3CAUDLNhj61u tDRIuilyQE9e+nL3pPMdRGQFEu2SFWyEukuiYX4FRJJregAACU0TMvBg 8pKpRZKn+m1K2TVmlOerGLTB4y2LRGyekTIJa+w6htaTR/BUq+zcIeGl 5G8yvA==\n"
"acroud.se.        7200    IN    NSEC    acrovia.se. NS RRSIG NSEC\n"
"acrovia.se.        86400    IN    NS    ns01.one.com.\n"
"acrovia.se.        86400    IN    NS    ns02.one.com.\n"
"acrovia.se.        3600    IN    DS    4000 13 2 C3F8FB234E2B71542D82EC5C54F4D6A639048143BD305EEEFBB35671 8652E258\n"
"acrovia.se.        3600    IN    RRSIG    DS 8 2 3600 20260116184920 20260102171920 60409 se. nHcxpTCvcE/gd7JQ/Jh1W//uvZeAnczE0u3NM/J+NC9uSj8jcUnfiqbi e/g7BLu+O91Ig1wvoi3z4cghG9YPb+brG1V8zc9UWy2fVKKsLaiOx529 9NKfnaJ7x4dUIiQoPDNE25GDIYxJOsBpPg6CCo7TsYhB0NJLX87cLPGM cE+a5J+sn66lp2hVFHAJuV80JwWlL+8r9ED836dFqokzp7eDYGl9JbKC U3oyYRcSKBZPcadxdqp4hx93s6bfnmzvQpvsBKo/MFMJCw8bElBoOwAd Ny5E4qPDE5dlrMDuMfDLwLcCdy+mwu7x3D3llW7Hy1OVJFyFSqjhgiym BA4Qjw==\n"
"acrovia.se.        7200    IN    RRSIG    NSEC 8 2 7200 20260116184920 20260102171920 60409 se. fm58CMem6mXqYwMKlW8anm07g6xAQVILVDQkjlnrps0fVmSK91KkpHm1 0mJVHqKhw59QbxRWzLasl4DJmP5x/8mHbmAQlZu3uNm45YfRCTA9QaXZ R3zav/YbyypXtXl/qfcTLe9a6Y21fu1IQx9GaU97+RKVaGLsm/rkYTr2 TGHMmmWlv9dwKvXyv1IROSAEXvgGWQog+uh/ooahUiTOteU7EjfWPya1 XYEZww8fjeqRAxQrR5HuXh0VHZlnzZG9MiCtMRatIFq+rrm3X0pEKTAP xqBBvmoJopIFgrcAORk4It5ebeqO3Qf9z6VnoqpOA/bEZV0oId5RpZd+ BZtR+A==\n"
"acrovia.se.        7200    IN    NSEC    acrowd.se. NS DS RRSIG NSEC\n"
"acrowd.se.        86400    IN    NS    primary.ns.hostup.se.\n"
"acrowd.se.        86400    IN    NS    secondary.ns.hostup.se.\n"
"acrowd.se.        3600    IN    DS    2371 13 2 062C88E4BF6B6B9C227B21340B4397A4C17C857FED16754C5FBEA439 71EB75DE\n"
"acrowd.se.        3600    IN    RRSIG    DS 8 2 3600 20260116184920 20260102171920 60409 se. fqYc3LB11/knMDLxaPYeO0+MBamQTZg5OSuHuGMQMGQV+xX0LfjmZdkM vGFkgzvCVtATwI5h3ibSxL0279NfcqtC/EkaByDFNZER+rRmbiuFF1os uGejsWT7qp3YC9MOm2PZiBiahlfqeXItweb6Aog+qlM+U8o46QCaX6fy bZ8PZ2YqZATx5dIex3E40fOp7XyLrJ9Ik1IbXPmZ8iemUZFLMU2sNDse l8hZAqqq7PaEzfG2spiu9l5E6KFOYgSG8+U3GK2t5WfrqJNGrk9TD6t7 EToKI2mNJPR8dA29/IbW/Av8AvA5ReFX6nAEpcowMLNDXP2WqY0lZVQZ r5W+3g==\n"
"acrowd.se.        7200    IN    RRSIG    NSEC 8 2 7200 20260116184920 20260102171920 60409 se. eqzqQuOibZbe2MREeUInJR4IPXZUtWTKTpn2aj/Y9sXgkJ6f3fiqU6UT YxQQ5y3DrYr6pHlISnWaBtjLwq3SCVMPIiPmHdNH6E9kDxJX3k1k73/R 8f50+swBxLH0Hmeeh8qqGuxWXlS/SHuKDLsykJvexCCTmiGw8WDmsZ+G uU8RXD3/IwNUGtRsnu4S+R+0YBYP24ccmuMVq2bTtHxQSXx78pc0K+tx oj90U24WkiX2/nAMV4gWii8fdgEKcUe20X01fZ2cKn55yjLHDWhXZ2ak F9Bd5O25u9MHemkrjAAo3BvGFiHUR/lebwxblp4Y5F3czxdsfYXMEOtn I0aCkg==\n"
"acrowd.se.        7200    IN    NSEC    acrowd-agency.se. NS DS RRSIG NSEC\n"
"acrowd-agency.se.    86400    IN    NS    ns01.one.com.\n"
"acrowd-agency.se.    86400    IN    NS    ns02.one.com.\n"
"acrowd-agency.se.    3600    IN    DS    53026 13 2 97A4F18F1A5506DF2545F4E8FEE3FF3AC510C864E6BAD1BF60E05489 1D62F6DF\n"
"acrowd-agency.se.    3600    IN    RRSIG    DS 8 2 3600 20260116184920 20260102171920 60409 se. IzdqfopOPW+B7kJ/a9yQQyLhHfI5WDAcRUOaubyJ/XGA+66y6wxn4ggN E6kkDsgOvfToxqW4TX7HUiebLceD2d+AAUfEQQ/H+z21aSJPzlnm8kCc TLN6oDtfCZOeDnO3uRLUjpFcVLz4ZmE2lDaH6iJkXjV/6k8vUPF6+DgG C6anSMtzEw9oh80+/cH8pNABj+T2HMxtX4yOFdVbtxMLIMxpJf+5Tns0 NK15cNHuQpKr7utbFp7gjMqwnIE1bjAJKqJDytUG7zrnqTQJhiE1+pnf WbSWcZvveeL9QTRB+QwcbyLijRyZvJ5DHrCEev1luOpiUOope08FOqMN 9HvdJg==\n"
"acrowd-agency.se.    7200    IN    RRSIG    NSEC 8 2 7200 20260116184920 20260102171920 60409 se. IIghr0BLqVfWg3bFmmT1zKZgYBb7GimYY9DC23JLexP9z9vJH51OK0xX OMKfPjeYCfSOcaxnQ4VcavdjDvyaFq+YyH9xHm1fTsDpoG+c+ffQ1Kcb bCFqHnqz1Vml8aexHqptnlKZKq1KFVUndVs1T3Tz5OJuaG938aqAXMiH gOXnQI7qjbd/3cw4uflxEbhVSs6yUq/6oKrngfjKOBQ+j1f+2fh2F5B6 ibXDp8IclVf9Lx1PZuHa14zGAeLR8BC+1y9ZS/Dhzlcsh5Elc3cbHGgr qNQTi4haLJxHt56p53J2VnVejVKfioCPRf/L1gbhvv1SpDMiszLRnqko mUGNZw==\n"
"acrowd-agency.se.    7200    IN    NSEC    acroyoga.se. NS DS RRSIG NSEC\n"
"acroyoga.se.        86400    IN    NS    ns1.dns-parking.com.\n"
"acroyoga.se.        86400    IN    NS    ns2.dns-parking.com.\n"
"acroyoga.se.        7200    IN    RRSIG    NSEC 8 2 7200 20260116184920 20260102171920 60409 se. HZAuGUgt8VTrSSGeIqEjZRrSPJ4qUz3e04isVTRaqVzCVNQdujT1MTy5 gBTfXYxsuDswLrNUBIvYsUzYoyscJNeC6rCXM+tKgaZ1oWH6y6/xi4Oo i7L8KGgkibeVX3tM78Bxe3FVpwOkNaaw+2XsPdu5dlwgu/2kZW7yQXoX VWQqDcmQQYff3Jagr5soVIlBqOAb7T8YMfoFiA33auBPZx3jbrnWvx1G ZfG/glxgg2hPczBmzLsrllLouBx4i0b4ruyia8z7WSFJNVn2zibwD2mZ z54itU6prk5RxW7PCYC4wmvXk1lnGw2Pi6K/CYRuHxW7ft64IfqrMUiH GASieg==\n"
"acroyoga.se.        7200    IN    NSEC    acroyogastockholm.se. NS RRSIG NSEC\n"
"acroyogastockholm.se.    86400    IN    NS    dns1.oderland.com.\n"
"acroyogastockholm.se.    86400    IN    NS    dns2.oderland.com.\n"
"acroyogastockholm.se.    86400    IN    NS    dns3.oderland.com.\n"
"acroyogastockholm.se.    3600    IN    DS    15908 13 2 6411E8294CB73FF76B30C389A587FB69558EBEC641079686819E67AF 88EBD4A8\n"
"acroyogastockholm.se.    3600    IN    RRSIG    DS 8 2 3600 20260116184920 20260102171920 60409 se. gAl2Zji2TMw5ScaKywwXqyCNGMfc4okMgIsJoLe0mJW5E/H1zPSl4BLC dqHYye3xAOOg9QpFartR/dOuQkUHs/gP2VnL2KfTpHYxrEK73OMsQ/s8 xRSp63RbwiF2GdZ85vVvveVWjTqkKTZFWk0fODEZA9pZGcA2Tjv2rm/W VOYLB8CXQnkPR1zGAcRl00Vts/ZZkCyryc8HBi/stDnBM8GbQ6oeG0I0 BFVjcQgJxrqJ3uJh/AGEEBCU0/TLiE8wttemJVM6OI7DSZcpPxxQ0Eaf UhC8sXriamZ/jBFwY1qinedrep33+40klbSu6nXZPd/MCpxqbfFfAgUG ISkQgw==\n"
"acroyogastockholm.se.    7200    IN    RRSIG    NSEC 8 2 7200 20260116184920 20260102171920 60409 se. h3ULLCzx3z5mt87yLbJE5hoiDOX1zQVz40yTpDRH4RHRXV7CMwgtjtQm JLap41w5FoHWQBFDzazK+EIayyeMVinRndS8RC1rXvaETYkxYcTvr7ba i3X8TwN0FDJ56nXIePtzLSjmKtw7+0k0Jh+2e88khwqbk/VeEQ1Ul0of BO/L7MWZyMcjDsfyw/TgB/Q8UFzYqLB3JEf5Pbs7NeWNQtH6/XB2gz/N tQhyaQrZ1w+dHREigYe1okVL0eAbi4Eu6CiGibvyGb7rqz5IzKi04ulw qSg+i2C1wFHx5/Ixwcpa53KCE9Jooia/GjdVRcZBves5ohJOFtdsgyhb oyOc1A==\n"
"acroyogastockholm.se.    7200    IN    NSEC    acroyogasyd.se. NS DS RRSIG NSEC\n"
"acroyogasyd.se.        86400    IN    NS    ns1.netim.net.\n"
"acroyogasyd.se.        86400    IN    NS    ns2.netim.net.\n"
"acroyogasyd.se.        86400    IN    NS    ns3.netim.net.\n"
"acroyogasyd.se.        7200    IN    RRSIG    NSEC 8 2 7200 20260116184920 20260102171920 60409 se. CHuTbfkFN9n7btvu4HElnLyWLw7b/2PFsxU6pTkYBucwy8lufdMdWnMe akhkoy/dY+oLhCa5ciMvIr1brZDo3SwF23tsslZPU5zDGQegvLeivfu/ 7othPfRCflURQmuRRwjhdJO7BfWs2fZmTYHgqoZuHaxtRr1k2BSzI/cT Y+JRqOWvvowu0At/QmryO3+ZPniQTYU7bWWKg6pOhU8G6M+WTpRwNYsr k0QoN2P/eSGG/7nCkTNlc0vgwnh4k59r8A+8B6wFocb0mRvWYrG81kT0 7VDjGvPQIwzVfICAoZ6uzMpv5roBPr4o4CNLaqRciXJInlJsmdSRQkvk OVVN2w==\n"
"acroyogasyd.se.        7200    IN    NSEC    acrs.se. NS RRSIG NSEC\n"
"acrs.se.        86400    IN    NS    ns65.domaincontrol.com.\n"
"acrs.se.        86400    IN    NS    ns66.domaincontrol.com.\n"
"acrs.se.        7200    IN    RRSIG    NSEC 8 2 7200 20260116184920 20260102171920 60409 se. HGQAH68ypygDSkrQ8tcJ4OjhpnNJF/ojBC04H60fMpjLcaWRiz5roqXH 2Ac4Ar4oC3XhvTBPitdSWmfKfdJn7U6U6t44NywHR27HbOmyYMihaH+U qbf9MF1PbK68V0DMA6vr1V+V9CMApR2Bobal25DIAvmPs9gCZlH+7ZKE Ywakin3Z//pK41i4sDV3l5RbrZTdCsE1G0Z4J7qt5fhNv3uV660m2duR bUXKwLwpqikFMrweQQ5fXB7P4nnL0sJiKLUDfUUJJhJLnzeul2ESMmWH aT1mzG0Cih/SfDezSrSbECIdCHEVbXvyalVasnkBsJNpB62jXTXDey50 rcn8cw==\n"
"acrs.se.        7200    IN    NSEC    acruise.se. NS RRSIG NSEC\n"
"acruise.se.        86400    IN    NS    ns1.brandshelter.com.\n"
"acruise.se.        86400    IN    NS    ns2.brandshelter.de.\n"
"acruise.se.        86400    IN    NS    ns3.brandshelter.info.\n"
"acruise.se.        86400    IN    NS    ns4.brandshelter.net.\n"
"acruise.se.        86400    IN    NS    ns5.brandshelter.us.\n";

int quick_scan_benchmark(int backend) {
    uint64_t total_bytes = 0;
    uint64_t total_records = 0;
    const char *filename = "benchmark";
    
    /*
     * Set the SIMD backend
     */
    zone_init(backend);
    
    /*
     * First, do a quick test to make sure the algorithms
     * are working.
     */
    int err = zone_scan_quicktest();
    if (err) {
        printf("[scan] %7s qtest failure\n", simd_current_name());
        return 1;
    }
    
    /*
     * Create a large test buffer.
     */
    char *buf;
    size_t max;
    size_t test_length = strlen(bench_data);
    static const size_t copies = 100000;
    
    buf = malloc(test_length * copies);
    for (int i=0; i<copies; i++) {
        memcpy(buf + i*test_length, bench_data, test_length);
    }
    max = test_length * copies;
    
    /*
     * Start the timer
     */
    struct timeval start, end;
    gettimeofday(&start, NULL);

    /*
     * Keep processing blocks until we reach end of input.
     */
    zone_block_t *block = zone_block_create(filename, 0, 0, 0);
    size_t offset = 0;
    while (offset < max) {
        int result;

        /* Grab the next chunk of data */
        offset = zone_block_fill(block, buf, offset, max);

        result = zone_block_scan(block);
        if (result == BLOCK_ERROR)
            goto fail;
        if (result == BLOCK_INCLUDE)
            goto fail;
        
        total_bytes += block->buf_consumed;
        total_records += block->record_count;
        
        zone_block_t *next = zone_block_next(block);
        zone_block_free(block);
        block = next;
    }
    zone_block_free(block);

    /*
     * End the timer
     */
    gettimeofday(&end, NULL);

    double elapsed = (end.tv_sec - start.tv_sec) +
                    (end.tv_usec - start.tv_usec) / 1000000.0;
    double gbps = (total_bytes / (1024.0 * 1024.0 * 1024.0)) / elapsed;
    
    //printf("\nParsed %ld records in %.4f seconds\n", (long)total_records, elapsed);
    printf("[scan] %7s %5.3f-GB/s\n", simd_current_name(), gbps);
    //printf("Throughput: \n", gbps);
    //printf("Records/sec: %.0f\n", total_records / elapsed);
    free(buf);
    return 0;
fail:
    fprintf(stderr, "[-] error during benchmark\n");
    free(buf);
    return 1;
}


static const char *dns_test_names[] = {
    "example.com.                                         ",
    "www.example.com.                                         ",
    "mail.example.com.                                         ",
    "ftp.example.com.                                         ",
    "ns1.example.com.                                         ",
    "ns2.example.com.                                         ",
    "api.example.com.                                         ",
    "dev.example.com.                                         ",
    "test.example.com.                                         ",
    "staging.example.com.                                         ",
    
    "example.net.                               ",
    "www.example.net.                                         ",
    "mail.example.net.                                         ",
    "vpn.example.net.                                         ",
    "edge.example.net.                                         ",
    "cdn.example.net.                                         ",
    "img.example.net.                                         ",
    "static.example.net.                                         ",
    "assets.example.net.                                         ",
    "blog.example.net.                                         ",
    
    "example.org.                                         ",
    "www.example.org.                                         ",
    "mail.example.org.                                         ",
    "docs.example.org.                                         ",
    "wiki.example.org.                                         ",
    "status.example.org.                                         ",
    "monitor.example.org.                                         ",
    "metrics.example.org.                                         ",
    "auth.example.org.                                         ",
    "login.example.org.                                         ",
    
    "a.com.                                         ",
    "b.com.                                         ",
    "c.com.                                         ",
    "x.y.z.                                         ",
    "x.y.z.example.                                         ",
    "x.y.z.example.com.                                         ",
    "one.two.three.four.example.com.                                         ",
    "deep.sub.domain.example.com.                                         ",
    "very.deep.sub.domain.example.com.                                         ",
    "extremely.deep.sub.domain.example.com.                                         ",
    
    "srv-01.example.com.                                         ",
    "srv-02.example.com.                                         ",
    "srv-03.example.com.                                         ",
    "db-01.example.com.                                         ",
    "db-02.example.com.                                         ",
    "cache-01.example.com.                                         ",
    "cache-02.example.com.                                         ",
    "redis-01.example.com.                                         ",
    "mq-01.example.com.                                         ",
    "queue-01.example.com.                                         ",
    
    "host123.example.com.                                         ",
    "node9.cluster.example.com.                                         ",
    "node10.cluster.example.com.                                         ",
    "node11.cluster.example.com.                                         ",
    "node12.cluster.example.com.                                         ",
    "rack1.row2.dc3.example.com.                                         ",
    "rack2.row4.dc1.example.com.                                         ",
    "edge1.lax.us.example.com.                                         ",
    "edge2.jfk.us.example.com.                                         ",
    "edge3.lon.uk.example.com.                                         ",
    
    "_internal.example.com.                                         ",
    "_service._tcp.example.com.                                         ",
    "_service._udp.example.com.                                         ",
    "_backup._tcp.example.com.                                         ",
    "_metrics._tcp.example.com.                                         ",
    "_health._udp.example.com.                                         ",
    "_logs._tcp.example.com.                                         ",
    "_alerts._udp.example.com.                                         ",
    "_sync._tcp.example.com.                                         ",
    "_replica._tcp.example.com.                                         ",
    "www ",
    "WWW ",
    "mail ",
    "mail2 ",
    "smtp ",
    "imap ",
    "ns ",
    "ns1 ",
    "ns2 ",
    "ftp ",
    "api ",
    "api.internal ",
    "db01 ",
    "db02 ",
    "cache01 ",
    "edge-gw ",
    "edge-gw01 ",
    "_sip ",
    "_sip._tcp ",
    "_sip._udp ",
    "_xmpp._tcp ",
    "_http._tcp ",
    "_https._tcp ",
    "_dmarc ",
    "_spf ",
    "selector1._domainkey ",
    "selector2._domainkey ",
    "corp.example.com. ",
    "www.example.com. ",
    "mail.example.com. ",
    "ns1.example.com. ",
    "ns2.example.com. ",
    "api.v2.example.com. ",
    "cdn.edge.example.net. ",
    "gw01.prod.us-west.example.org. ",
    "router-7.dc3.example.co. ",
    "mx1.mail.example.co.uk. ",
    "mx2.mail.example.co.uk. ",
    "xn--bcher-kva.example. ",      /* bücher */
    "xn--caf-dma.example. ",        /* café */
    "test\\032name.example. ",      /* escaped space */
    "weird\\046name.example. ",     /* escaped '&' */
    "star\\052name.example. ",      /* escaped '*' */
    "dash-name.example. ",
    "multi.level.sub.example. ",
    "root.example. ",
    0
};

#if 0
static size_t name1_quickperf(void) {
    int i;
    size_t total = 0;

    for (i=0; dns_test_names[i]; i++) {
        dns_name_t addr;
        size_t consumed = zone_atom_name1(dns_test_names[i], 0, 40, &addr);
        total += consumed;
    }
    
    return total;
}

static size_t name2_quickperf(void) {
    int i;
    size_t total = 0;

    for (i=0; dns_test_names[i]; i++) {
        dns_name_t addr;
        size_t consumed = zone_atom_name2(dns_test_names[i], 0, 40, &addr);
        total += consumed;
    }
    
    return total;
}
static size_t name3_quickperf(void) {
    int i;
    size_t total = 0;
    uint8_t out[256];
    size_t out_len;
    int is_err;
    int is_fqdn;
    
    for (i=0; dns_test_names[i]; i++) {
        size_t consumed = zone_atom_name3(dns_test_names[i], 0, 40, out, &out_len, &is_err, &is_fqdn);
        total += consumed;
    }
    
    return total;
}
#endif

static size_t name4_quickperf(void) {
    int i;
    size_t total = 0;
    struct wire_record_t out = {0};
    uint8_t buf[256 + 1024];
    out.wire.buf = buf;
    out.wire.max = 256;
    
    
    for (i=0; dns_test_names[i]; i++) {
        out.wire.len = 0;
        size_t consumed = zone_parse_ownername(dns_test_names[i], 0, 40, &out);
        total += consumed;
    }
    
    return total;
}

static size_t name5_quickperf(void) {
    int i;
    size_t total = 0;
    uint8_t buf[256 + 1024];
    struct wire_record_t out = {0};
    out.wire.buf = buf;
    out.wire.max = 256;
    
    for (i=0; dns_test_names[i]; i++) {
        out.wire.len = 0;
        size_t consumed = zone_atom_name_slow(dns_test_names[i], 0, 40, &out);
        total += consumed;
    }
    
    return total;
}


int quick_parse_name4_benchmark(int backend) {
    int err = 0;
    
    /*
     * Set the SIMD backend
     */
    zone_init(backend);
    
    /*
     * First, do a quick test to make sure the algorithms
     * are working.
     */
    err = zone_atom_name4_quicktest();
    if (err) {
        printf("[name4] %7s qtest failure\n", simd_current_name());
        return 1;
    }

    size_t repeat = 100000;
    size_t bytes = 0;
    
    
    struct timeval start, end;
    gettimeofday(&start, NULL);
    for (size_t i=0; i<repeat; i++) {
        bytes += name4_quickperf();
    }
    gettimeofday(&end, NULL);
    
    double elapsed = (end.tv_sec - start.tv_sec) +
                    (end.tv_usec - start.tv_usec) / 1000000.0;
    double gbps = (bytes / (1024.0 * 1024.0 * 1024.0)) / elapsed;
   
    //printf("Throughput: %.2f GB/s\n", gbps);
    printf("%s  %8s  %5.2f-GB/s\n", "name4", simd_name(backend), gbps);
    
    return 0;
}

int quick_parse_name5_benchmark(int backend) {
    int err = 0;
    
    /*
     * Set the SIMD backend
     */
    zone_init(backend);
    
    /*
     * First, do a quick test to make sure the algorithms
     * are working.
     */
    err = zone_atom_name5_quicktest();
    if (err) {
        printf("[name5] %7s qtest failure\n", simd_current_name());
        return 1;
    }

    size_t repeat = 100000;
    size_t bytes = 0;
    
    
    struct timeval start, end;
    gettimeofday(&start, NULL);
    for (size_t i=0; i<repeat; i++) {
        bytes += name5_quickperf();
    }
    gettimeofday(&end, NULL);
    
    double elapsed = (end.tv_sec - start.tv_sec) +
                    (end.tv_usec - start.tv_usec) / 1000000.0;
    double gbps = (bytes / (1024.0 * 1024.0 * 1024.0)) / elapsed;
   
    //printf("Throughput: %.2f GB/s\n", gbps);
    //printf("[name5] %7s %5.3f-GB/s\n", simd_current_name(), gbps);
    printf("%s  %8s  %5.2f-GB/s\n", "name4", simd_name(backend), gbps);

    return 0;
}

static const char classify_sample[] = ""
"021solutions.se.        86400   IN      NS      ns1.loopia.se.\n"
"021solutions.se.        86400   IN      NS      ns2.loopia.se.\n"
"021solutions.se.        3600    IN      DS      12412 8 2 65E0EF1072BF15679BE209C92619925956182A46D4BB4154F2A21C77 CE9DF9A8\n"
"021solutions.se.        3600    IN      RRSIG   DS 8 2 3600 20260116184920 20260102171920 60409 se. TgkmmdkvzbydCzq+sGrZ54EMmEsqVBUkavMlqxr2WmCPc6BzXzwF5HGu gNGjnY0b84S510G0/ObLug4KYxcQICmF+eUeQSfYNlH2BB4BOwksqhFI +2hDw76l0Cjn1BVqAX9ITeHdM1zdSuT1qVJWvED6qEoK1kxm8ckRQT1Q v34mvCTmV/lvr3wtJMlcQdy3G4yaca2I8pEggxeoYXTI/c9nbH2rt9cX u+jEmJUzzM99AKF8bPh93jX38Sp/BiV0XmcR33kjeMtGmbj6cBdoUKh9 iCxTQYpkt+iaLZRSLcYkCp7nIzTFzkZA2sgXb9No0mx6ll4TZYx4Y6c3 ZyKEAg==\n"
"021solutions.se.        7200    IN      RRSIG   NSEC 8 2 7200 20260116184920 20260102171920 60409 se. VLxn9ohkRynL2Sa4Q2UrsTJ7CGit+Unoe2F06Mu9ql6b4W1SXX4BKg7x XE88Atq4aLFbHGR71G8x1dNHB4YAA8b+Mq1zKIrUBPn79Zeeqbrax0eR KBjw35dYrZiPh2GSnzM8cJoI13JOQKRB0nRyEzjk90QNgz+ut03VI+SK ARIeKRp9iPoWBEuOf4eXAyQ5xbdKh+Kv2IvVtkJsyQMLlr38YgUaMMQu L/KjQNiMGR/vNdkIoABWvtcLXWEE585LMqWf2HVOmFiCu88RrQ8Lf4sn gB/ezyyieLbfELkoOS8hFPLBKKJK6r1J1KaOw32ujljhjDsQqDxwaZLv zvo4Jg==\n"
"021solutions.se.        7200    IN      NSEC    0224-742035.se. NS DS RRSIG NSEC\n"
"0224-742035.se.         86400   IN      NS      ns.gallerian.org.\n"
"0224-742035.se.         86400   IN      NS      ns2.gallerian.org.\n"
"0224-742035.se.         7200    IN      RRSIG   NSEC 8 2 7200 20260116184920 20260102171920 60409 se. mLISiTi/TrpyYSJwSbnA3Gh/LzP132zXVDdiIXtiZXwliMYIzvB46qf1 9gDbTVpjr4uTIBvCCiFP05MnZifkoif9aJ8wC+AQGZh8gs833RB0HD2b ToAQxXHp2svXEGB1TvYjW9tvNRTBaUN8wfiPTpElTvaMX4PKBlvnQr5F /3/r2DtwLIFtG04shTyOvm4jw/zT071ILNV8b1/nhhqNXBT2H6xktFv/ esVmAIfe8Sz03zKa9X3xvxGJXM8cQLJoZNKVHgrCDhIsDza2+IVLj4kn CzHLhq5Ok1ClZl/gW3IH2m4RavWbGzfxOnV6D5vpIZu8+5NVTQ9sWT9N Rst9fg==\n"
"0224-742035.se.         7200    IN      NSEC    023.se. NS RRSIG NSEC\n"
"023.se.                 86400   IN      NS      ns01.one.com.\n"
"023.se.                 86400   IN      NS      ns02.one.com.\n"
"023.se.                 3600    IN      DS      1513 13 2 D2721B8375444E29079B98902DBF31F8F366E4FB970DD7C8B948C350 60D8968F\n"
"023.se.                 3600    IN      RRSIG   DS 8 2 3600 20260116184920 20260102171920 60409 se. gbtCUQxxPb5C18MhFTME5VxcwCsxaBw9KShes9kCskKBpYp4WoN+wYww WDjKmBz5BE5ZBs4MJALGzVG5NoXFqh+gC/3f1LpZY4c7oY+AV6WpXYuV bOpnOZLcDGgei++e2qNy1A8rChS6L34Twu98KvXAVWMP0TEhP4uiXiJX KU+LC4SBg2qaVQA3VZVzhBs8ZgxzrE3PHQj5JzPLavIINVgiMUMkVKf0 GtAOaAH2dBk1m0rgRVPjAhaeUH7ermWZeCuudeTzNta7VWa/dfslcQ5z 8asD6HEtdgrI8JEQnL95Jmj8g9//MuFR8pfVwTrxHqfhno4hPKAnAL64 6k+zFg==\n"
"023.se.                 7200    IN      RRSIG   NSEC 8 2 7200 20260116184920 20260102171920 60409 se. gMSr81z1zvGI78TopiDJ27XZsIxR8dTnlaCBcmw/auJIYU48pLu9koY+ UqXmJ8UxxSc9/pQVdorwkgQ+IajqNnFvL7OMlWb2CFj2+Y8zm603fHQD 7VMXTe9ycauvWdTFds018nf/0ga0iIdSHXG54YWgPinfcWJkI/XfXK1a OOils00/cv8ciizHomQkxf5oQFgB139te308mFRDIwrOk4LhxD5Z5tvR lzEtGRFOSfxnZxssIE+lG2pQSdoTpE0YL37vG5GnD1p2dGL5z0e6fbtB j3tLM2wXiXnx+V0JZXGofOcTY1yC2JzlUW2hOPe3fcyDfXulivZZLd5C ApUk/g==\n";



/**
 * Utility function to give an aligned buffer
 */
static void* aligned_malloc(size_t size, size_t alignment) {
    if (alignment == 0) return NULL;
    size_t offset = alignment + sizeof(void*);
    void* p1 = malloc(size + offset);
    if (!p1) return NULL;
    void* p2 = (void*)(((uintptr_t)p1 + offset) & ~(alignment - 1));
    ((void**)p2)[-1] = p1;  // Store original pointer
    return p2;
}

static uint64_t bench_classify(int backend) {
    
    /* Select the SIMD backend, like SSE2, AVX2, NEON, SVE2, etc. */
    zone_fast_classify_init(backend);
    
    /* Allocate a buffer to test with */
    size_t max = 1024*1024;
    char *buf = aligned_malloc(max+1024, 64);
    
    /* Fill with sample data */
    static const size_t chunk_size = sizeof(classify_sample) - 1;
    for (size_t cursor=0; cursor < max; cursor += chunk_size) {
        memcpy(buf + cursor, classify_sample, chunk_size);
    }
    
    /* Create the token-tapes */
    tokentape_t *whitespace = malloc(max/64 + 2);
    tokentape_t *intoken = malloc(max/64 + 2);
    
    /* pseudo-variable to prevent optimizations */
    uint64_t total = 0;
    
    /* Count total bytes for reporting results */
    uint64_t total_bytes = 0;
    
    /*
     * START - take the high-resolution timestamp at the start
     */
    struct timeval start, end;
    gettimeofday(&start, NULL);

    
    /*
     * BENCHMARK - call the benchmarked function */
    for (unsigned n=0; n<10000; n++) {
        zone_fast_classify(buf, max, whitespace, intoken);
        total += whitespace[max/64] + intoken[max/64];
        total_bytes += max;
    }
    
    /*
     * STOP
     */
    gettimeofday(&end, NULL);
    
    /*
     * REPORT the results
     */
    double elapsed = (end.tv_sec - start.tv_sec) +
                    (end.tv_usec - start.tv_usec) / 1000000.0;
    double gbps = (total_bytes / (1024.0 * 1024.0 * 1024.0)) / elapsed;
    printf("%s  %8s  %5.2f-GB/s\n", "classify", simd_name(backend), gbps);
    
    /*
     * free up buffers
     */
    free(((void**)buf)[-1]);
    free(whitespace);
    free(intoken);
    
    return total;
}

static uint64_t
tokenize_buffer(const char *data, size_t max, tokentape_t *whitespace, tokentape_t *intoken, uint64_t *total_tokens) {
    size_t cursor = 0;
    uint64_t count_tokens = 0;
    
    while (cursor < max) {
        size_t len;
        len = classified_length(intoken, cursor);
        len += classified_length(whitespace, cursor+len);
        /*if (len == 0 && data[cursor+len] != '\n')
            printf("%.20s\n", data + cursor + len - 10);*/
        len += (len == 0);
        cursor += len;
        count_tokens++;
    }
    
    *total_tokens += count_tokens;
    return cursor;
}

static uint64_t bench_tokenize(int backend) {
    
    /* Select the SIMD backend, like SSE2, AVX2, NEON, SVE2, etc. */
    zone_fast_classify_init(backend);
    
    /* Allocate a buffer to test with */
    size_t max = 1024*1024;
    char *buf = aligned_malloc(max+1024, 64);
    
    /* Fill with sample data */
    static const size_t chunk_size = sizeof(classify_sample) - 1;
    for (size_t cursor=0; cursor < max; cursor += chunk_size) {
        memcpy(buf + cursor, classify_sample, chunk_size);
    }
    
    /* Create the token-tapes */
    tokentape_t *whitespace = malloc(max/sizeof(uint64_t) + 2);
    tokentape_t *intoken = malloc(max/sizeof(uint64_t) + 2);
    
    /* pseudo-variable to prevent optimizations */
    uint64_t total = 0;
    
    /* Count total bytes for reporting results */
    uint64_t total_bytes = 0;
    
    /*
     * Classify things
     */
    zone_fast_classify(buf, max, whitespace, intoken);
    
    /*
     * START - take the high-resolution timestamp at the start
     */
    struct timeval start, end;
    gettimeofday(&start, NULL);

    
    /*
     * BENCHMARK - call the benchmarked function */
    uint64_t total_tokens = 0;
    for (unsigned n=0; n<10000; n++) {
        total_bytes += tokenize_buffer(buf, max, whitespace, intoken, &total_tokens);
    }
    
    /*
     * STOP
     */
    gettimeofday(&end, NULL);
    
    /*
     * REPORT the results
     */
    double elapsed = (end.tv_sec - start.tv_sec) +
                    (end.tv_usec - start.tv_usec) / 1000000.0;
    double gbps = (total_bytes / (1024.0 * 1024.0 * 1024.0)) / elapsed;
    double tps = (total_tokens / (1024.0 * 1024.0 * 1024.0)) / elapsed;
    printf("%s  %8s  %5.2f-GB/s %4.2f-GT/s\n", "tokenize", simd_name(backend), gbps, tps);
    
    /*
     * free up buffers
     */
    free(((void**)buf)[-1]);
    free(whitespace);
    free(intoken);
    
    return total_bytes;
}

static uint64_t bench_lexifize(int backend) {
    
    /* Select the SIMD backend, like SSE2, AVX2, NEON, SVE2, etc. */
    zone_fast_classify_init(backend);
    
    /* Allocate a buffer to test with */
    size_t max = 1024*1024;
    char *buf = aligned_malloc(max+1024, 64);
    
    /* Fill with sample data */
    static const size_t chunk_size = sizeof(classify_sample) - 1;
    for (size_t cursor=0; cursor < max; cursor += chunk_size) {
        memcpy(buf + cursor, classify_sample, chunk_size);
    }
    
    /* Create the token-tapes */
    tokentape_t *whitespace = malloc(max/sizeof(uint64_t) + 2);
    tokentape_t *intoken = malloc(max/sizeof(uint64_t) + 2);
    
    /* pseudo-variable to prevent optimizations */
    uint64_t total = 0;
    
    /* Count total bytes for reporting results */
    uint64_t total_bytes = 0;
    
    
    /*
     * START - take the high-resolution timestamp at the start
     */
    struct timeval start, end;
    gettimeofday(&start, NULL);

    
    /*
     * BENCHMARK - call the benchmarked function */
    uint64_t total_tokens = 0;
    for (unsigned n=0; n<10000; n++) {
        intoken[5] = 11;
        zone_fast_classify(buf, max, whitespace, intoken);
        total_bytes += tokenize_buffer(buf, max, whitespace, intoken, &total_tokens);
    }
    
    /*
     * STOP
     */
    gettimeofday(&end, NULL);
    
    /*
     * REPORT the results
     */
    double elapsed = (end.tv_sec - start.tv_sec) +
                    (end.tv_usec - start.tv_usec) / 1000000.0;
    double gbps = (total_bytes / (1024.0 * 1024.0 * 1024.0)) / elapsed;
    double tps = (total_tokens / (1024.0 * 1024.0 * 1024.0)) / elapsed;
    printf("%s  %8s  %5.2f-GB/s %4.2f-GT/s\n", "tokenize", simd_name(backend), gbps, tps);
    
    /*
     * free up buffers
     */
    free(((void**)buf)[-1]);
    free(whitespace);
    free(intoken);
    
    return total_bytes;
}

/**
 * Simple deterministic random number generator.
 * LCG: x_{n+1} = (a * x_n + c) mod m, with m = 2^32 (implicit for uint32_t)
 */
static unsigned int rand_lcg(unsigned int *state) {
    const unsigned int a = 1664525U;
    const unsigned int c = 1013904223U;
    *state = a * *state + c;
    return *state;
}


/**
 * Createsa buffer with variable length integers separated by variable length spaces.
 * Numbers average 4 digits, and spaces are single but 10% double spaces.
 */
static char *build_integer_buffer(size_t max) {
    /* for the simple deterministic LCG random number generator */
    unsigned state = 12345;
    
    /* caller must free buffer */
    char *data = malloc(max + 128);
    for (size_t i=0; i<max; ) {
        unsigned digit_count = 3 + rand_lcg(&state) % 3;
        unsigned space_count = 1 + ((rand_lcg(&state) % 10) == 1);
        for (size_t d = 0; d < digit_count; d++) {
            data[i++] = '0' + (rand_lcg(&state) % 10);
        }
        for (size_t s = 0; s < space_count; s++) {
            data[i++] = ' ';
        }
    }
    memcpy(data + max, "\n x \n x \n", 9);
    return data;
}

#include "util-parseint.h"


static uint64_t
parseint1_buffer(const char *data, size_t max, tokentape_t *whitespace, tokentape_t *intoken, uint64_t *pseudo) {
    size_t cursor = 0;
    uint64_t tmp = 0;
    int err = 0;
    
    if (parse_integer_selftest()) {
        fprintf(stderr, "[-] selftewt.parse_integer1: failed\n");
        exit(1);
    }
    
    while (cursor < max) {
        size_t len;
        len = classified_length(intoken, cursor);

        tmp += parse_integer(data + cursor, len, &err);

        len += classified_length(whitespace, cursor+len);
        len += (len == 0);
        cursor += len;
    }
    
    *pseudo = tmp + err;
    return cursor;
}

static inline uint64_t
parse_integer2(const char *data, size_t length, int *err) {
    /* Accumlate errors in case of a bad length. This won't stop
     * parsing, but will indicate the result is malformed. */
    *err |= (length == 0);
    *err |= (length > 8);

    uint64_t result = 0;
    for (unsigned i=0; i<length; i++) {
        char c = data[i];
        *err |= (c < '0' || '9' < c);
        result = result * 10 + c - '0';
    }
    
    return result;
}


static uint64_t
parseint2_buffer(const char *data, size_t max, tokentape_t *whitespace, tokentape_t *intoken, uint64_t *pseudo) {
    size_t cursor = 0;
    uint64_t tmp = 0;
    int err = 0;
    while (cursor < max) {
        size_t len;
        len = classified_length(intoken, cursor);

        tmp += parse_integer2(data + cursor, len, &err);

        len += classified_length(whitespace, cursor+len);
        len += (len == 0);
        cursor += len;
    }
    
    *pseudo = tmp + err;
    return cursor;
}

static uint64_t bench_parseint(int backend, unsigned testcase) {
    
    /* Select the SIMD backend, like SSE2, AVX2, NEON, SVE2, etc. */
    zone_fast_classify_init(backend);
    
    /* Allocate a buffer to test with */
    size_t max = 1024*1024;
    char *buf = build_integer_buffer(max);
    
    /* Create the token-tapes */
    tokentape_t *whitespace = malloc(max/sizeof(uint64_t) + 2);
    tokentape_t *intoken = malloc(max/sizeof(uint64_t) + 2);

    /* Count total bytes for reporting results */
    uint64_t total_bytes = 0;
    
    /*
     * Classify things
     */
    zone_fast_classify(buf, max, whitespace, intoken);
    
    /*
     * START - take the high-resolution timestamp at the start
     */
    struct timeval start, end;
    gettimeofday(&start, NULL);

    
    /*
     * BENCHMARK - call the benchmarked function */
    uint64_t pseudo = 0;
    for (unsigned n=0; n<10000; n++) {
        uint64_t tmp = 0;
        switch (testcase) {
        case 1:
            total_bytes += parseint1_buffer(buf, max, whitespace, intoken, &tmp);
            break;
        case 2:
            total_bytes += parseint2_buffer(buf, max, whitespace, intoken, &tmp);
            break;
        }
        pseudo += tmp;
    }
    
    /*
     * STOP
     */
    gettimeofday(&end, NULL);
    
    /*
     * REPORT the results
     */
    double elapsed = (end.tv_sec - start.tv_sec) +
                    (end.tv_usec - start.tv_usec) / 1000000.0;
    double gbps = (total_bytes / (1024.0 * 1024.0 * 1024.0)) / elapsed;
    printf("parseint%u  %8s  %5.2f-GB/s\n", testcase, simd_name(backend), gbps);
    
    /*
     * free up buffers
     */
    free(buf);
    
    return total_bytes + pseudo;
}

/* ------------------------------------------------------------------------ */
void zone_quick_benchmarks(void) {
    int i;
    uint64_t pseudo = 0;

    printf("--- lex ---\n");
    pseudo += bench_tokenize(SIMD_NEON64);

    printf("--- tokenize ---\n");
    pseudo += bench_tokenize(SIMD_SCALAR2);

    printf("--- parseint branchless ---\n");
    pseudo += bench_parseint(SIMD_SCALAR2, 1);

    printf("--- parseint simple ---\n");
    pseudo += bench_parseint(SIMD_SCALAR2, 2);

    printf("--- classify ---\n");
    for (i=1; i<SIMD_MAX; i++) {
        pseudo += bench_classify(i);
    }

    printf("--- lex/tokenize ---\n");
    pseudo += bench_tokenize(SIMD_SCALAR2);

    printf("--- fast name ---\n");
    for (i=1; i<SIMD_MAX; i++) {
        pseudo += quick_parse_name4_benchmark(i);
    }

    printf("--- slow name ---\n");
    for (i=1; i<SIMD_MAX; i++) {
        pseudo += quick_parse_name5_benchmark(i);
    }

    

    printf("--- pseudo=%llu\n", pseudo);
}
