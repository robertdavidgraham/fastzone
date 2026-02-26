/*
    Quick benchmarks
 */
#include "zone-scan.h"
#include "zone-atom-name.h"
#include "zone-parse.h"
#include "zone-atom.h"
#include "zone.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>


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
        printf("[scan] %7s qtest failure\n", simd_get_name());
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
    printf("[scan] %7s %5.3f-GB/s\n", simd_get_name(), gbps);
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
        size_t consumed = zone_parse_name0(dns_test_names[i], 0, 40, &out);
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
        size_t consumed = zone_atom_name5(dns_test_names[i], 0, 40, &out);
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
        printf("[name4] %7s qtest failure\n", simd_get_name());
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
    printf("[name4] %7s %5.3f-GB/s\n", simd_get_name(), gbps);
    
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
        printf("[name5] %7s qtest failure\n", simd_get_name());
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
    printf("[name5] %7s %5.3f-GB/s\n", simd_get_name(), gbps);
    
    return 0;
}
