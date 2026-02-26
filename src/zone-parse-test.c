#include "zone-parse.h"
#include "zone-parse-record.h"
#include <string.h>
#include <assert.h>

/* --------------------------- quicktest --------------------------- */

/*
 * Testcases for major RR types.
 *
 * Assumption: `expected` is the wire-format **RDATA** (not the whole RR).
 * - Domain names are uncompressed DNS names (labels + root 0x00).
 * - Integers are network byte order.
 * - TXT/SPF/NAPTR "character-string" fields are length-prefixed.
 * - SVCB/HTTPS service parameters are encoded as: key(u16), len(u16), value,
 *   and are sorted by key (ascending).
 */

struct tc {
    const char *contents;       /* one zonefile line, must end with '\n' */
    const uint8_t *expected;    /* expected RDATA bytes */
    size_t expected_len;
};

/* --- helpers: common names in wire format (RDATA fragments) --- */
//static const uint8_t dn_example_com[]     = { 0x07,'e','x','a','m','p','l','e', 0x03,'c','o','m', 0x00 };
//static const uint8_t dn_www_example_com[] = { 0x03,'w','w','w', 0x07,'e','x','a','m','p','l','e', 0x03,'c','o','m', 0x00 };
//static const uint8_t dn_mail_example_com[]= { 0x04,'m','a','i','l', 0x07,'e','x','a','m','p','l','e', 0x03,'c','o','m', 0x00 };
//static const uint8_t dn_ns1_example_net[] = { 0x03,'n','s','1', 0x07,'e','x','a','m','p','l','e', 0x03,'n','e','t', 0x00 };
//static const uint8_t dn_ns2_example_net[] = { 0x03,'n','s','2', 0x07,'e','x','a','m','p','l','e', 0x03,'n','e','t', 0x00 };
//static const uint8_t dn_host_example_com[]= { 0x04,'h','o','s','t', 0x07,'e','x','a','m','p','l','e', 0x03,'c','o','m', 0x00 };
//static const uint8_t dn_sip_example_com[] = { 0x03,'s','i','p', 0x07,'e','x','a','m','p','l','e', 0x03,'c','o','m', 0x00 };
//static const uint8_t dn_sipserver_example_com[] = { 0x09,'s','i','p','s','e','r','v','e','r', 0x07,'e','x','a','m','p','l','e', 0x03,'c','o','m', 0x00 };
//static const uint8_t dn_svc_example_net[] = { 0x03,'s','v','c', 0x07,'e','x','a','m','p','l','e', 0x03,'n','e','t', 0x00 };
//static const uint8_t dn__root[]           = { 0x00 };

/* --- A --- */
static const uint8_t exp_a_192_0_2_1[] = { 0xC0,0x00,0x02,0x01 };
static const uint8_t exp_a_198_51_100_42[] = { 0xC6,0x33,0x64,0x2A };

/* --- AAAA --- */
static const uint8_t exp_aaaa_2001_db8__1[] = {
    0x20,0x01,0x0d,0xb8, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x01
};
static const uint8_t exp_aaaa_2001_db8_85a3__8a2e_0370_7334[] = {
    0x20,0x01,0x0d,0xb8, 0x85,0xa3,0x00,0x00, 0x00,0x00,0x8a,0x2e, 0x03,0x70,0x73,0x34
};

/* --- CAA: flags(1) taglen(1) tag + value --- */
static const uint8_t exp_caa_issue_letsencrypt[] = {
    0x00, 0x05, 'i','s','s','u','e',
    'l','e','t','s','e','n','c','r','y','p','t','.','o','r','g'
};
static const uint8_t exp_caa_iodef_mailto[] = {
    0x80, 0x05, 'i','o','d','e','f',
    'm','a','i','l','t','o',':','s','e','c','u','r','i','t','y','@','e','x','a','m','p','l','e','.','c','o','m'
};
static const uint8_t exp_caa_issuewild_ca[] = {
    0x00, 0x09, 'i','s','s','u','e','w','i','l','d',
    'c','a','.','e','x','a','m','p','l','e'
};

/* --- CNAME --- */
static const uint8_t exp_cname_canonical_example_net[] = {
    0x09,'c','a','n','o','n','i','c','a','l', 0x07,'e','x','a','m','p','l','e', 0x03,'n','e','t', 0x00
};
static const uint8_t exp_cname_root[] = { 0x00 };

/* --- DS: keytag(2) alg(1) digesttype(1) digest --- */
static const uint8_t exp_ds_sha256_seq00_1f[] = {
    0xEC,0x55, 0x0D, 0x02,
    /* 32 bytes digest: 00..1f */
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};
static const uint8_t exp_ds_sha1_a0_b3[] = {
    0x30,0x39, 0x08, 0x01,
    /* 20 bytes digest: a0..b3 */
    0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf,0xb0,0xb1,0xb2,0xb3
};

/* --- HTTPS / SVCB RDATA: prio(2) target-name + svcparams --- */
/* HTTPS(1, ".") + alpn("h2","h3") + port=443 + ipv4hint(192.0.2.1,198.51.100.42) */
static const uint8_t exp_https_prio1_root_alpn_port_ipv4hint[] = {
    0x00,0x01, /* priority */
    0x00,      /* target: "." */
    /* alpn key=1, len=6, value: [2]"h2"[2]"h3" */
    0x00,0x01, 0x00,0x06, 0x02,'h','2', 0x02,'h','3',
    /* port key=3, len=2, value: 443 */
    0x00,0x03, 0x00,0x02, 0x01,0xBB,
    /* ipv4hint key=4, len=8, two IPv4 addrs */
    0x00,0x04, 0x00,0x08, 0xC0,0x00,0x02,0x01, 0xC6,0x33,0x64,0x2A
};
/* HTTPS(0, "svc.example.net.") + mandatory(alpn,port) + alpn("h2") */
static const uint8_t exp_https_prio0_svc_mandatory_alpn[] = {
    0x00,0x00, /* priority */
    /* target: svc.example.net. */
    0x03,'s','v','c', 0x07,'e','x','a','m','p','l','e', 0x03,'n','e','t', 0x00,
    /* mandatory key=0, len=4, value keys: 1,3 */
    0x00,0x00, 0x00,0x04, 0x00,0x01, 0x00,0x03,
    /* alpn key=1, len=3, value: [2]"h2" */
    0x00,0x01, 0x00,0x03, 0x02,'h','2'
};
/* SVCB mirrors HTTPS encoding (different RRtype, same RDATA rules) */
static const uint8_t exp_svcb_prio1_root_port[] = {
    0x00,0x01, /* priority */
    0x00,      /* target "." */
    /* port key=3, len=2, value 8443 */
    0x00,0x03, 0x00,0x02, 0x20,0xFB
};

/* --- MX: preference(2) exchange-name --- */
static const uint8_t exp_mx_10_mail_example_com[] = {
    0x00,0x0A,
    0x04,'m','a','i','l', 0x07,'e','x','a','m','p','l','e', 0x03,'c','o','m', 0x00
};
static const uint8_t exp_mx_0_root[] = { 0x00,0x00, 0x00 };

/* --- NAPTR: order(2) pref(2) flags<cs> services<cs> regexp<cs> replacement<name> --- */
static const uint8_t exp_naptr_sip_u[] = {
    0x00,0x64, 0x00,0x32,                 /* order=100, pref=50 */
    0x01,'s',                             /* flags "s" */
    0x07,'S','I','P','+','D','2','U',     /* services */
    0x1B,'!','^','.','*','$','!','s','i','p',':','i','n','f','o','@','e','x','a','m','p','l','e','.','c','o','m','!', /* regexp */
    0x00                                  /* replacement "." */
};
static const uint8_t exp_naptr_empty_regexp_repl_sipserver[] = {
    0x00,0x0A, 0x00,0x64, /* order=10, pref=100 */
    0x01,'s',             /* flags */
    0x07,'S','I','P','+','D','2','T', /* services */
    0x00,                 /* empty regexp */
    0x09,'s','i','p','s','e','r','v','e','r', 0x07,'e','x','a','m','p','l','e', 0x03,'c','o','m', 0x00
};

/* --- NS --- */
static const uint8_t exp_ns_ns1_example_net[] = {
    0x03,'n','s','1', 0x07,'e','x','a','m','p','l','e', 0x03,'n','e','t', 0x00
};
static const uint8_t exp_ns_ns2_example_net[] = {
    0x03,'n','s','2', 0x07,'e','x','a','m','p','l','e', 0x03,'n','e','t', 0x00
};

/* --- PTR --- */
static const uint8_t exp_ptr_host_example_com[] = {
    0x04,'h','o','s','t', 0x07,'e','x','a','m','p','l','e', 0x03,'c','o','m', 0x00
};
static const uint8_t exp_ptr_root[] = { 0x00 };

/* --- SOA: mname rname serial refresh retry expire minimum --- */
static const uint8_t exp_soa_ns1_hostmaster_times[] = {
    /* mname: ns1.example.net. */
    0x03,'n','s','1', 0x07,'e','x','a','m','p','l','e', 0x03,'n','e','t', 0x00,
    /* rname: hostmaster.example.com. */
    0x0A,'h','o','s','t','m','a','s','t','e','r', 0x07,'e','x','a','m','p','l','e', 0x03,'c','o','m', 0x00,
    /* serial=2026020601, refresh=7200, retry=3600, expire=1209600, minimum=3600 */
    0x78,0xC2,0x9e,0xf9,
    0x00,0x00,0x1C,0x20,
    0x00,0x00,0x0E,0x10,
    0x00,0x12,0x75,0x00,
    0x00,0x00,0x0E,0x10
};
static const uint8_t exp_soa_ns2_admin_small[] = {
    /* mname: ns2.example.net. */
    0x03,'n','s','2', 0x07,'e','x','a','m','p','l','e', 0x03,'n','e','t', 0x00,
    /* rname: admin.example.com. */
    0x05,'a','d','m','i','n', 0x07,'e','x','a','m','p','l','e', 0x03,'c','o','m', 0x00,
    /* serial=1, refresh=3600, retry=600, expire=604800, minimum=300 */
    0x00,0x00,0x00,0x01,
    0x00,0x00,0x0E,0x10,
    0x00,0x00,0x02,0x58,
    0x00,0x09,0x3A,0x80,
    0x00,0x00,0x01,0x2C
};

/* --- SPF / TXT: one or more <character-string> segments --- */
static const uint8_t exp_spf_single[] = {
    0x18,'v','=','s','p','f','1',' ','-','a','l','l',' ','i','n','c','l','u','d','e',':','_','s','p','f'
};
static const uint8_t exp_spf_multi[] = {
    0x0F,'v','=','s','p','f','1',' ','i','p','4',':','1','9','2','.',
    0x0D,'0','.','2','.','0','/','2','4',' ','-','a','l','l'
};
static const uint8_t exp_txt_one[] = { 0x0B,'h','e','l','l','o',' ','w','o','r','l','d' };
static const uint8_t exp_txt_two[] = { 0x03,'o','n','e', 0x03,'t','w','o' };

/* --- SRV: priority(2) weight(2) port(2) target-name --- */
static const uint8_t exp_srv_sip_tcp[] = {
    0x00,0x0A, 0x00,0x3C, 0x13,0xC4,
    0x09,'s','i','p','s','e','r','v','e','r', 0x07,'e','x','a','m','p','l','e', 0x03,'c','o','m', 0x00
};
static const uint8_t exp_srv_root_target[] = {
    0x00,0x00, 0x00,0x00, 0x00,0x35,
    0x00
};

/* --- SSHFP: alg(1) fptype(1) fingerprint(bytes) --- */
static const uint8_t exp_sshfp_1_1_sha1_00_13[] = {
    0x01,0x01,
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13
};
static const uint8_t exp_sshfp_4_2_sha256_00_1f[] = {
    0x04,0x02,
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};

/* --- TLSA: usage(1) selector(1) matching(1) assoc-data(bytes) --- */
static const uint8_t exp_tlsa_3_1_1_sha256_00_1f[] = {
    0x03,0x01,0x01,
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};
static const uint8_t exp_tlsa_2_0_1_short[] = { 0x02,0x00,0x01, 0xDE,0xAD,0xBE,0xEF };

/* --- array of testcases --- */
static const struct tc zone_rr_major_tests[] = {
    { "_https.example.com. 3600 IN HTTPS 1 . alpn=\"h2,h3\" port=443 ipv4hint=192.0.2.1,198.51.100.42\n",
      exp_https_prio1_root_alpn_port_ipv4hint, sizeof(exp_https_prio1_root_alpn_port_ipv4hint) },

    { "alias.example.com. 600 IN CNAME canonical.example.net.\n",
      exp_cname_canonical_example_net, sizeof(exp_cname_canonical_example_net) },
    /* A */
    { "www.example.com. 3600 IN A 192.0.2.1\n",
      exp_a_192_0_2_1, sizeof(exp_a_192_0_2_1) },
    { "example.com. 300 A 198.51.100.42\n",
      exp_a_198_51_100_42, sizeof(exp_a_198_51_100_42) },

    /* AAAA */
    { "www.example.com. 3600 IN AAAA 2001:db8::1\n",
      exp_aaaa_2001_db8__1, sizeof(exp_aaaa_2001_db8__1) },
    { "example.com. AAAA 2001:db8:85a3::8a2e:370:7334\n",
      exp_aaaa_2001_db8_85a3__8a2e_0370_7334, sizeof(exp_aaaa_2001_db8_85a3__8a2e_0370_7334) },

    /* CAA */
    { "example.com. 3600 IN CAA 0 issue \"letsencrypt.org\"\n",
      exp_caa_issue_letsencrypt, sizeof(exp_caa_issue_letsencrypt) },
    { "example.com. CAA 128 iodef \"mailto:security@example.com\"\n",
      exp_caa_iodef_mailto, sizeof(exp_caa_iodef_mailto) },
    { "example.com. CAA 0 issuewild \"ca.example\"\n",
      exp_caa_issuewild_ca, sizeof(exp_caa_issuewild_ca) },

    /* CNAME */
    { "alias.example.com. 600 IN CNAME canonical.example.net.\n",
      exp_cname_canonical_example_net, sizeof(exp_cname_canonical_example_net) },
    { "gone.example.com. CNAME .\n",
      exp_cname_root, sizeof(exp_cname_root) },

    /* DS */
    { "example.com. 3600 IN DS 60501 13 2 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F\n",
      exp_ds_sha256_seq00_1f, sizeof(exp_ds_sha256_seq00_1f) },
    { "example.com. DS 12345 8 1 A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3\n",
      exp_ds_sha1_a0_b3, sizeof(exp_ds_sha1_a0_b3) },

    /* HTTPS */
    { "_https.example.com. 3600 IN HTTPS 1 . alpn=\"h2,h3\" port=443 ipv4hint=192.0.2.1,198.51.100.42\n",
      exp_https_prio1_root_alpn_port_ipv4hint, sizeof(exp_https_prio1_root_alpn_port_ipv4hint) },
    { "svc.example.com. HTTPS 0 svc.example.net. mandatory=alpn,port alpn=\"h2\"\n",
      exp_https_prio0_svc_mandatory_alpn, sizeof(exp_https_prio0_svc_mandatory_alpn) },

    /* MX */
    { "example.com. 3600 IN MX 10 mail.example.com.\n",
      exp_mx_10_mail_example_com, sizeof(exp_mx_10_mail_example_com) },
    { "example.com. MX 0 .\n",
      exp_mx_0_root, sizeof(exp_mx_0_root) },

    /* NAPTR */
    { "sip.example.com. 3600 IN NAPTR 100 50 \"s\" \"SIP+D2U\" \"!^.*$!sip:info@example.com!\" .\n",
      exp_naptr_sip_u, sizeof(exp_naptr_sip_u) },
    { "sip.example.com. NAPTR 10 100 \"s\" \"SIP+D2T\" \"\" sipserver.example.com.\n",
      exp_naptr_empty_regexp_repl_sipserver, sizeof(exp_naptr_empty_regexp_repl_sipserver) },

    /* NS */
    { "example.com. 3600 IN NS ns1.example.net.\n",
      exp_ns_ns1_example_net, sizeof(exp_ns_ns1_example_net) },
    { "example.com. NS ns2.example.net.\n",
      exp_ns_ns2_example_net, sizeof(exp_ns_ns2_example_net) },

    /* PTR */
    { "1.2.0.192.in-addr.arpa. 3600 IN PTR host.example.com.\n",
      exp_ptr_host_example_com, sizeof(exp_ptr_host_example_com) },
    { "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa. PTR .\n",
      exp_ptr_root, sizeof(exp_ptr_root) },

    /* SOA */
    { "example.com. 3600 IN SOA ns1.example.net. hostmaster.example.com. 2026020601 7200 3600 1209600 3600\n",
      exp_soa_ns1_hostmaster_times, sizeof(exp_soa_ns1_hostmaster_times) },
    { "example.com. SOA ns2.example.net. admin.example.com. 1 3600 600 604800 300\n",
      exp_soa_ns2_admin_small, sizeof(exp_soa_ns2_admin_small) },

    /* SPF */
    { "example.com. 3600 IN SPF \"v=spf1 -all include:_spf\"\n",
      exp_spf_single, sizeof(exp_spf_single) },
    { "example.com. SPF \"v=spf1 ip4:192.\" \"0.2.0/24 -all\"\n",
      exp_spf_multi, sizeof(exp_spf_multi) },

    /* SRV */
    { "_sip._tcp.example.com. 3600 IN SRV 10 60 5060 sipserver.example.com.\n",
      exp_srv_sip_tcp, sizeof(exp_srv_sip_tcp) },
    { "_sip._udp.example.com. SRV 0 0 53 .\n",
      exp_srv_root_target, sizeof(exp_srv_root_target) },

    /* SSHFP */
    { "host.example.com. 3600 IN SSHFP 1 1 000102030405060708090A0B0C0D0E0F10111213\n",
      exp_sshfp_1_1_sha1_00_13, sizeof(exp_sshfp_1_1_sha1_00_13) },
    { "host.example.com. SSHFP 4 2 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F\n",
      exp_sshfp_4_2_sha256_00_1f, sizeof(exp_sshfp_4_2_sha256_00_1f) },

    /* SVCB */
    { "_svc.example.com. 3600 IN SVCB 1 . port=8443\n",
      exp_svcb_prio1_root_port, sizeof(exp_svcb_prio1_root_port) },

    /* TLSA */
    { "_443._tcp.example.com. 3600 IN TLSA 3 1 1 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F\n",
      exp_tlsa_3_1_1_sha256_00_1f, sizeof(exp_tlsa_3_1_1_sha256_00_1f) },
    { "_25._tcp.example.com. TLSA 2 0 1 DEADBEEF\n",
      exp_tlsa_2_0_1_short, sizeof(exp_tlsa_2_0_1_short) },

    /* TXT */
    { "example.com. 3600 IN TXT \"hello world\"\n",
      exp_txt_one, sizeof(exp_txt_one) },
    { "example.com. TXT \"one\" \"two\"\n",
      exp_txt_two, sizeof(exp_txt_two) },
    
    {0,0}
};


/* ─────────────────────────────────────────────────────────────────────────────
 * Additional TYPE testcases for: DNSKEY RRSIG NSEC NSEC3 IPSECKEY ZONEMD URI
 *                                 SMIMEA DNAME
 *
 * These are RDATA-only strings (what appears after the TYPE field), each ending
 * with '\n', with expected wire-format RDATA bytes.
 *
 * Assumptions about your atoms (matching what we discussed earlier):
 *  - base64/base64es decode into raw bytes
 *  - hex/hexes decode into raw bytes
 *  - names are encoded as DNS wire names (labels + root 0)
 *  - RRSIG time atom accepts YYYYMMDDHHMMSS and converts to seconds since epoch.
 *    Trick used here: 19700101000000 -> 0, 19700101000001 -> 1.
 *  - NSEC/NSEC3 bitmap atom encodes RFC-style type bitmaps.
 *  - NSEC3 next hashed owner name atom decodes Base32hex:
 *      "00" => one byte 0x00 (common minimal case).
 *
 * If any of those differ in your implementation, tweak the inputs or expected bytes.
 * ───────────────────────────────────────────────────────────────────────────── */

static const uint8_t exp_dnskey_0[] = {
    0x01,0x01,             /* flags=257 */
    0x03,                  /* protocol=3 */
    0x0d,                  /* algorithm=13 */
    0x01,0x02,0x03,0x04    /* public key (base64 "AQIDBA==") */
};

static const uint8_t exp_dnskey_1[] = {
    0x01,0x00,             /* flags=256 */
    0x03,                  /* protocol=3 */
    0x08,                  /* algorithm=8 */
    0x00                   /* public key (base64 "AA==") */
};

static const uint8_t exp_rrsig_0[] = {
    0x00,0x01,             /* type covered = A (1) */
    0x0d,                  /* algorithm = 13 */
    0x02,                  /* labels = 2 */
    0x00,0x00,0x0e,0x10,   /* original TTL = 3600 */
    0x00,0x00,0x00,0x01,   /* expiration = 1 (1970-01-01 00:00:01) */
    0x00,0x00,0x00,0x00,   /* inception  = 0 (1970-01-01 00:00:00) */
    0xec,0x45,             /* key tag = 60485 */
    0x07,'e','x','a','m','p','l','e',
    0x03,'c','o','m',
    0x00,                  /* signer name = example.com. */
    0x01,0x02,0x03         /* signature (base64 "AQID") */
};

static const uint8_t exp_rrsig_1[] = {
    0x00,0x0f,             /* type covered = MX (15) */
    0x08,                  /* algorithm = 8 */
    0x03,                  /* labels = 3 */
    0x00,0x00,0x00,0x00,   /* original TTL = 0 */
    0x00,0x00,0x00,0x00,   /* expiration = 0 */
    0x00,0x00,0x00,0x00,   /* inception  = 0 */
    0x00,0x00,             /* key tag = 0 */
    0x00,                  /* signer name = . (root) */
    0x00                   /* signature (base64 "AA==") */
};

static const uint8_t exp_nsec_0[] = {
    0x04,'n','e','x','t',
    0x07,'e','x','a','m','p','l','e',
    0x03,'c','o','m',
    0x00,                  /* next domain name = next.example.com. */
    0x00,0x01,0x60         /* bitmap: window 0, len 1, types {A,NS} -> 0x60 */
};

static const uint8_t exp_nsec_1[] = {
    0x00,                  /* next domain name = . */
    0x00,0x06,             /* window 0, bitmap length 6 (max type 46) */
    0x60,0x00,0x00,0x00,0x00,0x02
    /* types {A(1),NS(2),RRSIG(46)} -> byte0=0x60, byte5 bit(46)=0x02 */
};

static const uint8_t exp_nsec3_0[] = {
    0x01,                  /* hash alg = 1 */
    0x00,                  /* flags = 0 */
    0x00,0x0a,             /* iterations = 10 */
    0x00,                  /* salt length = 0 (salt '-') */
    0x01,                  /* hash length = 1 */
    0x00,                  /* next hashed owner = 0x00 (base32hex "00") */
    0x00,0x01,0x60         /* bitmap: {A,NS} */
};

static const uint8_t exp_nsec3_1[] = {
    0x01,                  /* hash alg = 1 */
    0x01,                  /* flags = 1 */
    0x00,0x00,             /* iterations = 0 */
    0x02,                  /* salt length = 2 */
    0xa1,0xb2,             /* salt = A1B2 */
    0x01,                  /* hash length = 1 */
    0x00,                  /* next hashed owner = 0x00 (base32hex "00") */
    0x00,0x01,0x40         /* bitmap: {A} -> 0x40 */
};

static const uint8_t exp_ipseckey_0[] = {
    0x0a,                  /* precedence = 10 */
    0x01,                  /* gateway type = 1 (IPv4) */
    0x02,                  /* algorithm = 2 */
    0xc0,0x00,0x02,0x01,   /* gateway IPv4 = 192.0.2.1 */
    0x01,0x02,0x03         /* public key (base64 "AQID") */
};

static const uint8_t exp_ipseckey_1[] = {
    0x00,                  /* precedence = 0 */
    0x03,                  /* gateway type = 3 (domain name) */
    0x00,                  /* algorithm = 0 */
    0x02,'g','w',
    0x07,'e','x','a','m','p','l','e',
    0x03,'c','o','m',
    0x00                   /* gateway name = gw.example.com. ; key is '-' empty */
};

static const uint8_t exp_zonemd_0[] = {
    0x00,0x00,0x00,0x01,   /* serial = 1 */
    0x01,                  /* scheme = 1 */
    0x01,                  /* hash alg = 1 */
    0xaa,0xbb              /* digest = AABB */
};

static const uint8_t exp_zonemd_1[] = {
    0x00,0x00,0x00,0x00,   /* serial = 0 */
    0x01,                  /* scheme = 1 */
    0x02                   /* hash alg = 2 ; digest '-' empty */
};

static const uint8_t exp_uri_0[] = {
    0x00,0x0a,             /* priority = 10 */
    0x00,0x01,             /* weight = 1 */
    0x0a,                  /* target length = 10 */
    'h','t','t','p','s',':','/','/','e','/'  /* "https://e/" */
};

static const uint8_t exp_uri_1[] = {
    0x00,0x00,             /* priority = 0 */
    0x00,0x00,             /* weight = 0 */
    0x00                   /* empty target "" */
};

static const uint8_t exp_smimea_0[] = {
    0x03,                  /* usage = 3 */
    0x01,                  /* selector = 1 */
    0x01,                  /* matching type = 1 */
    0xaa,0xbb,0xcc         /* data = AABBCC */
};

static const uint8_t exp_smimea_1[] = {
    0x00,                  /* usage = 0 */
    0x00,                  /* selector = 0 */
    0x00                   /* matching type = 0 ; data '-' empty */
};

static const uint8_t exp_dname_0[] = {
    0x07,'e','x','a','m','p','l','e',
    0x03,'c','o','m',
    0x00                   /* example.com. */
};

static const uint8_t exp_dname_1[] = {
    0x00                   /* . (root) */
};

static const uint8_t exp_dnskey_multiline[] = {
    0x01,0x01, 0x03, 0x0d, 0x01,0x02,0x03,0x04
};

static const uint8_t exp_rrsig_multiline[] = {
    0x00,0x01, 0x0d, 0x02,
    0x00,0x00,0x0e,0x10,
    0x00,0x00,0x00,0x01,
    0x00,0x00,0x00,0x00,
    0xec,0x45,
    0x07,'e','x','a','m','p','l','e',
    0x03,'c','o','m',
    0x00,
    0x01,0x02,0x03
};

static const uint8_t exp_nsec3_a[] = {
 0x01, /* algo=SHA-1 */
 0x00, /* flags */
 0x00, 0x00, /* iterations = 0 */
 0x00, /* salt length = 0 */
 0x14, /* hash length */
 0xc6, 0xda, 0xcc, 0x1c, 0xda, 0x94, 0x6c, 0x44,
 0x62, 0x34, 0xe0, 0xdd, 0x0b, 0x13, 0x3a, 0xd2,
 0x3b, 0x68, 0x8c, 0x8d,
 0x00, 0x07, /* bitmask length = 7 */
 0x62, 0x01, 0x80, 0x08, 0x00, 0x02, 0x90, /* bitmask */
};

static const uint8_t se_0_ds[] = {
    0x36, 0xc6,
    0x0d,
    0x02,
    0x24, 0x89, 0x97, 0x83, 0xe8, 0x85, 0xc3, 0x47, 0x33, 0x1e, 0xb4, 0xe7, 0x98, 0xe2, 0x9c, 0xea,
    0x96, 0x1c, 0x80, 0xdd, 0x3b, 0xd9, 0xa2, 0x9e, 0x65, 0x0a, 0x4c, 0xc7, 0x54, 0x90, 0x15, 0x3b,
};

static const uint8_t se_zonemd[] = {
    0x69, 0x96, 0x2d, 0x14,
    0x01,
    0x02,
    0x68, 0x38, 0x64, 0xa9, 0xbd, 0x3d, 0xa9, 0x49,
    0xdb, 0x78, 0x7e, 0xe5, 0x5a, 0xa4, 0x2d, 0x47,
    0xc9, 0xf6, 0x2a, 0xd2, 0x1d, 0x7a, 0xb7, 0x75,
    0x2a, 0x67, 0x5f, 0x5f, 0xd9, 0x4b, 0xdb, 0xd1,
    0x37, 0xfe, 0xef, 0xb3, 0x5d, 0xad, 0xb0, 0x1a,
    0x1c, 0xcc, 0xf8, 0xcb, 0x77, 0x32, 0x65, 0x1e,
    0x58, 0x32, 0xb4, 0x71, 0xe3, 0x30, 0xa6, 0xb6,
    0xcd, 0x12, 0x45, 0x2c, 0xa9, 0xb5, 0x4e, 0xbe,
};

static const uint8_t for_sale[] = {
    0x19,
    0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x2d, 0x6d,
    0x61, 0x79, 0x2d, 0x62, 0x65, 0x2d, 0x66, 0x6f,
    0x72, 0x2d, 0x73, 0x61, 0x6c, 0x65, 0x2d, 0x61, 0x74,
    0x05, 0x65, 0x64, 0x6f, 0x6d, 0x73, /* ".edoms" */
    0x03, 0x62, 0x69, 0x7a, /* ".biz" */
    0x00 /* ". */
};
static const struct tc tc_types2[] = {
    {"720pstream.se.        86400    IN    NS    domain-may-be-for-sale-at.edoms.biz. ;hello\r\n",
        for_sale, sizeof(for_sale)},
    {"se.            172800    IN    TYPE63    \\# 70 69962D140102683864A9BD3DA949DB787EE55AA42D47C9F62AD21D7A B7752A675F5FD94BDBD137FEEFB35DADB01A1CCCF8CB7732651E5832 B471E330A6B6CD12452CA9B54EBE\n",
        se_zonemd, sizeof(se_zonemd)},
    {"0.se.            3600    IN    DS    14022 13 2 24899783E885C347331EB4E798E29CEA961C80DD3BD9A29E650A4CC7 5490153B\r\n",
    se_0_ds, sizeof(se_0_ds)},
    { "onib9mgub9h0rml3cdf5bgrj59dkjhvk.example.com. 3600 IN NSEC3 1 0 0 - ORDCO76QIHM48OHKS3EGM4PQQ8TMH34D  A NS SOA MX TXT AAAA RRSIG DNSKEY NSEC3PARAM\n", exp_nsec3_a, sizeof(exp_nsec3_a)},
    /* DNSKEY */
    { "foo. DNSKEY 257 3 13 AQIDBA==\n",                exp_dnskey_0,  sizeof(exp_dnskey_0) },
    { "foo. DNSKEY 256 3 8 AA==\n",                     exp_dnskey_1,  sizeof(exp_dnskey_1) },

    /* RRSIG */
    { "foo. RRSIG A 13 2 3600 19700101000001 19700101000000 60485 example.com. AQID\n",
                                           exp_rrsig_0,   sizeof(exp_rrsig_0) },
    { "foo. RRSIG MX 8 3 0 19700101000000 19700101000000 0 . AA==\n",
                                           exp_rrsig_1,   sizeof(exp_rrsig_1) },

    /* NSEC */
    { "foo. NSEC next.example.com. A NS\n",          exp_nsec_0,    sizeof(exp_nsec_0) },
    { "foo. NSEC . A NS RRSIG\n",                    exp_nsec_1,    sizeof(exp_nsec_1) },

    /* NSEC3 */
    { "foo. NSEC3 1 0 10 - 00 A NS\n",                exp_nsec3_0,   sizeof(exp_nsec3_0) },
    { "foo. NSEC3 1 1 0 A1B2 00 A\n",                 exp_nsec3_1,   sizeof(exp_nsec3_1) },

    /* IPSECKEY */
    { "foo. IPSECKEY 10 1 2 192.0.2.1 AQID\n",           exp_ipseckey_0,sizeof(exp_ipseckey_0) },
    { "foo. IPSECKEY 0 3 0 gw.example.com. -\n",         exp_ipseckey_1,sizeof(exp_ipseckey_1) },

    /* ZONEMD */
    { "foo. ZONEMD 1  1 1 AABB\n",                      exp_zonemd_0,  sizeof(exp_zonemd_0) },
    { "foo. ZONEMD 0 1 2 -\n",                         exp_zonemd_1,  sizeof(exp_zonemd_1) },

    /* URI */
    { "foo. URI 10 1 \"https://e/\"\n",             exp_uri_0,     sizeof(exp_uri_0) },
    { "foo. URI 0 0 \"\"\n",                        exp_uri_1,     sizeof(exp_uri_1) },

    /* SMIMEA */
    { "foo. SMIMEA 3 1 1 AABBCC\n",                    exp_smimea_0,  sizeof(exp_smimea_0) },
    { "foo. SMIMEA 0 0 0 -\n",                         exp_smimea_1,  sizeof(exp_smimea_1) },

    /* DNAME */
    { "foo. DNAME example.com.\n",                    exp_dname_0,   sizeof(exp_dname_0) },
    { "foo. DNAME .\n",                               exp_dname_1,   sizeof(exp_dname_1) },
    { "foo. DNSKEY 257 3 13 (\n  AQIDBA==\n )\n",       exp_dnskey_multiline, sizeof(exp_dnskey_multiline) },
    { "foo. RRSIG A 13 2 3600 (\n  19700101000001 19700101000000\n  60485 example.com.\n  AQID\n )\n",
        exp_rrsig_multiline, sizeof(exp_rrsig_multiline) },
    {0}
};

int
zone_parse_quicktest1(const struct tc *testcases) {
    /* Expected wire format in these tests is:
     *   NAME | TYPE | CLASS | TTL | RDLENGTH | RDATA
     *
     * Note: These expected byte strings assume:
     * - CLASS=IN (0x0001)
     * - TTL encoding is 32-bit big-endian
     * - All names encoded as DNS label format ending in 0x00
     *
     * If your project’s “wire chunk” layout differs (e.g., omits TTL/class/type),
     * update these vectors accordingly.
     */


    int failures = 0;
    struct zone_state_t state = {0};
    memcpy(state.origin, "\x7example\x3com\x0", 13);
    state.origin_length = 13;

    for (int i = 0; testcases[i].contents; i++) {
        const struct tc *test = &testcases[i];
        
        wire_record_t out = {0};
        unsigned char wirebuf[65536+1024];
        out.wire.buf = wirebuf;
        out.wire.max = 65536;

        state.line_number = i;
        state.line_offset = 0;
        const char *data = test->contents;
        size_t max = strlen(test->contents);
        
        /*
         * Call the tested function to parse the record.
         */
        size_t cursor = zone_parse_record(data, 0, max, &state, &out);
        
        const unsigned char *out_wire = out.wire.buf + out.name_length + 8;
        size_t out_len = out_wire[0]<<8 | out_wire[1];
        out_wire += 2;
        
        /*
         * Verify the results
         */
        if (out.err.code != 0 || cursor > max) {
            fprintf(stderr, "[-] #%d: error: %s \n", i, zone_error_msg(out.err.code));
            fprintf(stderr, "    %s\n", test->contents);
            failures++;
            continue;
        }
        if (out_len != test->expected_len) {
            fprintf(stderr, "[-] record: %d: bad len, found=%u, expect=%u\n",
                    i, (unsigned)out_len, (unsigned)test->expected_len);
            fprintf(stderr, "    %s\n", test->contents);
            failures++;
            //continue;
        }
        if (memcmp(out_wire, test->expected, test->expected_len) != 0) {
            fprintf(stderr, "[-] record: %d: bad data\n",
                    i);
            fprintf(stderr, "    %s\n", test->contents);
            for (int j=0; j<out_len; j++) {
                fprintf(stderr, " %02x ", out_wire[j]);
            }
            fprintf(stderr, "\n");
            for (int j=0; j<test->expected_len; j++) {
                fprintf(stderr, " %02x ", test->expected[j]);
            }
            fprintf(stderr, "\n");
            
            failures++;
            continue;
        }
    }

    return failures ? 1 : 0;
}

int
zone_parse_quicktest(void) {
    int err = 0;
    
    err += zone_parse_quicktest1(zone_rr_major_tests);
    err += zone_parse_quicktest1(tc_types2);
    
    return err;
}
