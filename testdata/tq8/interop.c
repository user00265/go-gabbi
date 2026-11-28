/* Cross-implementation interop checks against Debian TrustedQSL 2.8.7-1. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "tqsllib.h"
#include "tqslerrno.h"
#include "tqslconvert.h"

static void check(int result, const char *what) {
    if (result) {
        fprintf(stderr, "%s (rc=%d): %s\n", what, result, tqsl_getErrorString());
        exit(1);
    }
}

static void assert_nonempty_cert_file(const char *tqsldir, const char *name) {
    char path[4096];
    struct stat st;
    int n = snprintf(path, sizeof(path), "%s/certs/%s", tqsldir, name);
    if (n < 0 || (size_t)n >= sizeof(path)) {
        fprintf(stderr, "path overflow for %s\n", name);
        exit(1);
    }
    if (stat(path, &st) != 0) {
        fprintf(stderr, "expected cert file %s to exist\n", path);
        perror("stat");
        exit(1);
    }
    if (st.st_size <= 0) {
        fprintf(stderr, "expected cert file %s to be non-empty (size=%lld)\n",
                path, (long long)st.st_size);
        exit(1);
    }
}

static void assert_cert_files_restored(void) {
    const char *tqsldir = getenv("TQSLDIR");
    if (!tqsldir || !tqsldir[0]) {
        fprintf(stderr, "TQSLDIR is not set\n");
        exit(1);
    }
    assert_nonempty_cert_file(tqsldir, "root");
    assert_nonempty_cert_file(tqsldir, "authorities");
    assert_nonempty_cert_file(tqsldir, "user");
}

static int check_p12(const char *p12_path, const char *password) {
    check(tqsl_init(), "init");
    check(tqsl_importPKCS12File(p12_path, password, "", NULL, NULL, NULL), "import p12");
    assert_cert_files_restored();

    tQSL_Cert *certs = NULL;
    int count = 0;
    check(tqsl_selectCertificates(&certs, &count, "KF0TST", 291, NULL, NULL, 1), "selectCertificates");
    if (count != 1) {
        fprintf(stderr, "expected 1 cert for %s, got %d\n", p12_path, count);
        return 1;
    }
    return 0;
}

static int check_tq6(const char *tq6_path) {
    check(tqsl_init(), "init");
    check(tqsl_importTQSLFile(tq6_path, NULL, NULL), "import tq6");
    assert_cert_files_restored();

    tQSL_Cert *certs = NULL;
    int count = 0;
    check(tqsl_selectCertificates(&certs, &count, "KF0TST", 291, NULL, NULL, 1), "selectCertificates");
    if (count != 1) {
        fprintf(stderr, "expected 1 cert after tq6 restore, got %d\n", count);
        return 1;
    }
    return 0;
}

static int check_sign(const char *p12_1, const char *p12_2, const char *adif_path, const char *out_path) {
    check(tqsl_init(), "init");
    check(tqsl_importPKCS12File(p12_1, "", "", NULL, NULL, NULL), "import cert1");
    check(tqsl_importPKCS12File(p12_2, "", "", NULL, NULL, NULL), "import cert2");

    tQSL_Location loc = NULL;
    check(tqsl_initStationLocationCapture(&loc), "location");
    check(tqsl_setStationLocationCapturePage(loc, 1), "page 1");
    check(tqsl_setLocationCallSign(loc, "KF0TST", 291), "callsign");
    check(tqsl_updateStationLocationCapture(loc), "update page 1");
    check(tqsl_setLocationField(loc, "GRIDSQUARE", "em10dh"), "GRIDSQUARE");
    check(tqsl_setLocationField(loc, "CQZ", "4"), "CQZ");
    check(tqsl_setLocationField(loc, "ITUZ", "7"), "ITUZ");
    check(tqsl_setLocationField(loc, "IOTA", "na-001"), "IOTA");
    check(tqsl_updateStationLocationCapture(loc), "update page 1 fields");
    check(tqsl_nextStationLocationCapture(loc), "page 2");
    check(tqsl_setLocationField(loc, "US_STATE", "TX"), "US_STATE");
    check(tqsl_updateStationLocationCapture(loc), "update US_STATE");
    check(tqsl_setLocationField(loc, "US_COUNTY", "Travis"), "US_COUNTY");
    check(tqsl_updateStationLocationCapture(loc), "update US_COUNTY");

    tQSL_Cert *certs = NULL;
    int count = 0;
    check(tqsl_selectCertificates(&certs, &count, "KF0TST", 291, NULL, NULL, 1), "selectCertificates");
    if (count != 1) {
        fprintf(stderr, "expected 1 active cert (superseded cert1 excluded), got %d\n", count);
        return 1;
    }

    tQSL_Converter conv = NULL;
    check(tqsl_beginADIFConverter(&conv, adif_path, certs, count, loc), "converter");
    check(tqsl_setConverterAllowDuplicates(conv, 0), "duplicates");
    check(tqsl_setConverterAppName(conv, "go-gabbi-interop"), "app name");

    FILE *out = fopen(out_path, "wb");
    if (!out) {
        perror("output");
        return 1;
    }
    for (;;) {
        const char *record = tqsl_getConverterGABBI(conv);
        if (record) {
            if (fputs(record, out) == EOF) {
                perror("write");
                return 1;
            }
            continue;
        }
        if (tQSL_Error == TQSL_SIGNINIT_ERROR) {
            tQSL_Cert cert;
            check(tqsl_getConverterCert(conv, &cert), "converter cert");
            char password[] = "";
            check(tqsl_beginSigning(cert, password, NULL, NULL), "begin signing");
            continue;
        }
        if (tQSL_Error == TQSL_NEW_UPLOAD_DB) {
            continue;
        }
        if (tQSL_Error != TQSL_NO_ERROR) {
            fprintf(stderr, "convert error %d: %s\n", tQSL_Error, tqsl_getErrorString());
            return 1;
        }
        break;
    }
    if (fclose(out)) {
        perror("close");
        return 1;
    }
    check(tqsl_converterRollBack(conv), "rollback");
    check(tqsl_endConverter(&conv), "end converter");
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <p12|tq6|sign> ...\n", argv[0]);
        return 2;
    }
    if (!strcmp(argv[1], "p12")) {
        if (argc != 4) {
            fprintf(stderr, "usage: %s p12 <file.p12> <password>\n", argv[0]);
            return 2;
        }
        return check_p12(argv[2], argv[3]);
    }
    if (!strcmp(argv[1], "tq6")) {
        if (argc != 3) {
            fprintf(stderr, "usage: %s tq6 <file.tq6>\n", argv[0]);
            return 2;
        }
        return check_tq6(argv[2]);
    }
    if (!strcmp(argv[1], "sign")) {
        if (argc != 6) {
            fprintf(stderr, "usage: %s sign <cert1.p12> <cert2.p12> <contacts.adi> <out.gabbi>\n", argv[0]);
            return 2;
        }
        return check_sign(argv[2], argv[3], argv[4], argv[5]);
    }
    fprintf(stderr, "unknown subcommand: %s\n", argv[1]);
    return 2;
}
