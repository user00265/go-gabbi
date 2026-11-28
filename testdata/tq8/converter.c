/* Runs Debian TrustedQSL's ADIF converter using disposable imported keys. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tqsllib.h"
#include "tqslerrno.h"
#include "tqslconvert.h"

static void check(int result, const char *what) {
    if (result) {
        fprintf(stderr, "%s (rc=%d): %s\n", what, result, tqsl_getErrorString());
        exit(1);
    }
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <normal|chained|commit|dupe-preamble> <adif> <out> [p12...]\n", argv[0]);
        return 2;
    }
    const char *mode = argv[1];
    const char *adif_path = argv[2];
    const char *out_path = argv[3];
    int chained = !strcmp(mode, "chained");
    int commit = !strcmp(mode, "commit");
    int allow_dupe_skip = !strcmp(mode, "dupe-preamble");
    if (!chained && !commit && !allow_dupe_skip && strcmp(mode, "normal") != 0) {
        fprintf(stderr, "unknown mode: %s\n", mode);
        return 2;
    }

    check(tqsl_init(), "init");
    for (int i = 4; i < argc; i++) {
        check(tqsl_importPKCS12File(argv[i], "", "", NULL, NULL, NULL), "import");
    }
    if (chained) {
        check(tqsl_setADIFMode("CW", "SSB"), "map CW");
        check(tqsl_setADIFMode("SSB", "DATA"), "map SSB");
    }

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
    check(tqsl_selectCertificates(&certs, &count, "KF0TST", 291, NULL, NULL, 1), "certificates");
    if (count < 1) {
        fprintf(stderr, "expected at least one certificate, got %d\n", count);
        return 1;
    }

    tQSL_Converter conv = NULL;
    check(tqsl_beginADIFConverter(&conv, adif_path, certs, count, loc), "converter");
    check(tqsl_setConverterAllowDuplicates(conv, 0), "duplicates");
    check(tqsl_setConverterAppName(conv, "go-gabbi-fixture"), "app name");

    FILE *out = fopen(out_path, "wb");
    if (!out) {
        perror("output");
        return 1;
    }
    int dupes = 0;
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
        if (allow_dupe_skip && tQSL_Error == TQSL_DUPLICATE_QSO) {
            dupes++;
            continue;
        }
        if (tQSL_Error != TQSL_NO_ERROR) {
            int err = tQSL_Error;
            const char *msg = tqsl_getErrorString();
            fprintf(stderr, "convert error %d: %s\n", err, msg);
            return 1;
        }
        break;
    }
    if (allow_dupe_skip && dupes != 1) {
        fprintf(stderr, "expected 1 duplicate in dupe-preamble mode, got %d\n", dupes);
        return 1;
    }
    if (fclose(out)) {
        perror("close");
        return 1;
    }
    if (commit) {
        check(tqsl_converterCommit(conv), "commit");
    } else {
        check(tqsl_converterRollBack(conv), "rollback");
    }
    check(tqsl_endConverter(&conv), "end converter");
    return 0;
}
