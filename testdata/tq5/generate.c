/* Fixture harness: invokes the Debian TrustedQSL shared library, not go-gabbi. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tqsllib.h"

static void check(int result, const char *what) {
    if (result) { fprintf(stderr, "%s: %s\n", what, tqsl_getErrorString()); exit(1); }
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    check(tqsl_init(), "init");
    TQSL_CERT_REQ req = {0};
    strcpy(req.providerName, "American Radio Relay League");
    strcpy(req.providerUnit, "Logbook of the World");
    strcpy(req.callSign, "KF0TST");
    strcpy(req.name, "John Q Public");
    strcpy(req.address1, "1 Main Street");
    strcpy(req.city, "Dona Ana");
    strcpy(req.state, "NM");
    strcpy(req.postalCode, "88001");
    strcpy(req.country, "USA");
    strcpy(req.emailAddress, "john@example.org");
    req.dxccEntity = 291;
    check(tqsl_initDate(&req.qsoNotBefore, "2020-05-14"), "start date");
    check(tqsl_initDate(&req.qsoNotAfter, "2029-03-19"), "end date");
    char path[512];
    snprintf(path, sizeof path, "%s/new.tq5", argv[1]);
    check(tqsl_createCertRequest(path, &req, NULL, NULL), "new request");
    check(tqsl_importPKCS12File("signer.p12", "", "", NULL, NULL, NULL), "import signer");
    tQSL_Cert *list = NULL;
    int count = 0;
    check(tqsl_selectCertificates(&list, &count, "KF0TST", 291, NULL, NULL, 1), "select signer");
    if (count < 1) { fprintf(stderr, "no signing certificate\n"); return 1; }
    char password[] = "";
    check(tqsl_beginSigning(list[0], password, NULL, NULL), "begin signing");
    req.signer = list[0];
    snprintf(path, sizeof path, "%s/additional.tq5", argv[1]);
    check(tqsl_createCertRequest(path, &req, NULL, NULL), "additional request");
    return 0;
}
