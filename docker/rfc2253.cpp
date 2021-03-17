// compile with: g++ -std=c++14 rfc2553.cpp -lcrypto -lssl

#include <openssl/x509.h>
#include <iostream>
#include <openssl/err.h>
#include <memory>
#include <cstring>

char const* program_name;

std::string to_rfc2253(std::string const& name);

int main(int argc, char* argv[])
{
  program_name = argv[0];

  if (argc == 1) {
    std::string name;
    while (std::getline(std::cin, name)) {
      std::cout << to_rfc2253(name) << '\n';
    }
  } else {
    std::cout << to_rfc2253(argv[1]) << '\n';
  }
}

char const* opt_getprog()
{
  return program_name;
}

BIO* bio_err = BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT);

// the following function is taken literally from openssl

/*
 * name is expected to be in the format /type0=value0/type1=value1/type2=...
 * where + can be used instead of / to form multi-valued RDNs if canmulti
 * and characters may be escaped by \
 */
X509_NAME *parse_name(const char *cp, int chtype, int canmulti,
                      const char *desc)
{
    int nextismulti = 0;
    char *work;
    X509_NAME *n;

    if (*cp++ != '/') {
        BIO_printf(bio_err,
                   "%s: %s name is expected to be in the format "
                   "/type0=value0/type1=value1/type2=... where characters may "
                   "be escaped by \\. This name is not in that format: '%s'\n",
                   opt_getprog(), desc, --cp);
        return NULL;
    }

    n = X509_NAME_new();
    if (n == NULL) {
        BIO_printf(bio_err, "%s: Out of memory\n", opt_getprog());
        return NULL;
    }
    work = OPENSSL_strdup(cp);
    if (work == NULL) {
        BIO_printf(bio_err, "%s: Error copying %s name input\n",
                   opt_getprog(), desc);
        goto err;
    }

    while (*cp != '\0') {
        char *bp = work;
        char *typestr = bp;
        unsigned char *valstr;
        int nid;
        int ismulti = nextismulti;
        nextismulti = 0;

        /* Collect the type */
        while (*cp != '\0' && *cp != '=')
            *bp++ = *cp++;
        *bp++ = '\0';
        if (*cp == '\0') {
            BIO_printf(bio_err,
                       "%s: Missing '=' after RDN type string '%s' in %s name string\n",
                       opt_getprog(), typestr, desc);
            goto err;
        }
        ++cp;

        /* Collect the value. */
        valstr = (unsigned char *)bp;
        for (; *cp != '\0' && *cp != '/'; *bp++ = *cp++) {
            /* unescaped '+' symbol string signals further member of multiRDN */
            if (canmulti && *cp == '+') {
                nextismulti = 1;
                break;
            }
            if (*cp == '\\' && *++cp == '\0') {
                BIO_printf(bio_err,
                           "%s: Escape character at end of %s name string\n",
                           opt_getprog(), desc);
                goto err;
            }
        }
        *bp++ = '\0';

        /* If not at EOS (must be + or /), move forward. */
        if (*cp != '\0')
            ++cp;

        /* Parse */
        nid = OBJ_txt2nid(typestr);
        if (nid == NID_undef) {
            BIO_printf(bio_err,
                       "%s: Skipping unknown %s name attribute \"%s\"\n",
                       opt_getprog(), desc, typestr);
            if (ismulti)
                BIO_printf(bio_err,
                           "Hint: a '+' in a value string needs be escaped using '\\' else a new member of a multi-valued RDN is expected\n");
            continue;
        }
        if (*valstr == '\0') {
            BIO_printf(bio_err,
                       "%s: No value provided for %s name attribute \"%s\", skipped\n",
                       opt_getprog(), desc, typestr);
            continue;
        }
        if (!X509_NAME_add_entry_by_NID(n, nid, chtype,
                                        valstr, strlen((char *)valstr),
                                        -1, ismulti ? -1 : 0)) {
            ERR_print_errors(bio_err);
            BIO_printf(bio_err,
                       "%s: Error adding %s name attribute \"/%s=%s\"\n",
                       opt_getprog(), desc, typestr ,valstr);
            goto err;
        }
    }

    OPENSSL_free(work);
    return n;

 err:
    X509_NAME_free(n);
    OPENSSL_free(work);
    return NULL;
}

std::string to_rfc2253(X509_NAME const* name)
{
  std::string result;

  using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;

  BioPtr bio(BIO_new(BIO_s_mem()), &BIO_free);
  if (bio == nullptr) {
    BIO_printf(bio_err, "Cannot create new BIO_s_mem\n");
    return result;
  }

  if (X509_NAME_print_ex(bio.get(), const_cast<X509_NAME*>(name), 0, XN_FLAG_RFC2253) < 0) {
    BIO_printf(bio_err, "X509_NAME_print_ex failed\n");
    return result;
  }

  auto len = BIO_pending(bio.get());
  result.resize(len);

  BIO_read(bio.get(), &result[0], result.size());

  return result;
}

std::string to_rfc2253(std::string const& name)
{
  std::string result;

  const unsigned long chtype = MBSTRING_ASC;
  const int multirdn = 1;

  auto x509_name = parse_name(name.c_str(), chtype, multirdn, "subject");

  if (x509_name != nullptr) {
    result = to_rfc2253(x509_name);
    X509_NAME_free(x509_name);
  }

  return result;
}
