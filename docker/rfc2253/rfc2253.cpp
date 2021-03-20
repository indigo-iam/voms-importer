// compile with: g++ -std=c++11 rfc2253.cpp -lcrypto -lssl
//  add -DENABLE_TESTING to do testing

#include <openssl/err.h>
#include <openssl/x509.h>
#include <cstring>
#include <iostream>
#include <memory>
#include <vector>

std::string to_rfc2253(std::string const& name);

std::string program_name{"a.out"};

#ifdef ENABLE_TESTING

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

TEST_CASE("Testing rfc 2253")
{
  int ret =
      ASN1_STRING_TABLE_add(NID_organizationName, 1, 128, DIRSTRING_TYPE, 0);
  REQUIRE_MESSAGE(ret == 1,
                  "Cannot change length limits of Organization Name\n");

  CHECK(to_rfc2253("/DC=ch/CN=") == "");
  CHECK(to_rfc2253("/DC=ch/=pippo") == "");
  CHECK(to_rfc2253("/DC=ch/CN=pippo") == "CN=pippo,DC=ch");
  CHECK(to_rfc2253("/DC=ch/DC=cern/OU=computers/CN=unified") ==
        "CN=unified,OU=computers,DC=cern,DC=ch");
  CHECK(to_rfc2253("/DC=ch/DC=cern/OU=computers/CN=unified/voms") ==
        "CN=unified/voms,OU=computers,DC=cern,DC=ch");
  CHECK(to_rfc2253("/DC=ch/DC=cern/OU=computers/CN=tier0/vocms001.cern.ch") ==
        "CN=tier0/vocms001.cern.ch,OU=computers,DC=cern,DC=ch");
  CHECK(to_rfc2253("/DC=org/DC=terena/DC=tcs/C=ES/O=Centro de Investigaciones "
                   "Energeticas Medioambientales y Tecnologicas/CN=Cruz "
                   "Martinez M. Begona De La u3606@ciemat.es") ==
        "CN=Cruz Martinez M. Begona De La u3606@ciemat.es,O=Centro de "
        "Investigaciones Energeticas Medioambientales y "
        "Tecnologicas,C=ES,DC=tcs,DC=terena,DC=org");
}

#else  // ENABLE_TESTING

int main(int argc, char* argv[])
{
  program_name = argv[0];

  int ret =
      ASN1_STRING_TABLE_add(NID_organizationName, 1, 128, DIRSTRING_TYPE, 0);
  if (ret == 0) {
    std::cerr << "Cannot change length limits of Organization Name\n";
    return EXIT_FAILURE;
  }

  if (argc == 1) {
    std::string name;
    while (std::getline(std::cin, name)) {
      std::cout << to_rfc2253(name) << '\n';
    }
  } else {
    std::cout << to_rfc2253(argv[1]) << '\n';
  }
}

#endif  // ENABLE_TESTING

char const* opt_getprog()
{
  return program_name.c_str();
}

BIO* bio_err = BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT);

// the following function is taken literally from openssl

// clang-format off
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
// clang-format on

#include <algorithm>

X509_NAME* parse_name_impl(const char* cp,
                           int chtype,
                           int canmulti,
                           const char* desc);

X509_NAME* parse_name(std::string const& name)
{
  unsigned long const chtype = MBSTRING_ASC;
  auto const multirdn = 1;
  auto const desc = "subject";

  return parse_name_impl(name.c_str(), chtype, multirdn, desc);
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

  if (X509_NAME_print_ex(
          bio.get(), const_cast<X509_NAME*>(name), 0, XN_FLAG_RFC2253) < 0) {
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

  auto x509_name = parse_name(name);

  if (x509_name != nullptr) {
    result = to_rfc2253(x509_name);
    X509_NAME_free(x509_name);
  }

  return result;
}

X509_NAME* parse_name_impl(const char* cp,
                           int chtype,
                           int /* canmulti */,
                           const char* /* desc */)
{
  std::string const name(cp);
  using X509NamePtr = std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)>;

  X509NamePtr x509_name(X509_NAME_new(), &X509_NAME_free);

  // scan the string in reverse order
  auto it = name.rbegin();
  auto end = name.rend();

  while (it != end) {
    auto eq_it = std::find(it, end, '=');
    auto slash_it = std::find(eq_it, end, '/');
    if (eq_it == it || eq_it == end || slash_it == end ||
        eq_it + 1 == slash_it) {
      return nullptr;
    }
    std::string const value(eq_it.base(), it.base());
    ++eq_it;
    std::string const type(slash_it.base(), eq_it.base());

    auto const nid = OBJ_txt2nid(type.c_str());
    if (nid == NID_undef) {
      return nullptr;
    }
    auto const value_u = reinterpret_cast<unsigned char const*>(value.c_str());
    auto const err = X509_NAME_add_entry_by_NID(
        x509_name.get(), nid, chtype, value_u, value.size(), 0, 0);
    if (err == 0) {
      ERR_print_errors(bio_err);
      return nullptr;
    }

    it = ++slash_it;
  }

  return x509_name.release();
}
