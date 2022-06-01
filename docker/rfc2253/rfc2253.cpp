// compile with: g++ -std=c++11 rfc2253.cpp -lcrypto
//  add -DENABLE_TESTING to do testing

#include <openssl/x509.h>
#include <algorithm>
#include <iostream>
#include <string>

std::string to_rfc2253(std::string const& name);

#ifdef ENABLE_TESTING

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

TEST_CASE("Testing rfc 2253")
{
  CHECK(to_rfc2253("/DC=ch/CN=") == "");
  CHECK(to_rfc2253("DC=ch/CN=") == "");
  CHECK(to_rfc2253("/DC=ch/=pippo") == "");
  CHECK(to_rfc2253("/D=ch/CN=pippo") == "");
  CHECK(to_rfc2253("DC=ch/CN=pippo") == "");
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
  CHECK(to_rfc2253("/DC=org/DC=incommon/C=US/ST=California/L=La Jolla/O=University of California, San Diego") == R"(O=University of California\, San Diego,L=La Jolla,ST=California,C=US,DC=incommon,DC=org)");
  CHECK(to_rfc2253("/C=IT/O=INFN/OU=Personal Certificate/L=Milano/CN=Mario Rossi/Email=mario.rossi@mi.infn.it") == "");
  CHECK(to_rfc2253("/C=DE/O=Max/CN=Rossi, Dr. Mario ABC1234@uni-hamburg.de") == R"(CN=Rossi\, Dr. Mario ABC1234@uni-hamburg.de,O=Max,C=DE)");
  CHECK(to_rfc2253("/C=DE/O=GridGermany/OU=Technische Universitaet Dresden/sn=Becker/gn=Boris/CN=Boris Becker") == "");
}

#else  // ENABLE_TESTING

int main(int argc, char* argv[])
{
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

bool is_special(char c)
{
  return c == ',' || c == '+';
}

std::string escape(std::string const& value)
{
  std::string result;
  result.reserve(value.size());
  for (char c : value) {
    if (is_special(c)) {
      result.push_back('\\');
    }
    result.push_back(c);
  }
  return result;
}

std::string to_rfc2253(std::string const& name)
{
  std::string result;

  // scan the string in reverse order
  auto it = name.rbegin();
  auto end = name.rend();

  while (it != end) {
    auto eq_it = std::find(it, end, '=');
    auto slash_it = std::find(eq_it, end, '/');

    if (eq_it == it || eq_it == end || slash_it == end ||
        eq_it + 1 == slash_it) {
      return std::string{};
    }

    std::string const value(eq_it.base(), it.base());
    ++eq_it;
    std::string const type(slash_it.base(), eq_it.base());

    if (OBJ_txt2nid(type.c_str()) != NID_undef) {
      if (not result.empty()) {
        result += ',';
      }
      result += type + '=' + escape(value);
    } else {
      return std::string{};
    }

    it = ++slash_it;
  }

  return result;
}
