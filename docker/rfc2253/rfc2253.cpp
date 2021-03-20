// compile with: g++ -std=c++11 rfc2253.cpp -lcrypto -lssl
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
  CHECK(to_rfc2253("/DC=ch/=pippo") == "");
  CHECK(to_rfc2253("/D=ch/CN=pippo") == "");
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
      result += type + '=' + value;
    } else {
      return std::string{};
    }

    it = ++slash_it;
  }

  return result;
}
