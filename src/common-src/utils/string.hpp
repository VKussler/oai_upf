/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

#ifndef FILE_STRING_HPP_FILE_SEEN
#define FILE_STRING_HPP_FILE_SEEN

#include <arpa/inet.h>

#include <string>
#include "bstrlib.h"

namespace oai::utils {

template<class T>
class Buffer {
 public:
  explicit Buffer(size_t size) {
    msize = size;
    mbuf  = new T[msize];
  }
  ~Buffer() {
    if (mbuf) delete[] mbuf;
  }
  T* get() { return mbuf; }

 private:
  Buffer();
  size_t msize;
  T* mbuf;
};

std::string& ltrim(std::string& s);
// trim from end
std::string& rtrim(std::string& s);
// trim from both ends
std::string& trim(std::string& s);
// extract query param from given querystring
std::string get_query_param(std::string querystring, std::string param);

void string_to_bstring(const std::string& str, bstring bstr);
bool string_to_dotted(const std::string& str, std::string& dotted);
bool dotted_to_string(const std::string& dot, std::string& no_dot);
void string_to_dnn(const std::string& str, bstring bstr);

void ipv4_to_bstring(struct in_addr ipv4_address, bstring str);

void ipv6_to_bstring(struct in6_addr ipv6_address, bstring str);

/*
 * Create a PDU Address Information in form of a bstring (byte 0-7: IPv6 prefix,
 * 8-11: Ipv4 Address)
 * @param [struct in_addr] ipv4_address: IPv4 address
 * @param [struct in6_addr ] ipv6_address: IPv6 address
 * @param [bstring] str: store the PDU Address Information
 * @return void
 */
void ipv4v6_to_pdu_address_information(
    struct in_addr ipv4_address, struct in6_addr ipv6_address, bstring str);

}  // namespace oai::utils
#endif
