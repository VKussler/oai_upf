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

#ifndef _ABBA_H_
#define _ABBA_H_

#include "Type4NasIe.hpp"

constexpr uint8_t kAbbaMinimumLength = 4;
constexpr uint8_t kAbbaContentMinimumLength =
    kAbbaMinimumLength - 2;  // Minimum length - 2 octets for IEI/Length
constexpr auto kAbbaIeName = "Abba";

namespace oai::nas {

class Abba : public Type4NasIe {
 public:
  Abba();
  Abba(uint8_t iei);
  Abba(uint8_t length, uint8_t* value);
  Abba(uint8_t iei, uint8_t length, uint8_t* value);
  ~Abba();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kAbbaIeName; }

  void Set(uint8_t length, const uint8_t* value);
  void Set(uint8_t iei, uint8_t length, const uint8_t* value);

 private:
  uint8_t value_[256];  // TODO:
};

}  // namespace oai::nas

#endif
