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

#ifndef _LADN_Indication_H_
#define _LADN_Indication_H_

#include "Type6NasIe.hpp"

constexpr uint8_t kLadnIndicationMinimumLength = 3;
constexpr uint8_t kLadnIndicationContentMinimumLength =
    kLadnIndicationMinimumLength -
    3;  // Minimum length - 3 octets for IEI/Length
constexpr uint16_t kLadnIndicationMaximumLength        = 811;
constexpr uint8_t kLadnIndicationMaximumSupportedLadns = 8;
constexpr auto kLadnIndicationIeName                   = "LADN Indication";

namespace oai::nas {

class LadnIndication : public Type6NasIe {
 public:
  LadnIndication();
  LadnIndication(const std::vector<bstring>& ladn);
  ~LadnIndication();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kLadnIndicationIeName; }

  // void SetValue(const std::vector<bstring>& ladn);
  void GetValue(std::vector<bstring>& ladn) const;

 private:
  std::vector<bstring> ladn_;
};

}  // namespace oai::nas

#endif
