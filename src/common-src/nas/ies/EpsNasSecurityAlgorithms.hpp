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

#ifndef _EPS_NAS_SECURITY_ALGORITHS_H
#define _EPS_NAS_SECURITY_ALGORITHS_H

#include "Type3NasIe.hpp"

constexpr uint8_t kEpsNasSecurityAlgorithmsLength = 2;
constexpr auto kEpsNasSecurityAlgorithmsIeName = "EPS NAS Security Algorithms";

namespace oai::nas {

class EpsNasSecurityAlgorithms : public Type3NasIe {
 public:
  EpsNasSecurityAlgorithms();
  EpsNasSecurityAlgorithms(uint8_t ciphering, uint8_t integrity_protection);
  ~EpsNasSecurityAlgorithms();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  static std::string GetIeName() { return kEpsNasSecurityAlgorithmsIeName; }
  uint32_t GetIeLength() const override;

  void SetTypeOfCipheringAlgorithm(uint8_t value);
  uint8_t GetTypeOfCipheringAlgorithm() const;

  void SetTypeOfIntegrityProtectionAlgorithm(uint8_t value);
  uint8_t GetTypeOfIntegrityProtectionAlgorithm() const;

  void Set(uint8_t ciphering, uint8_t integrity_protection);
  void Get(uint8_t& ciphering, uint8_t& integrity_protection) const;

 private:
  uint8_t type_of_ciphering_algorithm_;
  uint8_t type_of_integrity_protection_algorithm_;
};

}  // namespace oai::nas

#endif
