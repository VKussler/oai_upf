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

#ifndef _TYPE3_NAS_IE_H_
#define _TYPE3_NAS_IE_H_

#include "NasIe.hpp"

constexpr uint8_t kType3NasIeFormatTvLength = 1;
namespace oai::nas {

class Type3NasIe : public NasIe {
 public:
  Type3NasIe();
  Type3NasIe(uint8_t iei);
  virtual ~Type3NasIe();

  int Encode(uint8_t* buf, int len) const override;
  int Decode(const uint8_t* const buf, int len, bool is_iei = false) override;

  uint32_t GetIeLength() const override;
  bool Validate(int len) const override;

  void SetIei(uint8_t iei);

 protected:
  std::optional<uint8_t> iei_;  // IEI present format TV
};

}  // namespace oai::nas

#endif
