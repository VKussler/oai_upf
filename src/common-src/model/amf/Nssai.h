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
/**
 * Nudm_SDM
 * Nudm Subscriber Data Management Service. � 2019, 3GPP Organizational Partners
 * (ARIB, ATIS, CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 2.1.0.alpha-1
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */
/*
 * Nssai.h
 *
 *
 */

#ifndef Nssai_H_
#define Nssai_H_

#include <nlohmann/json.hpp>
#include <string>
#include <vector>

#include "Snssai.h"

namespace oai::model::amf {

/// <summary>
///
/// </summary>
class Nssai {
 public:
  Nssai();
  virtual ~Nssai();

  void validate();

  /////////////////////////////////////////////
  /// Nssai members

  /// <summary>
  ///
  /// </summary>
  std::string getSupportedFeatures() const;
  void setSupportedFeatures(std::string const& value);
  bool supportedFeaturesIsSet() const;
  void unsetSupportedFeatures();
  /// <summary>
  ///
  /// </summary>
  std::vector<oai::model::common::Snssai>& getDefaultSingleNssais();
  void setDefaultSingleNssais(std::vector<oai::model::common::Snssai>& snssais);
  /// <summary>
  ///
  /// </summary>
  std::vector<oai::model::common::Snssai>& getSingleNssais();
  bool singleNssaisIsSet() const;
  void unsetSingleNssais();

  friend void to_json(nlohmann::json& j, const Nssai& o);
  friend void from_json(const nlohmann::json& j, Nssai& o);

 protected:
  std::string m_SupportedFeatures;
  bool m_SupportedFeaturesIsSet;
  std::vector<oai::model::common::Snssai> m_DefaultSingleNssais;

  std::vector<oai::model::common::Snssai> m_SingleNssais;
  bool m_SingleNssaisIsSet;
};

}  // namespace oai::model::amf

#endif /* Nssai_H_ */
