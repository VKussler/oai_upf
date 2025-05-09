/**
 * Namf_Communication
 * AMF Communication Service © 2019, 3GPP Organizational Partners (ARIB, ATIS,
 * CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.1.0.alpha-1
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */
/*
 * N1N2MsgTxfrErrDetail.h
 *
 *
 */

#ifndef N1N2MsgTxfrErrDetail_H_
#define N1N2MsgTxfrErrDetail_H_

#include "Arp.h"
#include <nlohmann/json.hpp>

namespace oai::model::amf {

/// <summary>
///
/// </summary>
class N1N2MsgTxfrErrDetail {
 public:
  N1N2MsgTxfrErrDetail();
  virtual ~N1N2MsgTxfrErrDetail();

  void validate();

  /////////////////////////////////////////////
  /// N1N2MsgTxfrErrDetail members

  /// <summary>
  ///
  /// </summary>
  int32_t getRetryAfter() const;
  void setRetryAfter(int32_t const value);
  bool retryAfterIsSet() const;
  void unsetRetryAfter();
  /// <summary>
  ///
  /// </summary>
  oai::model::common::Arp getHighestPrioArp() const;
  void setHighestPrioArp(oai::model::common::Arp const& value);
  bool highestPrioArpIsSet() const;
  void unsetHighestPrioArp();

  friend void to_json(nlohmann::json& j, const N1N2MsgTxfrErrDetail& o);
  friend void from_json(const nlohmann::json& j, N1N2MsgTxfrErrDetail& o);

 protected:
  int32_t m_RetryAfter;
  bool m_RetryAfterIsSet;
  oai::model::common::Arp m_HighestPrioArp;
  bool m_HighestPrioArpIsSet;
};

}  // namespace oai::model::amf

#endif /* N1N2MsgTxfrErrDetail_H_ */
