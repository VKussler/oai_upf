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

#include "N2InformationNotification.h"

namespace oai::model::amf {

N2InformationNotification::N2InformationNotification() {
  m_N2NotifySubscriptionId    = "";
  m_N2InfoContainerIsSet      = false;
  m_ToReleaseSessionListIsSet = false;
  m_LcsCorrelationId          = "";
  m_LcsCorrelationIdIsSet     = false;
  m_NotifyReasonIsSet         = false;
  m_SmfChangeIndIsSet         = false;
}

N2InformationNotification::~N2InformationNotification() {}

void N2InformationNotification::validate() {
  // TODO: implement validation
}

void to_json(nlohmann::json& j, const N2InformationNotification& o) {
  j                           = nlohmann::json();
  j["n2NotifySubscriptionId"] = o.m_N2NotifySubscriptionId;
  if (o.n2InfoContainerIsSet()) j["n2InfoContainer"] = o.m_N2InfoContainer;
  if (o.toReleaseSessionListIsSet())
    j["toReleaseSessionList"] = o.m_ToReleaseSessionList;
  if (o.lcsCorrelationIdIsSet()) j["lcsCorrelationId"] = o.m_LcsCorrelationId;
  if (o.notifyReasonIsSet()) j["notifyReason"] = o.m_NotifyReason;
  if (o.smfChangeIndIsSet()) j["smfChangeInd"] = o.m_SmfChangeInd;
}

void from_json(const nlohmann::json& j, N2InformationNotification& o) {
  j.at("n2NotifySubscriptionId").get_to(o.m_N2NotifySubscriptionId);
  if (j.find("n2InfoContainer") != j.end()) {
    j.at("n2InfoContainer").get_to(o.m_N2InfoContainer);
    o.m_N2InfoContainerIsSet = true;
  }
  if (j.find("toReleaseSessionList") != j.end()) {
    j.at("toReleaseSessionList").get_to(o.m_ToReleaseSessionList);
    o.m_ToReleaseSessionListIsSet = true;
  }
  if (j.find("lcsCorrelationId") != j.end()) {
    j.at("lcsCorrelationId").get_to(o.m_LcsCorrelationId);
    o.m_LcsCorrelationIdIsSet = true;
  }
  if (j.find("notifyReason") != j.end()) {
    j.at("notifyReason").get_to(o.m_NotifyReason);
    o.m_NotifyReasonIsSet = true;
  }
  if (j.find("smfChangeInd") != j.end()) {
    j.at("smfChangeInd").get_to(o.m_SmfChangeInd);
    o.m_SmfChangeIndIsSet = true;
  }
}

std::string N2InformationNotification::getN2NotifySubscriptionId() const {
  return m_N2NotifySubscriptionId;
}
void N2InformationNotification::setN2NotifySubscriptionId(
    std::string const& value) {
  m_N2NotifySubscriptionId = value;
}
N2InfoContainer N2InformationNotification::getN2InfoContainer() const {
  return m_N2InfoContainer;
}
void N2InformationNotification::setN2InfoContainer(
    N2InfoContainer const& value) {
  m_N2InfoContainer      = value;
  m_N2InfoContainerIsSet = true;
}
bool N2InformationNotification::n2InfoContainerIsSet() const {
  return m_N2InfoContainerIsSet;
}
void N2InformationNotification::unsetN2InfoContainer() {
  m_N2InfoContainerIsSet = false;
}
std::vector<int32_t>& N2InformationNotification::getToReleaseSessionList() {
  return m_ToReleaseSessionList;
}
bool N2InformationNotification::toReleaseSessionListIsSet() const {
  return m_ToReleaseSessionListIsSet;
}
void N2InformationNotification::unsetToReleaseSessionList() {
  m_ToReleaseSessionListIsSet = false;
}
std::string N2InformationNotification::getLcsCorrelationId() const {
  return m_LcsCorrelationId;
}
void N2InformationNotification::setLcsCorrelationId(std::string const& value) {
  m_LcsCorrelationId      = value;
  m_LcsCorrelationIdIsSet = true;
}
bool N2InformationNotification::lcsCorrelationIdIsSet() const {
  return m_LcsCorrelationIdIsSet;
}
void N2InformationNotification::unsetLcsCorrelationId() {
  m_LcsCorrelationIdIsSet = false;
}
N2InfoNotifyReason N2InformationNotification::getNotifyReason() const {
  return m_NotifyReason;
}
void N2InformationNotification::setNotifyReason(
    N2InfoNotifyReason const& value) {
  m_NotifyReason      = value;
  m_NotifyReasonIsSet = true;
}
bool N2InformationNotification::notifyReasonIsSet() const {
  return m_NotifyReasonIsSet;
}
void N2InformationNotification::unsetNotifyReason() {
  m_NotifyReasonIsSet = false;
}
SmfChangeIndication N2InformationNotification::getSmfChangeInd() const {
  return m_SmfChangeInd;
}
void N2InformationNotification::setSmfChangeInd(
    SmfChangeIndication const& value) {
  m_SmfChangeInd      = value;
  m_SmfChangeIndIsSet = true;
}
bool N2InformationNotification::smfChangeIndIsSet() const {
  return m_SmfChangeIndIsSet;
}
void N2InformationNotification::unsetSmfChangeInd() {
  m_SmfChangeIndIsSet = false;
}

}  // namespace oai::model::amf
