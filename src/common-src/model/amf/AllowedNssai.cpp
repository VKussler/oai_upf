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

#include "AllowedNssai.h"
#include "Helpers.h"

#include <sstream>

namespace oai::model::amf {

AllowedNssai::AllowedNssai() {}

void AllowedNssai::validate() const {
  std::stringstream msg;
  // if (!validate(msg))
  // {
  //     throw oai::nssf_server::helpers::ValidationException(msg.str());
  // }
}

bool AllowedNssai::validate(std::stringstream& msg) const {
  return validate(msg, "");
}

bool AllowedNssai::validate(
    std::stringstream& msg, const std::string& pathPrefix) const {
  bool success = true;
  const std::string _pathPrefix =
      pathPrefix.empty() ? "AllowedNssai" : pathPrefix;

  /* AllowedSnssaiList */ {
    const std::vector<AllowedSnssai>& value = m_AllowedSnssaiList;
    const std::string currentValuePath = _pathPrefix + ".allowedSnssaiList";

    if (value.size() < 1) {
      success = false;
      msg << currentValuePath << ": must have at least 1 elements;";
    }
    {  // Recursive validation of array elements
      const std::string oldValuePath = currentValuePath;
      int i                          = 0;
      for (const AllowedSnssai& value : value) {
        const std::string currentValuePath =
            oldValuePath + "[" + std::to_string(i) + "]";

        success =
            value.validate(msg, currentValuePath + ".allowedSnssaiList") &&
            success;

        i++;
      }
    }
  }

  return success;
}

bool AllowedNssai::operator==(const AllowedNssai& rhs) const {
  return

      (getAllowedSnssaiList() == rhs.getAllowedSnssaiList())  // &&

      // (getAccessType() == rhs.getAccessType())

      ;
}

bool AllowedNssai::operator!=(const AllowedNssai& rhs) const {
  return !(*this == rhs);
}

void to_json(nlohmann::json& j, const AllowedNssai& o) {
  j                      = nlohmann::json();
  j["allowedSnssaiList"] = o.m_AllowedSnssaiList;
  j["accessType"]        = o.m_AccessType;
}

void from_json(const nlohmann::json& j, AllowedNssai& o) {
  j.at("allowedSnssaiList").get_to(o.m_AllowedSnssaiList);
  j.at("accessType").get_to(o.m_AccessType);
}

std::vector<AllowedSnssai> AllowedNssai::getAllowedSnssaiList() const {
  return m_AllowedSnssaiList;
}
void AllowedNssai::setAllowedSnssaiList(
    std::vector<AllowedSnssai> const& value) {
  m_AllowedSnssaiList = value;
}
oai::model::common::AccessType AllowedNssai::getAccessType() const {
  return m_AccessType;
}
void AllowedNssai::setAccessType(oai::model::common::AccessType const& value) {
  m_AccessType = value;
}

}  // namespace oai::model::amf
