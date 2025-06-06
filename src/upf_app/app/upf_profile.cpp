/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 *file except in compliance with the License. You may obtain a copy of the
 *License at
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

/*! \file upf_nf_profile.cpp
 \brief
 \author  Tien-Thinh NGUYEN
 \company Eurecom
 \date 2021
 \email: Tien-Thinh.Nguyen@eurecom.fr
 */

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

#include "logger.hpp"
#include "upf_profile.hpp"
#include "string.hpp"
#include "3gpp_conversions.hpp"

using namespace oai::upf::app;

//------------------------------------------------------------------------------
void upf_nf_profile::set_nf_instance_id(const std::string& instance_id) {
  nf_instance_id = instance_id;
}

//------------------------------------------------------------------------------
void upf_nf_profile::get_nf_instance_id(std::string& instance_id) const {
  instance_id = nf_instance_id;
}

//------------------------------------------------------------------------------
std::string upf_nf_profile::get_nf_instance_id() const {
  return nf_instance_id;
}

//------------------------------------------------------------------------------
void upf_nf_profile::set_nf_instance_name(const std::string& instance_name) {
  nf_instance_name = instance_name;
}

//------------------------------------------------------------------------------
void upf_nf_profile::get_nf_instance_name(std::string& instance_name) const {
  instance_name = nf_instance_name;
}

//------------------------------------------------------------------------------
std::string upf_nf_profile::get_nf_instance_name() const {
  return nf_instance_name;
}

//------------------------------------------------------------------------------
void upf_nf_profile::set_nf_type(const std::string& type) {
  nf_type = type;
}

//------------------------------------------------------------------------------
std::string upf_nf_profile::get_nf_type() const {
  return nf_type;
}
//------------------------------------------------------------------------------
void upf_nf_profile::set_nf_status(const std::string& status) {
  nf_status = status;
}

//------------------------------------------------------------------------------
void upf_nf_profile::get_nf_status(std::string& status) const {
  status = nf_status;
}

//------------------------------------------------------------------------------
std::string upf_nf_profile::get_nf_status() const {
  return nf_status;
}

//------------------------------------------------------------------------------
void upf_nf_profile::set_nf_heartBeat_timer(const int32_t& timer) {
  heartBeat_timer = timer;
}

//------------------------------------------------------------------------------
void upf_nf_profile::get_nf_heartBeat_timer(int32_t& timer) const {
  timer = heartBeat_timer;
}

//------------------------------------------------------------------------------
int32_t upf_nf_profile::get_nf_heartBeat_timer() const {
  return heartBeat_timer;
}

//------------------------------------------------------------------------------
void upf_nf_profile::set_nf_priority(const uint16_t& p) {
  priority = p;
}

//------------------------------------------------------------------------------
void upf_nf_profile::get_nf_priority(uint16_t& p) const {
  p = priority;
}

//------------------------------------------------------------------------------
uint16_t upf_nf_profile::get_nf_priority() const {
  return priority;
}

//------------------------------------------------------------------------------
void upf_nf_profile::set_nf_capacity(const uint16_t& c) {
  capacity = c;
}

//------------------------------------------------------------------------------
void upf_nf_profile::get_nf_capacity(uint16_t& c) const {
  c = capacity;
}

//------------------------------------------------------------------------------
uint16_t upf_nf_profile::get_nf_capacity() const {
  return capacity;
}

//------------------------------------------------------------------------------
void upf_nf_profile::set_nf_snssais(const std::vector<snssai_t>& s) {
  snssais = s;
}

//------------------------------------------------------------------------------
void upf_nf_profile::get_nf_snssais(std::vector<snssai_t>& s) const {
  s = snssais;
}

//------------------------------------------------------------------------------
void upf_nf_profile::add_snssai(const snssai_t& s) {
  snssais.push_back(s);
}

//------------------------------------------------------------------------------
void upf_nf_profile::set_fqdn(const std::string& fqdN) {
  fqdn = fqdN;
}

//------------------------------------------------------------------------------
std::string upf_nf_profile::get_fqdn() const {
  return fqdn;
}

//------------------------------------------------------------------------------
void upf_nf_profile::set_nf_ipv4_addresses(
    const std::vector<struct in_addr>& a) {
  ipv4_addresses = a;
}

//------------------------------------------------------------------------------
void upf_nf_profile::add_nf_ipv4_addresses(const struct in_addr& a) {
  ipv4_addresses.push_back(a);
}
//------------------------------------------------------------------------------
void upf_nf_profile::get_nf_ipv4_addresses(
    std::vector<struct in_addr>& a) const {
  a = ipv4_addresses;
}

//------------------------------------------------------------------------------
void upf_nf_profile::set_upf_info(const upf_info_t& s) {
  upf_info = s;
}

//------------------------------------------------------------------------------
void upf_nf_profile::add_upf_info_item(const snssai_upf_info_item_t& s) {
  upf_info.snssai_upf_info_list.push_back(s);
}

//------------------------------------------------------------------------------
void upf_nf_profile::get_upf_info(upf_info_t& s) const {
  s = upf_info;
}

//------------------------------------------------------------------------------
void upf_nf_profile::display() const {
  Logger::upf_app().debug("- NF instance info");
  Logger::upf_app().debug("    Instance ID: %s", nf_instance_id.c_str());
  Logger::upf_app().debug("    Instance name: %s", nf_instance_name.c_str());
  Logger::upf_app().debug("    Instance type: %s", nf_type.c_str());
  Logger::upf_app().debug("    Instance fqdn: %s", fqdn.c_str());
  Logger::upf_app().debug("    Status: %s", nf_status.c_str());
  Logger::upf_app().debug("    HeartBeat timer: %d", heartBeat_timer);
  Logger::upf_app().debug("    Priority: %d", priority);
  Logger::upf_app().debug("    Capacity: %d", capacity);
  // SNSSAIs
  if (snssais.size() > 0) {
    Logger::upf_app().debug("    SNSSAI:");
  }
  for (auto s : snssais) {
    Logger::upf_app().debug("        SST, SD: %d, %s", s.sst, s.sd.c_str());
  }

  // IPv4 Addresses
  if (ipv4_addresses.size() > 0) {
    Logger::upf_app().debug("    IPv4 Addr:");
  }
  for (auto address : ipv4_addresses) {
    Logger::upf_app().debug("        %s", inet_ntoa(address));
  }

  // UPF info
  if (upf_info.snssai_upf_info_list.size() > 0) {
    Logger::upf_app().debug("    UPF Info:");
  }
  for (auto s : upf_info.snssai_upf_info_list) {
    Logger::upf_app().debug(
        "        SNSSAI (SST %d, SD %s)", s.snssai.sst, s.snssai.sd.c_str());
    for (auto d : s.dnn_upf_info_list) {
      Logger::upf_app().debug("            DNN %s", d.dnn.c_str());
    }
  }
}

//------------------------------------------------------------------------------
void upf_nf_profile::to_json(nlohmann::json& data) const {
  data["nfInstanceId"]   = nf_instance_id;
  data["nfInstanceName"] = nf_instance_name;
  data["nfType"]         = nf_type;
  data["nfStatus"]       = nf_status;
  data["heartBeatTimer"] = heartBeat_timer;
  // SNSSAIs
  data["sNssais"] = nlohmann::json::array();
  for (auto s : snssais) {
    nlohmann::json tmp = {};
    tmp["sst"]         = s.sst;
    tmp["sd"]          = s.sd;
    data["sNssais"].push_back(tmp);
  }
  data["fqdn"] = fqdn;
  // ipv4_addresses
  data["ipv4Addresses"] = nlohmann::json::array();
  for (auto address : ipv4_addresses) {
    nlohmann::json tmp = inet_ntoa(address);
    data["ipv4Addresses"].push_back(tmp);
  }

  data["priority"] = priority;
  data["capacity"] = capacity;

  // UPF info
  data["upfInfo"]                      = {};
  data["upfInfo"]["sNssaiUpfInfoList"] = nlohmann::json::array();
  for (auto s : upf_info.snssai_upf_info_list) {
    nlohmann::json tmp    = {};
    tmp["sNssai"]["sst"]  = s.snssai.sst;
    tmp["sNssai"]["sd"]   = s.snssai.sd;
    tmp["dnnUpfInfoList"] = nlohmann::json::array();
    for (auto d : s.dnn_upf_info_list) {
      nlohmann::json dnn_json = {};
      dnn_json["dnn"]         = d.dnn;
      tmp["dnnUpfInfoList"].push_back(dnn_json);
    }
    data["upfInfo"]["sNssaiUpfInfoList"].push_back(tmp);
  }

  Logger::upf_app().debug("UPF profile to JSON:\n %s", data.dump().c_str());
}

//------------------------------------------------------------------------------
void upf_nf_profile::from_json(const nlohmann::json& data) {
  if (data.find("nfInstanceId") != data.end()) {
    nf_instance_id = data["nfInstanceId"].get<std::string>();
  }

  if (data.find("nfInstanceName") != data.end()) {
    nf_instance_name = data["nfInstanceName"].get<std::string>();
  }

  if (data.find("nfType") != data.end()) {
    nf_type = data["nfType"].get<std::string>();
  }

  if (data.find("nfStatus") != data.end()) {
    nf_status = data["nfStatus"].get<std::string>();
  }

  if (data.find("heartBeatTimer") != data.end()) {
    heartBeat_timer = data["heartBeatTimer"].get<int>();
  }
  // sNssais
  if (data.find("sNssais") != data.end()) {
    for (auto it : data["sNssais"]) {
      snssai_t s = {};
      if (it["sNssai"].find("sst") != it["sNssai"].end()) {
        s.sst = it["sNssai"]["sst"].get<int>();
        if (it["sNssai"].find("sd") != it["sNssai"].end()) {
          s.sd = it["sNssai"]["sd"].get<std::string>();
        }
        snssais.push_back(s);
      }
    }
  }

  if (data.find("ipv4Addresses") != data.end()) {
    nlohmann::json addresses = data["ipv4Addresses"];

    ipv4_addresses.clear(); // Clear the existing list first
    for (auto it : addresses) {
      struct in_addr addr4 = {};
      std::string address  = it.get<std::string>();
      unsigned char buf_in_addr[sizeof(struct in_addr)];
      if (inet_pton(AF_INET, oai::utils::trim(address).c_str(), buf_in_addr) ==
          1) {
        memcpy(&addr4, buf_in_addr, sizeof(struct in_addr));
      } else {
        Logger::upf_app().warn(
            "Address conversion: Bad value %s",
            oai::utils::trim(address).c_str());
      }
      add_nf_ipv4_addresses(addr4);
    }
  }

  if (data.find("priority") != data.end()) {
    priority = data["priority"].get<int>();
  }

  if (data.find("capacity") != data.end()) {
    capacity = data["capacity"].get<int>();
  }

  // UPF info
  upf_info.snssai_upf_info_list.clear();
  if (data.find("upfInfo") != data.end()) {
    nlohmann::json info = data["upfInfo"];

    if (info.find("sNssaiUpfInfoList") != info.end()) {
      nlohmann::json snssai_upf_info_list = info["sNssaiUpfInfoList"];

      for (auto it : snssai_upf_info_list) {
        snssai_upf_info_item_t upf_info_item = {};
        bool found_snssai                    = false;
        if (it.find("sNssai") != it.end()) {
          if (it["sNssai"].find("sst") != it["sNssai"].end()) {
            upf_info_item.snssai.sst = it["sNssai"]["sst"].get<int>();
            found_snssai             = true;
            if (it["sNssai"].find("sd") != it["sNssai"].end()) {
              upf_info_item.snssai.sd = it["sNssai"]["sd"].get<std::string>();
            }
          }
        }
        if (it.find("dnnUpfInfoList") != it.end()) {
          for (auto d : it["dnnUpfInfoList"]) {
            if (d.find("dnn") != d.end()) {
              dnn_upf_info_item_t dnn_item = {};
              dnn_item.dnn                 = d["dnn"].get<std::string>();
              upf_info_item.dnn_upf_info_list.insert(dnn_item);
            }
          }
        }
        if (found_snssai)
          upf_info.snssai_upf_info_list.push_back(upf_info_item);
      }
    }
  }

  display();
}

//------------------------------------------------------------------------------
void upf_nf_profile::handle_heartbeart_timeout(uint64_t ms) {
  Logger::upf_app().info(
      "Handle heartbeart timeout profile %s, time %d", nf_instance_id.c_str(),
      ms);
  set_nf_status("SUSPENDED");
}
