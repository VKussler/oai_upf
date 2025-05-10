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

#include "upf_config_yaml.hpp"

#include <boost/algorithm/string.hpp>
#include <regex>
#include <sstream>

#include "conv.hpp"
#include "conversions.hpp"
#include "fqdn.hpp"
#include "logger.hpp"
#include <nlohmann/json.hpp>
#include "yaml-cpp/yaml.h"
#include "upf_pfcp_association.hpp"
#include "pfcp.hpp"
#include "upf_nrf.hpp"

// Forward declaration or include for upf_nrf if not already present
// Likely upf_nrf.hpp should be included if upf_nrf_inst is used.
// #include "upf_nrf.hpp" // Might be needed here

// Assuming upf_nrf_inst is an accessible global/static pointer to the upf_nrf instance
extern oai::upf::app::upf_nrf* upf_nrf_inst;

namespace oai::config {

//------------------------------------------------------------------------------
upf_support_features::upf_support_features(
    bool enable_bpf_datapath, bool enable_qos, bool enable_snat) {
  m_config_name = "Supported Features";

  m_enable_bpf_datapath = option_config_value(
      UPF_CONFIG_SUPPORT_FEATURES_ENABLE_BPF_LABEL, enable_bpf_datapath);

  m_enable_qos = option_config_value(
      UPF_CONFIG_SUPPORT_FEATURES_ENABLE_QOS_LABEL, enable_qos);

  m_enable_snat = option_config_value(
      UPF_CONFIG_SUPPORT_FEATURES_ENABLE_SNAT_LABEL, enable_snat);
}

//------------------------------------------------------------------------------
void upf_support_features::from_yaml(const YAML::Node& node) {
  if (node[UPF_CONFIG_SUPPORT_FEATURES_ENABLE_BPF]) {
    m_enable_bpf_datapath.from_yaml(
        node[UPF_CONFIG_SUPPORT_FEATURES_ENABLE_BPF]);
  }

  if (node[UPF_CONFIG_SUPPORT_FEATURES_ENABLE_QOS]) {
    m_enable_qos.from_yaml(node[UPF_CONFIG_SUPPORT_FEATURES_ENABLE_QOS]);
  }

  if (node[UPF_CONFIG_SUPPORT_FEATURES_ENABLE_SNAT]) {
    m_enable_snat.from_yaml(node[UPF_CONFIG_SUPPORT_FEATURES_ENABLE_SNAT]);
  }
}

//------------------------------------------------------------------------------
std::string upf_support_features::to_string(const std::string& indent) const {
  std::string out;
  unsigned int inner_width = get_inner_width(indent.length());

  // Enable BPF
  std::string enable_bpf_datapath = m_enable_bpf_datapath.get_value() ?
                                        UPF_CONFIG_OPTION_YES_STR :
                                        UPF_CONFIG_OPTION_NO_STR;
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, INNER_LIST_ELEM,
      UPF_CONFIG_SUPPORT_FEATURES_ENABLE_BPF_LABEL, inner_width,
      enable_bpf_datapath));

  // Enable QoS
  std::string enable_qos = m_enable_qos.get_value() ?
                               UPF_CONFIG_OPTION_YES_STR :
                               UPF_CONFIG_OPTION_NO_STR;
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, INNER_LIST_ELEM,
      UPF_CONFIG_SUPPORT_FEATURES_ENABLE_QOS_LABEL, inner_width, enable_qos));

  // Enable SNAT
  std::string enable_snat = m_enable_snat.get_value() ?
                                UPF_CONFIG_OPTION_YES_STR :
                                UPF_CONFIG_OPTION_NO_STR;
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, INNER_LIST_ELEM,
      UPF_CONFIG_SUPPORT_FEATURES_ENABLE_SNAT_LABEL, inner_width, enable_snat));
  return out;
}

//------------------------------------------------------------------------------
upf::upf(
    const std::string& name, const std::string& host, const sbi_interface& sbi,
    const std::map<std::string, upf_interface_config>& interfaces)
    : nf(name, host, sbi),
      m_instance_id(UPF_CONFIG_INSTANCE_ID_LABEL, 0),
      m_upf_support_features(false, false, false),
      m_remote_n6(UPF_CONFIG_REMOTE_N6_GW_LABEL, ""),
      m_interfaces(interfaces) {
  set_config_name(name);
  oai::model::nrf::SnssaiUpfInfoItem item;
  item.setSNssai(DEFAULT_SNSSAI);
  item.setDnnUpfInfoList(DEFAULT_DNN_LIST);
  m_upf_info.setSNssaiUpfInfoList(
      std::vector<oai::model::nrf::SnssaiUpfInfoItem>{item});
}

//------------------------------------------------------------------------------
bool upf::parse_and_validate_upf_info(const YAML::Node& upf_info_yaml_node, oai::model::nrf::UpfInfo& target_upf_info) {
    if (!upf_info_yaml_node || !upf_info_yaml_node.IsMap()) {
        Logger::system().error("UPF Info YAML node is not a valid map or is missing for parsing.\\n");
        return false;
    }

    try {
        nlohmann::json upf_info_json = oai::utils::conversions::yaml_to_json(upf_info_yaml_node, false);
        nlohmann::from_json(upf_info_json, target_upf_info);

        std::stringstream validation_ss_msg;
        if (!target_upf_info.validate(validation_ss_msg)) {
            Logger::system().error("Validation failed for parsed UpfInfo: {}\\n", validation_ss_msg.str());
            return false;
        }
        Logger::system().info("Successfully parsed and validated UpfInfo from YAML node.\\n");
        return true;

    } catch (const YAML::Exception& e) {
        Logger::system().error("YAML parsing exception while processing UpfInfo: {}\\n", e.what());
        return false;
    } catch (const nlohmann::json::exception& e) {
        Logger::system().error("JSON processing exception while processing UpfInfo (from YAML conversion): {}\\n", e.what());
        return false;
    } catch (const std::exception& e) {
        Logger::system().error("Standard exception while processing UpfInfo: {}\\n", e.what());
        return false;
    }
    return false;
}

//------------------------------------------------------------------------------
void upf::from_yaml(const YAML::Node& node) {
  nf::from_yaml(node);
  create_or_update_interface(
      UPF_CONFIG_N3_LABEL, node, upf_config_yaml::get_default_n3_interface());
  create_or_update_interface(
      UPF_CONFIG_N4_LABEL, node, upf_config_yaml::get_default_n4_interface());
  create_or_update_interface(
      UPF_CONFIG_N6_LABEL, node, upf_config_yaml::get_default_n6_interface());

  // Iterate through top-level keys of the 'upf' specific section of config
  for (const auto& elem : node) {
    auto key = elem.first.as<std::string>();

    if (key == UPF_CONFIG_INSTANCE_ID) {
      m_instance_id.from_yaml(elem.second);
    }

    if (key == UPF_CONFIG_SUPPORT_FEATURES) {
      m_upf_support_features.from_yaml(elem.second);
    }

    if (key == UPF_CONFIG_REMOTE_N6_GW) {
      m_remote_n6.from_yaml(elem.second);
    }

    if (key == UPF_CONFIG_SMF_LIST) {
      m_smf_list.clear(); // Clear previous list if any
      for (const auto& yaml_sub : elem.second) { // elem.second should be the list node for SMFs
        string_config_value m_smf_host_cfg_val(key+"_host", ""); // Temporary config value
        if (yaml_sub["host"]) {
          m_smf_host_cfg_val.from_yaml(yaml_sub["host"]);
          m_smf_list.push_back(m_smf_host_cfg_val);
        }
      }
    }

    if (key == UPF_CONFIG_UPF_INFO) {
        // Use the new helper function for initial loading as well to keep logic centralized
        // Lock not strictly needed here if from_yaml is guaranteed to be called only during
        // single-threaded initialization phase.
        oai::model::nrf::UpfInfo temp_initial_upf_info;
        if (parse_and_validate_upf_info(elem.second, temp_initial_upf_info)) {
            m_upf_info = temp_initial_upf_info; // Assign to the member
        } else {
            Logger::system().error("Failed to parse initial UpfInfo from configuration. UPF Info might use defaults or be empty.\\n");
            // m_upf_info retains its constructor-initialized default value
        }
    }
  }
}

//------------------------------------------------------------------------------
std::string upf::to_string(const std::string& indent) const {
  std::string out          = nf::to_string("");
  unsigned int inner_width = get_inner_width(indent.length());
  std::string inner_indent = add_indent(indent);

  for (const auto& iface : m_interfaces) {
    out.append(indent).append(fmt::format(
        "{} {}:\n", OUTER_LIST_ELEM, iface.second.get_config_name()));
    out.append(iface.second.to_string(inner_indent));
  }

  out.append(indent).append(fmt::format(
      BASE_FORMATTER, OUTER_LIST_ELEM, UPF_CONFIG_INSTANCE_ID_LABEL,
      inner_width, m_instance_id.get_value()));

  out.append(indent).append(fmt::format(
      BASE_FORMATTER, OUTER_LIST_ELEM, UPF_CONFIG_REMOTE_N6_GW_LABEL,
      inner_width, m_remote_n6.get_value()));

  out.append(indent).append(fmt::format(
      "{} {}:\n", OUTER_LIST_ELEM, UPF_CONFIG_SUPPORT_FEATURES_LABEL));
  out.append(m_upf_support_features.to_string(inner_indent));

  out.append(m_upf_info.to_string(1));

  return out;
}

//------------------------------------------------------------------------------
uint32_t upf::get_instance_id() const {
  return m_instance_id.get_value();
}

//------------------------------------------------------------------------------
std::string upf::get_remote_n6() const {
  return m_remote_n6.get_value();
}

//------------------------------------------------------------------------------
std::vector<string_config_value> upf::get_smf_list() const {
  return m_smf_list;
}

//------------------------------------------------------------------------------
bool upf_support_features::get_option_enable_bpf_datapath() const {
  return m_enable_bpf_datapath.get_value();
}

//------------------------------------------------------------------------------
bool upf_support_features::get_option_enable_qos() const {
  return m_enable_qos.get_value();
}

//------------------------------------------------------------------------------
bool upf_support_features::get_option_enable_snat() const {
  return m_enable_snat.get_value();
}

//------------------------------------------------------------------------------
const upf_support_features& upf::get_support_features() const {
  return m_upf_support_features;
}

//------------------------------------------------------------------------------
oai::model::nrf::UpfInfo upf::get_upf_info() const {
  std::lock_guard<std::mutex> lock(m_upf_info_mutex);
  return m_upf_info;
}

const std::map<std::string, upf_interface_config>& upf::get_interfaces() const {
  return m_interfaces;
}

void upf::create_or_update_interface(
    const std::string& iface_type, const YAML::Node& node,
    const upf_interface_config& default_config) {
  if (node[iface_type]) {
    auto n3 = m_interfaces.find(iface_type);
    if (n3 == m_interfaces.end()) {
      // we use the default values as template, YAML only overwrites these
      upf_interface_config new_cfg = default_config;
      new_cfg.from_yaml(node[iface_type]);
      m_interfaces.insert(std::make_pair(iface_type, new_cfg));
    } else {
      n3->second.from_yaml(node[iface_type]);
    }
  }
}

void upf::validate() {
  nf::validate();
  m_upf_support_features.validate();
  for (auto& iface : m_interfaces) {
    iface.second.validate();
  }
  std::stringstream upf_info_validation_ss;
  if (!m_upf_info.validate(upf_info_validation_ss)) {
      throw std::runtime_error("UPF Info validation failed: " + upf_info_validation_ss.str());
  }
}

//------------------------------------------------------------------------------
upf_config_yaml::upf_config_yaml(
    const std::string& config_path, bool log_stdout, bool log_rot_file)
    : oai::config::config(
          config_path, oai::config::UPF_CONFIG_NAME, log_stdout, log_rot_file) {
  m_used_sbi_values = {
      oai::config::UPF_CONFIG_NAME, oai::config::SMF_CONFIG_NAME,
      oai::config::NRF_CONFIG_NAME};
  m_used_config_values = {
      oai::config::LOG_LEVEL_CONFIG_NAME, oai::config::REGISTER_NF_CONFIG_NAME,
      oai::config::NF_CONFIG_HTTP_NAME,   oai::config::NF_LIST_CONFIG_NAME,
      oai::config::UPF_CONFIG_NAME,       oai::config::DNNS_CONFIG_NAME};

  m_nf_name = UPF_CONFIG_NAME;

  // TODO with NF_Type and switch
  // TODO: Still we need to add default NFs even we don't use this in all_in_one
  // use case
  std::map<std::string, upf_interface_config> ifaces;
  ifaces.insert(
      std::make_pair(UPF_CONFIG_N3_LABEL, get_default_n3_interface()));
  ifaces.insert(
      std::make_pair(UPF_CONFIG_N4_LABEL, get_default_n4_interface()));
  ifaces.insert(
      std::make_pair(UPF_CONFIG_N6_LABEL, get_default_n6_interface()));

  auto m_upf = std::make_shared<upf>(
      "UPF Configuration", "oai-upf",
      sbi_interface("SBI", "oai-upf", 80, "v1", "eth0"), ifaces);
  add_nf(oai::config::UPF_CONFIG_NAME, m_upf);

  auto m_smf = std::make_shared<nf>(
      "SMF", "oai-smf", sbi_interface("SBI", "oai-smf", 80, "v1", "eth0"));
  add_nf(oai::config::SMF_CONFIG_NAME, m_smf);

  auto m_nrf = std::make_shared<nf>(
      "NRF", "oai-nrf", sbi_interface("SBI", "oai-nrf", 80, "v1", "eth0"));
  add_nf(oai::config::NRF_CONFIG_NAME, m_nrf);

  // DNN default values
  dnn_config dnn("default", "IPV4", "12.1.1.0/24", "");
  m_dnns.push_back(dnn);

  update_used_nfs();
}

//------------------------------------------------------------------------------
upf_config_yaml::~upf_config_yaml() {}

void upf_config_yaml::pre_process() {
  // Process configuration information to display only the appropriate
  // information
  // TODO
  std::shared_ptr<upf> upf_local = std::static_pointer_cast<upf>(get_local());
  std::shared_ptr<nf> smf        = get_nf(SMF_CONFIG_NAME);
  smf->set_config();
  std::shared_ptr<nf> nrf = get_nf(NRF_CONFIG_NAME);
  nrf->set_config();
}

//------------------------------------------------------------------------------
in_addr upf_config_yaml::resolve_nf(const std::string& host) {
  // we remove use_fqdn_dns towards the user, if it is an IPv4 we don't resolve
  std::regex re(IPV4_ADDRESS_VALIDATOR_REGEX);
  if (!std::regex_match(host, re)) {
    logger::logger_registry::get_logger(LOGGER_NAME)
        .info("Configured host %s is an FQDN. Resolve on NF startup", host);
    std::string ip_address;
    // we ignore the port for now
    uint32_t port;
    uint8_t addr_type;
    fqdn::resolve(host, ip_address, port, addr_type);
    if (addr_type != 0) {
      // TODO:
      throw std::invalid_argument(fmt::format(
          "IPv6 is not supported at the moment. Please provide a valid IPv4 "
          "address in your DNS configuration for the host {}.",
          host));
    }
    return oai::utils::conv::fromString(ip_address);
  }
  return oai::utils::conv::fromString(host);
}

//------------------------------------------------------------------------------
void upf_config_yaml::to_upf_config(upf_config& cfg) {
  std::shared_ptr<upf> upf_local = std::static_pointer_cast<upf>(get_local());
  cfg.instance                   = upf_local->get_instance_id();
  cfg.log_level                  = spdlog::level::from_str(log_level());
  cfg.register_nrf               = register_nrf();
  cfg.http_request_timeout       = get_http_request_timeout();

  std::string remote_n6_addr;
  uint8_t addr_type = {};
  unsigned int port = 0;
  fqdn::resolve(upf_local->get_remote_n6(), remote_n6_addr, port, addr_type);
  if (addr_type != 0) {  // IPv6: TODO
    throw("DO NOT SUPPORT IPV6 ADDR FOR NRF!");
  } else {  // IPv4
    IPV4_STR_ADDR_TO_INADDR(
        oai::utils::trim(remote_n6_addr).c_str(), cfg.remote_n6,
        "BAD IPv4 ADDRESS FORMAT FOR N6 DN !");
  }

  if (!cfg.register_nrf) {
    std::vector<string_config_value> smf_list = upf_local->get_smf_list();
    for (const auto& smf_host : smf_list) {
      std::string smf_addr;
      uint8_t addr_type = {};
      pfcp::node_id_t n = {};
      unsigned int port = 0;
      n.node_id_type    = pfcp::NODE_ID_TYPE_IPV4_ADDRESS;  // actually
      fqdn::resolve(smf_host.get_value(), smf_addr, port, addr_type);
      if (addr_type != 0) {  // IPv6: TODO
        throw("DO NOT SUPPORT IPV6 ADDR FOR SMF!");
      } else {  // IPv4
        IPV4_STR_ADDR_TO_INADDR(
            oai::utils::trim(smf_addr).c_str(), n.u1.ipv4_address,
            "BAD IPv4 ADDRESS FORMAT FOR SMF !");
      }
      cfg.smfs.push_back(n);
    }
  }

  if (get_nf(NRF_CONFIG_NAME)->is_set() & register_nrf()) {
    cfg.nrf_addr = get_nf(NRF_CONFIG_NAME)->get_sbi();
  }

  cfg.http_version = get_http_version();

  cfg.sbi.port    = local().get_sbi().get_port();
  cfg.sbi.addr4   = local().get_sbi().get_addr4();
  cfg.sbi.if_name = local().get_sbi().get_if_name();

  cfg.enable_bpf_datapath =
      upf_local->get_support_features().get_option_enable_bpf_datapath();
  cfg.enable_qos  = upf_local->get_support_features().get_option_enable_qos();
  cfg.enable_snat = upf_local->get_support_features().get_option_enable_snat();

  auto snssai_upf_list = upf_local->get_upf_info().getSNssaiUpfInfoList();
  for (const auto& snssai : snssai_upf_list) {
    snssai_upf_info_item_t item;
    item.snssai.sd  = snssai.getSNssai().getSd();
    item.snssai.sst = snssai.getSNssai().getSst();
    for (const auto& dnn : snssai.getDnnUpfInfoList()) {
      dnn_upf_info_item_t dnn_item = {};
      dnn_item.dnn                 = dnn.getDnn();
      item.dnn_upf_info_list.insert(dnn_item);
    }
    cfg.upf_info.snssai_upf_info_list.push_back(item);
  }

  // ToDo: Remove hardcoded pdn value here
  for (const auto& cfg_dnn : get_dnns()) {
    pdn_cfg_t pdn_cfg = {};
    unsigned char buf_in_addr[sizeof(struct in_addr) + 1];
    inet_pton(AF_INET, inet_ntoa(cfg_dnn.get_ipv4_subnet()), buf_in_addr);
    memcpy(&pdn_cfg.network_ipv4, buf_in_addr, sizeof(struct in_addr));
    pdn_cfg.prefix_ipv4          = cfg_dnn.get_ipv4_subnet_prefix();
    pdn_cfg.network_ipv4_be      = htobe32(pdn_cfg.network_ipv4.s_addr);
    pdn_cfg.network_mask_ipv4    = 0xFFFFFFFF << (32 - pdn_cfg.prefix_ipv4);
    pdn_cfg.network_mask_ipv4_be = htobe32(pdn_cfg.network_mask_ipv4);
    logger::logger_registry::get_logger(LOGGER_NAME)
        .debug(
            "PDN Network validation for UE Subnet:  %s ",
            oai::utils::conv::toString(cfg_dnn.get_ipv4_subnet()));
    logger::logger_registry::get_logger(LOGGER_NAME)
        .debug(
            "IP Pool :  %s - %s",
            oai::utils::conv::toString(cfg_dnn.get_ipv4_pool_start()),
            oai::utils::conv::toString(cfg_dnn.get_ipv4_pool_end()));
    cfg.pdns.push_back(pdn_cfg);
  }

  // we set the local interfaces and also the UPF profile
  for (const auto& iface : upf_local->get_interfaces()) {
    if (iface.first == UPF_CONFIG_N3_LABEL) {
      cfg.n3 = iface.second.to_interface_config();
    } else if (iface.first == UPF_CONFIG_N6_LABEL) {
      cfg.n6 = iface.second.to_interface_config();
    } else if (iface.first == UPF_CONFIG_N4_LABEL) {
      cfg.n4 = iface.second.to_interface_config();
    }
    cfg.upf_info.interface_upf_info_list.push_back(
        iface.second.to_upf_info_item());
  }

  if (get_nf(oai::config::SMF_CONFIG_NAME)) {
    cfg.smf_addr.api_version = get_nf("smf")->get_sbi().get_api_version();
    cfg.smf_addr.uri_root    = get_nf(oai::config::SMF_CONFIG_NAME)->get_url();
  }

  for (int i = 0; i < m_dnns.size(); i++) {
    bool m_dnn_matched = false;
    for (auto s : cfg.upf_info.snssai_upf_info_list) {
      for (auto d : s.dnn_upf_info_list) {
        if (d.dnn == m_dnns[i].get_dnn()) m_dnn_matched = true;
      }
    }
    if (!m_dnn_matched) m_dnns[i].unset_config();
  }
}

upf_interface_config upf_config_yaml::get_default_n3_interface() {
  return upf_interface_config(
      "N3", "oai-upf", 2152, "eth0", UPF_CONFIG_N3_LABEL, "access.oai.org");
}

upf_interface_config upf_config_yaml::get_default_n4_interface() {
  return upf_interface_config(
      "N4", "oai-upf", 8805, "eth0", UPF_CONFIG_N4_LABEL);
}

upf_interface_config upf_config_yaml::get_default_n6_interface() {
  return upf_interface_config(
      "N6", "oai-upf", 2152, "eth0", UPF_CONFIG_N6_LABEL, "core.oai.org");
}

upf_interface_config::upf_interface_config(
    const std::string& name, const std::string& host, uint16_t port,
    const std::string& if_name, const std::string& if_type)
    : upf_interface_config(name, host, port, if_name, if_type, ""){};

upf_interface_config::upf_interface_config(
    const std::string& name, const std::string& host, uint16_t port,
    const std::string& if_name, const std::string& if_type,
    const std::string& nwi)
    : local_interface(name, host, port, if_name) {
  set_if_type(if_type);
  m_nwi = string_config_value("Network Instance", nwi);
}

void upf_interface_config::from_yaml(const YAML::Node& node) {
  local_interface::from_yaml(node);
  if (node["nwi"]) {
    m_nwi.from_yaml(node["nwi"]);
  }
}

void upf_interface_config::set_if_type(const std::string& if_type) {
  m_interface_type = string_config_value("Interface Type", if_type);
}

std::string upf_interface_config::to_string(const std::string& indent) const {
  std::string out          = local_interface::to_string(indent);
  unsigned int inner_width = get_inner_width(indent.length());

  if (!m_nwi.get_value().empty()) {
    out.append(indent).append(fmt::format(
        BASE_FORMATTER, INNER_LIST_ELEM, m_nwi.get_config_name(), inner_width,
        m_nwi.get_value()));
  }
  return out;
}

interface_upf_info_item_t upf_interface_config::to_upf_info_item() const {
  interface_upf_info_item_t item{};
  item.endpoint_fqdn  = m_host.get_value();
  item.interface_type = m_interface_type.get_value();
  item.ipv4_addresses = std::vector<struct in_addr>{m_addr4};
  // TODO commented out because we should not send IPv6 to NRF if we do not
  // support it
  // item.ipv6_addresses = std::vector<struct in6_addr>{m_addr6};

  return item;
}
interface_cfg_t upf_interface_config::to_interface_config() const {
  // TODO this method is only temporary until we refactor the whole config
  interface_cfg_t cfg;
  cfg.addr4   = get_addr4();
  cfg.addr6   = get_addr6();
  cfg.mtu     = get_mtu();
  cfg.port    = get_port();
  cfg.if_name = get_if_name();

  return cfg;
}

void upf::trigger_pfcp_node_reports() {
    Logger::system().info("Initiating PFCP Node Reports to SMFs due to UpfInfo change.\\n");

    oai::model::nrf::UpfInfo current_dynamic_upf_info = this->get_upf_info(); 

    pfcp::node_id_t upf_node_id_val = {};
    bool node_id_found = false;
    // Get N4 interface configuration from this UPF instance
    const auto& iface_map = this->get_interfaces(); // Assuming get_interfaces() is a const getter like get_upf_info()
    auto it_n4 = iface_map.find(UPF_CONFIG_N4_LABEL); // UPF_CONFIG_N4_LABEL is "n4"

    if (it_n4 != iface_map.end()) {
        const upf_interface_config& n4_if_config = it_n4->second;
        // local_interface (base of upf_interface_config) has get_addr4() which should be populated.
        struct in_addr n4_addr = n4_if_config.get_addr4(); // Assuming get_addr4() exists and returns in_addr
        if (n4_addr.s_addr != 0) {
            upf_node_id_val.node_id_type = pfcp::NODE_ID_TYPE_IPV4_ADDRESS;
            upf_node_id_val.u1.ipv4_address = n4_addr;
            node_id_found = true;
            Logger::system().info("Using UPF Node ID (IPv4 from m_interfaces[n4]): {}\\n", upf_node_id_val.toString().c_str());
        } else {
            Logger::system().warn("N4 interface IP address is 0 in m_interfaces. Cannot form UPF Node ID.\\n");
        }
    } else {
        Logger::system().warn("N4 interface configuration not found in m_interfaces. Cannot form UPF Node ID.\\n");
    }

    if (!node_id_found) {
        Logger::system().error("Failed to determine UPF Node ID for PFCP Node Report. Skipping PFCP notification.\\n");
        return;
    }

    oai::upf::app::pfcp_associations::get_instance().send_node_report_to_all_smfs(current_dynamic_upf_info, upf_node_id_val);
}

bool upf::reload_upf_info_from_node(const YAML::Node& upf_info_yaml_node) {
    oai::model::nrf::UpfInfo temp_reloaded_upf_info;

    if (!parse_and_validate_upf_info(upf_info_yaml_node, temp_reloaded_upf_info)) {
        Logger::system().error("Reloading UpfInfo failed during parsing or validation. Configuration not updated.\\n");
        return false; 
    }

    bool info_changed = false;
    oai::model::nrf::UpfInfo info_to_propagate; // To store the info that needs to be sent out

    {
        std::lock_guard<std::mutex> lock(m_upf_info_mutex);
        if (m_upf_info != temp_reloaded_upf_info) { 
            m_upf_info = temp_reloaded_upf_info; 
            info_to_propagate = m_upf_info; // Get a copy of the newly set info
            Logger::system().info("m_upf_info has been successfully updated with reloaded configuration.\\n");
            info_changed = true;
        } else {
            Logger::system().info("Reloaded UpfInfo is identical to current. No update applied or signaled.\\n");
        }
    }
    
    if (info_changed) {
        if (upf_nrf_inst /* && some_way_to_check_nrf_registration_is_enabled() */ ) { 
            Logger::system().info("Triggering NRF profile update due to UpfInfo change.\\n");
            if (!upf_nrf_inst->trigger_nrf_profile_update(info_to_propagate)) { 
                Logger::system().error("NRF profile update failed after UpfInfo change.\\n");
            }
        } else if (!upf_nrf_inst) {
             Logger::system().warn("upf_nrf_inst is null, skipping NRF profile update.\\n");
        }
        
        this->trigger_pfcp_node_reports(); 
    } else {
        Logger::system().info("No change in UpfInfo, NRF/SMF notification skipped.\\n");
    }
    return true;
}

}  // namespace oai::config
