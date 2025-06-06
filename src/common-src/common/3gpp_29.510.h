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

#ifndef FILE_3GPP_29_510_SEEN
#define FILE_3GPP_29_510_SEEN

#include <arpa/inet.h>
#include <netinet/in.h>

#include <map>
#include <vector>
#include <unordered_set>

#include "3gpp_23.003.h"

namespace oai::common::sbi {

enum class nf_status_e { REGISTERED = 0, SUSPENDED = 1, UNDISCOVERABLE = 2 };

static const std::vector<std::string> nf_status_e2str = {
    "REGISTERED", "SUSPENDED", "UNDISCOVERABLE"};

typedef enum nf_up_interface_type_s {
  N3              = 0,
  N6              = 1,
  N9              = 2,
  DATA_FORWARDING = 3,
  TYPE_UNKNOWN    = 4
} nf_up_interface_type_t;

static const std::vector<std::string> up_interface_type_e2str = {
    "N3", "N6", "N9", "DATA_FORWARDING", "UNKNOWN"};

typedef struct amf_info_s {
  std::string amf_set_id;
  std::string amf_region_id;
  std::vector<guami_t> guami_list;
} amf_info_t;

typedef struct dnn_smf_info_item_s {
  std::string dnn;
} dnn_smf_info_item_t;

typedef struct snssai_smf_info_item_s {
  snssai_t snssai;
  std::vector<dnn_smf_info_item_t> dnn_smf_info_list;

} snssai_smf_info_item_t;

typedef struct smf_info_s {
  std::vector<snssai_smf_info_item_t> snssai_smf_info_list;
} smf_info_t;

typedef struct dnn_upf_info_item_s {
  std::string dnn;
  std::vector<std::string> dnai_list;
  // supported from R16.8
  std::map<std::string, std::string> dnai_nw_instance_list;
  // std::vector<std::string> pdu_session_types

  dnn_upf_info_item_s& operator=(const dnn_upf_info_item_s& d) {
    dnn                   = d.dnn;
    dnai_list             = d.dnai_list;
    dnai_nw_instance_list = d.dnai_nw_instance_list;
    return *this;
  }

  bool operator==(const dnn_upf_info_item_s& s) const { return dnn == s.dnn; }

  size_t operator()(const dnn_upf_info_item_s&) const {
    return std::hash<std::string>()(dnn);
  }

  std::string to_string() const {
    std::string s = {};

    s.append("DNN = ").append(dnn).append(", ");

    if (dnai_list.size() > 0) {
      s.append("DNAI list: {");

      for (const auto& dnai : dnai_list) {
        s.append("DNAI = ").append(dnai).append(", ");
      }
      s.append("}, ");
    }

    if (dnai_nw_instance_list.size() > 0) {
      s.append("DNAI NW Instance list: {");

      for (const auto& dnai_nw : dnai_nw_instance_list) {
        s.append("(")
            .append(dnai_nw.first)
            .append(", ")
            .append(dnai_nw.second)
            .append("),");
      }
      s.append("}, ");
    }
    return s;
  }

} dnn_upf_info_item_t;

typedef struct snssai_upf_info_item_s {
  mutable snssai_t snssai;
  mutable std::unordered_set<dnn_upf_info_item_t, dnn_upf_info_item_t>
      dnn_upf_info_list;

  snssai_upf_info_item_s& operator=(const snssai_upf_info_item_s& s) {
    snssai            = s.snssai;
    dnn_upf_info_list = s.dnn_upf_info_list;
    return *this;
  }

  bool operator==(const snssai_upf_info_item_s& s) const {
    return (snssai == s.snssai) and (dnn_upf_info_list == s.dnn_upf_info_list);
  }

  std::string to_string() const {
    std::string s = {};

    s.append("{" + snssai.toString() + ", ");

    if (dnn_upf_info_list.size() > 0) {
      s.append("{");

      for (auto dnn_upf : dnn_upf_info_list) {
        s.append(dnn_upf.to_string());
      }
      s.append("}, ");
    }
    return s;
  }

} snssai_upf_info_item_t;

typedef struct interface_upf_info_item_s {
  std::string interface_type;
  std::vector<struct in_addr> ipv4_addresses;
  std::vector<struct in6_addr> ipv6_addresses;
  std::string endpoint_fqdn;
  std::string network_instance;

  interface_upf_info_item_s& operator=(const interface_upf_info_item_s& i) {
    interface_type   = i.interface_type;
    ipv4_addresses   = i.ipv4_addresses;
    ipv6_addresses   = i.ipv6_addresses;
    endpoint_fqdn    = i.endpoint_fqdn;
    network_instance = i.network_instance;

    return *this;
  }

} interface_upf_info_item_t;

typedef struct upf_info_s {
  std::vector<interface_upf_info_item_t> interface_upf_info_list;
  std::vector<snssai_upf_info_item_t> snssai_upf_info_list;

  upf_info_s& operator=(const upf_info_s& s) {
    interface_upf_info_list = s.interface_upf_info_list;
    snssai_upf_info_list    = s.snssai_upf_info_list;
    return *this;
  }

  std::string to_string() const {
    std::string s = {};
    // TODO: Interface UPF Info List
    if (!snssai_upf_info_list.empty()) {
      s.append("S-NSSAI UPF Info: ");
      for (auto sn : snssai_upf_info_list) {
        s.append("{" + sn.snssai.toString() + ", ");
        for (auto d : sn.dnn_upf_info_list) {
          s.append("{DNN = " + d.dnn + "} ");
        }
        s.append("};");
      }
    }
    return s;
  }
} upf_info_t;

typedef struct supi_range_s {
  std::string start;
  std::string end;
  std::string pattern;
} supi_range_t;

typedef struct supi_range_info_item_s {
  supi_range_t supi_range;
} supi_range_info_item_t;

typedef struct identity_range_s {
  std::string start;
  std::string end;
  std::string pattern;
} identity_range_t;

typedef struct identity_range_info_item_s {
  identity_range_t identity_range;
} identity_range_info_item_t;

typedef struct internal_grpid_range_s {
  std::string start;
  std::string end;
  std::string pattern;
} internal_grpid_range_t;

typedef struct internal_grpid_range_info_item_s {
  internal_grpid_range_t int_grpid_range;
} internal_grpid_range_info_item_t;

typedef struct ausf_info_s {
  std::string groupid;
  std::vector<supi_range_info_item_t> supi_ranges;
  std::vector<std::string> routing_indicators;
} ausf_info_t;

typedef struct udm_info_s {
  std::string groupid;
  std::vector<supi_range_info_item_t> supi_ranges;
  std::vector<identity_range_info_item_t> gpsi_ranges;
  std::vector<identity_range_info_item_t> ext_grp_id_ranges;
  std::vector<std::string> routing_indicator;
  std::vector<internal_grpid_range_info_item_t> int_grp_id_ranges;
} udm_info_t;

typedef struct udr_info_s {
  std::string groupid;
  std::vector<supi_range_info_item_t> supi_ranges;
  std::vector<identity_range_info_item_t> gpsi_ranges;
  std::vector<identity_range_info_item_t> ext_grp_id_ranges;
  std::vector<std::string> data_set_id;
} udr_info_t;

typedef struct pcf_info_s {
  std::string groupid;
  std::vector<std::string> dnn_list;
  std::vector<supi_range_info_item_t> supi_ranges;
  std::vector<identity_range_info_item_t> gpsi_ranges;
  // ToDo: rxDiamHost, rxDiamRealm, v2xSupportInd.
} pcf_info_t;

typedef struct udsf_info_s {
  std::string group_id;
  std::vector<supi_range_t> supi_ranges;
  std::map<std::string, std::vector<identity_range_t>> storage_id_ranges;
} udsf_info_t;

enum subscr_condition_type_e {  // TODO: use enum class
  UNKNOWN_CONDITION   = 0,
  NF_INSTANCE_ID_COND = 1,
  NF_TYPE_COND        = 2,
  SERVICE_NAME_COND   = 3,
  AMF_COND            = 4,
  GUAMI_LIST_COND     = 5,
  NETWOTK_SLICE_COND  = 6,
  NF_GROUP_COND       = 7
};

static const std::vector<std::string> subscription_condition_type_e2str = {
    "UNKNOWN_CONDITION",  "NF_INSTANCE_ID_COND",
    "NF_TYPE_COND",       "SERVICE_NAME_COND",
    "AMF_COND",           "GUAMI_LIST_COND",
    "NETWOTK_SLICE_COND", "NF_GROUP_COND"};

typedef struct amf_cond_s {
  std::string amf_set_id;
  std::string amf_region_id;
} amf_cond_t;

typedef struct network_slice_cond_s {
  std::vector<snssai_t> snssai_list;
  std::vector<std::string> nsi_list;
} network_slice_cond_t;

typedef struct nf_group_cond_s {
  std::string nf_type;

  std::string nf_group_id;
} nf_group_cond_t;

typedef struct subscription_condition_s {
  uint8_t type;
  union {
    std::string nf_instance_id;
    std::string nf_type;
    std::string service_name;
    amf_cond_t amf_info;
    std::vector<guami_t> guami_list;
    network_slice_cond_t network_slice;
    nf_group_cond_t nf_group;
  };

  subscription_condition_s() : type(0), nf_instance_id() {}

  subscription_condition_s(uint8_t t) : type(t) {}

  subscription_condition_s(const subscription_condition_s& s)
      : subscription_condition_s() {
    type = s.type;
    switch (s.type) {
      case NF_INSTANCE_ID_COND: {
        nf_instance_id = s.nf_instance_id;
      } break;
      case NF_TYPE_COND: {
        nf_type = s.nf_type;
      } break;

      case SERVICE_NAME_COND: {
        service_name = s.service_name;
      } break;
      case AMF_COND: {
        amf_info.amf_set_id    = s.amf_info.amf_set_id;
        amf_info.amf_region_id = s.amf_info.amf_region_id;
      } break;

      case GUAMI_LIST_COND: {
        // TODO:
      } break;

      case NETWOTK_SLICE_COND: {
        // TODO:
      } break;

      case NF_GROUP_COND: {
        // TODO:
      } break;

      default: {
        // TODO:
      }
    }
    // TODO:
  }
  bool operator==(const struct subscription_condition_s& s) const {
    return (s.type == type);
  }

  bool operator==(const uint8_t& t) const { return (t == type); }

  subscription_condition_s& operator=(const subscription_condition_s& s) {
    type = s.type;
    switch (s.type) {
      case NF_INSTANCE_ID_COND: {
        nf_instance_id = s.nf_instance_id;
      } break;
      case NF_TYPE_COND: {
        nf_type = s.nf_type;
      } break;

      case SERVICE_NAME_COND: {
        service_name = s.service_name;
      } break;
      case AMF_COND: {
        amf_info.amf_set_id    = s.amf_info.amf_set_id;
        amf_info.amf_region_id = s.amf_info.amf_region_id;
      } break;

      case GUAMI_LIST_COND: {
        // TODO:
      } break;

      case NETWOTK_SLICE_COND: {
        // TODO:
      } break;

      case NF_GROUP_COND: {
        // TODO:
      } break;

      default: {
        // TODO:
      }
    }
    return *this;
    // TODO:
  }

  virtual ~subscription_condition_s(){};

  std::string to_string() const {
    std::string s = {};
    s.append("Type: ");
    s.append(subscription_condition_type_e2str[type]);
    s.append(", condition: ");
    switch (type) {
      case NF_INSTANCE_ID_COND: {
        s.append(nf_instance_id);
      } break;
      case NF_TYPE_COND: {
        s.append(nf_type);
      } break;
      case SERVICE_NAME_COND: {
        s.append(service_name);
      } break;
      case AMF_COND: {
        s.append(", AMF_Set_ID: ");
        s.append(amf_info.amf_set_id);
        s.append(", AMF_Region_ID: ");
        s.append(amf_info.amf_region_id);
      } break;

      case GUAMI_LIST_COND: {
        // TODO:
      } break;

      case NETWOTK_SLICE_COND: {
        // TODO:
      } break;

      case NF_GROUP_COND: {
        // TODO:
      } break;

      default: {
        // TODO:
      }
    }
    // TODO:

    return s;
  }

} subscription_condition_t;

enum notification_event_type_t {
  NOTIFICATION_TYPE_UNKNOWN_EVENT      = 0,
  NOTIFICATION_TYPE_NF_REGISTERED      = 1,
  NOTIFICATION_TYPE_NF_DEREGISTERED    = 2,
  NOTIFICATION_TYPE_NF_PROFILE_CHANGED = 3
};

static const std::vector<std::string> notification_event_type_e2str = {
    "UNKNOWN EVENT", "NF_REGISTERED", "NF_DEREGISTERED", "NF_PROFILE_CHANGED"};

typedef struct nf_service_version_s {
  std::string api_version_in_uri;  // apiVersionInUri
  std::string api_full_version;    // apiFullVersion

  nf_service_version_s& operator=(const nf_service_version_s& s) {
    api_version_in_uri = s.api_version_in_uri;
    api_full_version   = s.api_full_version;
    return *this;
  }

  std::string to_string() const {
    std::string s = {};
    s.append(", Version (");
    s.append("apiVersionInUri: ");
    s.append(api_version_in_uri);
    s.append(", apiFullVersion: ");
    s.append(api_full_version);
    s.append(" )");
    return s;
  }
} nf_service_version_t;

typedef struct ip_endpoint_s {
  // struct in6_addr  ipv6_address;
  struct in_addr ipv4_address;
  std::string transport;  // TCP
  unsigned int port;
  std::string to_string() const {
    std::string s = {};
    s.append("Ipv4 Address: ");
    s.append(inet_ntoa(ipv4_address));
    s.append(", TransportProtocol: ");
    s.append(transport);
    s.append(", Port: ");
    s.append(std::to_string(port));
    return s;
  }
} ip_endpoint_t;

typedef struct nf_service_s {
  std::string service_instance_id;
  std::string service_name;
  std::vector<nf_service_version_t> versions;
  std::string scheme;
  std::string nf_service_status;
  std::vector<ip_endpoint_t> ip_endpoints;

  std::string to_string() const {
    std::string s = {};
    s.append("Service Instance ID: ");
    s.append(service_instance_id);
    s.append(", Service name: ");
    s.append(service_name);
    for (const auto& v : versions) {
      s.append(v.to_string());
    }
    s.append(", Scheme: ");
    s.append(scheme);
    s.append(", Service status: ");
    s.append(nf_service_status);
    s.append(",  IpEndPoints: ");
    for (auto endpoint : ip_endpoints) {
      s.append(endpoint.to_string());
    }
    return s;
  }
} nf_service_t;

typedef struct dnai_s {
} dnai_t;

typedef struct patch_item_s {
  std::string op;
  std::string path;
  // std::string from;
  std::string value;

  nlohmann::json to_json() const {
    nlohmann::json json_data = {};
    json_data["op"]          = op;
    json_data["path"]        = path;
    json_data["value"]       = value;
    return json_data;
  }
} patch_item_t;

}  // namespace oai::common::sbi

#endif  // FILE_3GPP_29_510_SEEN
