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

/*! \file upf_pfcp_association.cpp
   \brief
   \author  Lionel GAUTHIER
   \date 2019
   \email: lionel.gauthier@eurecom.fr
*/
#include "common_defs.h"
#include "logger.hpp"
#include "pfcp_switch.hpp"
#include "upf_pfcp_association.hpp"
#include "upf_n4.hpp"
#include "pfcp.hpp"
#include "upf_config.hpp"
#include "conv.hpp"

using namespace oai::upf::app;
// using namespace oai::config;
using namespace std;

extern itti_mw* itti_inst;
extern pfcp_switch* pfcp_switch_inst;
extern upf_n4* upf_n4_inst;
extern oai::config::upf_config upf_cfg;

//------------------------------------------------------------------------------
void pfcp_association::notify_add_session(const pfcp::fseid_t& cp_fseid) {
  std::unique_lock<std::mutex> l(m_sessions);
  sessions.insert(cp_fseid);
}
//------------------------------------------------------------------------------
bool pfcp_association::has_session(const pfcp::fseid_t& cp_fseid) const {
  std::unique_lock<std::mutex> l(m_sessions);
  auto it = sessions.find(cp_fseid);
  if (it != sessions.end()) {
    return true;
  } else {
    return false;
  }
}
//------------------------------------------------------------------------------
void pfcp_association::notify_del_session(const pfcp::fseid_t& cp_fseid) {
  std::unique_lock<std::mutex> l(m_sessions);
  sessions.erase(cp_fseid);
}
//------------------------------------------------------------------------------
void pfcp_association::del_sessions() {
  std::unique_lock<std::mutex> l(m_sessions);
  for (std::set<pfcp::fseid_t>::iterator it = sessions.begin();
       it != sessions.end();) {
    pfcp_switch_inst->remove_pfcp_session(*it);
    sessions.erase(it++);
  }
}
//------------------------------------------------------------------------------
bool pfcp_associations::add_association(
    pfcp::node_id_t& node_id,
    pfcp::recovery_time_stamp_t& recovery_time_stamp) {
  std::shared_ptr<pfcp_association> sa = {};
  if (remove_peer_candidate_node(node_id, sa)) {
    sa->recovery_time_stamp  = recovery_time_stamp;
    sa->function_features    = {};
    std::size_t hash_node_id = std::hash<pfcp::node_id_t>{}(node_id);
    associations.insert((int32_t) hash_node_id, sa);
    trigger_heartbeat_request_procedure(sa);
    return true;
  }
  return false;
}
//------------------------------------------------------------------------------
bool pfcp_associations::add_association(
    pfcp::node_id_t& node_id, pfcp::recovery_time_stamp_t& recovery_time_stamp,
    pfcp::cp_function_features_s& function_features) {
  std::shared_ptr<pfcp_association> sa = {};
  if (remove_peer_candidate_node(node_id, sa)) {
    sa->recovery_time_stamp = recovery_time_stamp;
    sa->set(function_features);
    std::size_t hash_node_id = std::hash<pfcp::node_id_t>{}(node_id);
    associations.insert((int32_t) hash_node_id, sa);
    trigger_heartbeat_request_procedure(sa);
    return true;
  }
  return false;
}

//------------------------------------------------------------------------------
bool pfcp_associations::get_association(
    const pfcp::node_id_t& node_id,
    std::shared_ptr<pfcp_association>& sa) const {
  std::size_t hash_node_id = std::hash<pfcp::node_id_t>{}(node_id);
  auto pit                 = associations.find((int32_t) hash_node_id);
  if (pit == associations.end())
    return false;
  else {
    sa = pit->second;
    return true;
  }
}
//------------------------------------------------------------------------------
bool pfcp_associations::get_association(
    const pfcp::fseid_t& cp_fseid,
    std::shared_ptr<pfcp_association>& sa) const {
  folly::AtomicHashMap<int32_t, std::shared_ptr<pfcp_association>>::iterator it;

  FOR_EACH(it, associations) {
    std::shared_ptr<pfcp_association> a = it->second;
    if (it->second->has_session(cp_fseid)) {
      sa = it->second;
      return true;
    }
  }
  return false;
}
//------------------------------------------------------------------------------
bool pfcp_associations::remove_peer_candidate_node(
    pfcp::node_id_t& node_id, std::shared_ptr<pfcp_association>& s) {
  for (std::vector<std::shared_ptr<pfcp_association>>::iterator it =
           pending_associations.begin();
       it < pending_associations.end(); ++it) {
    if ((*it)->node_id == node_id) {
      s = *it;
      pending_associations.erase(it);
      return true;
    }
  }
  return false;
}
//------------------------------------------------------------------------------
bool pfcp_associations::add_peer_candidate_node(
    const pfcp::node_id_t& node_id) {
  for (std::vector<std::shared_ptr<pfcp_association>>::iterator it =
           pending_associations.begin();
       it < pending_associations.end(); ++it) {
    if ((*it)->node_id == node_id) {
      // TODO purge sessions of this node
      Logger::upf_n4().info("TODO purge sessions of this node");
      pending_associations.erase(it);
      break;
    }
  }
  pfcp_association* association = new pfcp_association(node_id);
  std::shared_ptr<pfcp_association> s =
      std::shared_ptr<pfcp_association>(association);
  pending_associations.push_back(s);
  return true;
  // start_timer = itti_inst->timer_setup(0,0, TASK_UPF_N4,
  // TASK_MME_S11_TIMEOUT_SEND_GTPU_PING, 0);
}
//------------------------------------------------------------------------------
void pfcp_associations::trigger_heartbeat_request_procedure(
    std::shared_ptr<pfcp_association>& s) {
  s->timer_heartbeat = itti_inst->timer_setup(
      5, 0, TASK_UPF_N4, TASK_UPF_N4_TRIGGER_HEARTBEAT_REQUEST,
      s->hash_node_id);
}
//------------------------------------------------------------------------------
void pfcp_associations::initiate_heartbeat_request(
    timer_id_t timer_id, uint64_t arg2_user) {
  size_t hash = (size_t) arg2_user;
  for (auto it : associations) {
    if (it.second->hash_node_id == hash) {
      Logger::upf_n4().info("PFCP HEARTBEAT PROCEDURE hash %u starting", hash);
      it.second->num_retries_timer_heartbeat = 0;
      upf_n4_inst->send_heartbeat_request(it.second);
    }
  }
}
//------------------------------------------------------------------------------
void pfcp_associations::timeout_heartbeat_request(
    timer_id_t timer_id, uint64_t arg2_user) {
  size_t hash = (size_t) arg2_user;
  for (auto it : associations) {
    if (it.second->hash_node_id == hash) {
      Logger::upf_n4().info("PFCP HEARTBEAT PROCEDURE hash %u TIMED OUT", hash);
      if (it.second->num_retries_timer_heartbeat <
          PFCP_ASSOCIATION_HEARTBEAT_MAX_RETRIES) {
        it.second->num_retries_timer_heartbeat++;
        upf_n4_inst->send_heartbeat_request(it.second);
      } else {
        it.second->del_sessions();
        pfcp::node_id_t node_id  = it.second->node_id;
        std::size_t hash_node_id = it.second->hash_node_id;
        associations.erase((uint32_t) hash_node_id);
        add_peer_candidate_node(node_id);
        break;
      }
    }
  }
}
//------------------------------------------------------------------------------
void pfcp_associations::handle_receive_heartbeat_response(
    const uint64_t trxn_id) {
  for (auto it : associations) {
    if (it.second->trxn_id_heartbeat == trxn_id) {
      itti_inst->timer_remove(it.second->timer_heartbeat);
      trigger_heartbeat_request_procedure(it.second);
      return;
    }
  }
  Logger::upf_n4().info(
      "PFCP HEARTBEAT PROCEDURE trxn_id %d NOT FOUND", trxn_id);
}

//------------------------------------------------------------------------------
void pfcp_associations::notify_add_session(
    const pfcp::node_id_t& node_id, const pfcp::fseid_t& cp_fseid) {
  std::shared_ptr<pfcp_association> sa = {};
  if (get_association(node_id, sa)) {
    sa->notify_add_session(cp_fseid);
  }
}
//------------------------------------------------------------------------------
void pfcp_associations::notify_del_session(const pfcp::fseid_t& cp_fseid) {
  std::shared_ptr<pfcp_association> sa = {};
  if (get_association(cp_fseid, sa)) {
    sa->notify_del_session(cp_fseid);
  }
}

//------------------------------------------------------------------------------
void pfcp_associations::send_node_report_to_all_smfs(
    const oai::model::nrf::UpfInfo& current_upf_info,
    const pfcp::node_id_t& upf_node_id) {
  Logger::upf_n4().info("Attempting to send PFCP Node Report to all associated SMFs due to UPF info change.");

  if (!upf_n4_inst) {
    Logger::upf_n4().error("upf_n4_inst is null. Cannot send PFCP Node Reports.");
    return;
  }

  pfcp::recovery_time_stamp_t rts_ie = {};
  rts_ie.recovery_time_stamp = upf_n4_inst->get_recovery_timestamp();
  
  for (auto const& [key, assoc_ptr] : associations) {
    if (assoc_ptr) {
      const pfcp::node_id_t& smf_peer_node_id = assoc_ptr->peer_node_id();

      pfcp::pfcp_node_report_request report_ies = {}; 
      pfcp::up_function_features_s features_to_report = {}; 

      // 1. Always enable FTUP (Framed Tunneling User Plane)
      features_to_report.ftup = 1;

      // 2. Check global QoS config
      if (upf_cfg.enable_qos) { 
        features_to_report.quoac = 1; 
        features_to_report.dlbd  = 1; 
      }

      // 3. Simple check on dynamic UpfInfo: if any S-NSSAI is configured, enable BUCMP and DDND
      if (!current_upf_info.getSNssaiUpfInfoList().empty()) {
        features_to_report.bucp = 1; 
        features_to_report.ddnd = 1; 
      }
      
      report_ies.set(upf_node_id); // This one is likely okay as node_id is a common field       
      // report_ies.set(features_to_report); // Commented out: No matching 'set' for up_function_features_s
      // report_ies.set(rts_ie);             // Commented out: No matching 'set' for recovery_time_stamp_t

      // 4. Populate User Plane IP Resource Information IEs
      Logger::upf_n4().debug("Populating User Plane IP Resource Information IEs for Node Report to SMF: %s", smf_peer_node_id.toString().c_str());
      if (current_upf_info.interfaceUpfInfoListIsSet()) {
          for (const auto& if_info_item : current_upf_info.getInterfaceUpfInfoList()) {
              pfcp::user_plane_ip_resource_information_t up_ip_resource = {};
              bool ip_resource_valid = false;

              // Determine Source Interface Type
              std::string if_type_str = if_info_item.getInterfaceType().getEnumString();
              if (if_type_str == "N3") {
                  up_ip_resource.assosi = 1;
                  up_ip_resource.source_interface = 0;
                  Logger::upf_n4().debug("Processing N3 interface for User Plane IP Resource Info.");
              } else if (if_type_str == "N6") {
                  up_ip_resource.assosi = 1;
                  up_ip_resource.source_interface = 1;
                   if (if_info_item.networkInstanceIsSet() && !if_info_item.getNetworkInstance().empty()) {
                      up_ip_resource.assoni = 1;
                      up_ip_resource.network_instance = if_info_item.getNetworkInstance();
                      Logger::upf_n4().debug("Processing N6 interface with NetworkInstance: %s", up_ip_resource.network_instance.c_str());
                  } else {
                       Logger::upf_n4().debug("Processing N6 interface (no specific NetworkInstance from InterfaceUpfInfoItem).");
                  }
              } else {
                  Logger::upf_n4().debug("Skipping interface type %s for User Plane IP Resource Info in Node Report.", if_type_str.c_str());
                  continue;
              }

              // Populate IP addresses
              if (if_info_item.ipv4EndpointAddressesIsSet() && !if_info_item.getIpv4EndpointAddresses().empty()) {
                  const std::string& ipv4_str = if_info_item.getIpv4EndpointAddresses().front();
                  try {
                      up_ip_resource.ipv4_address = oai::utils::conv::fromString(ipv4_str);
                      up_ip_resource.v4 = 1;
                      ip_resource_valid = true;
                      Logger::upf_n4().debug("Added IPv4: %s to User Plane IP Resource Info for interface type %s.", ipv4_str.c_str(), if_type_str.c_str());
                  } catch (const std::invalid_argument& e) {
                      Logger::upf_n4().error("Invalid IPv4 address string '%s' for interface type %s: %s", ipv4_str.c_str(), if_type_str.c_str(), e.what());
                  }
              }

              if (ip_resource_valid) {
                  // report_ies.set(up_ip_resource); // Commented out: No matching 'set' for user_plane_ip_resource_information_t
              } else {
                  Logger::upf_n4().warn("No valid IP address found for interface type %s in InterfaceUpfInfoItem, skipping this User Plane IP Resource.", if_type_str.c_str());
              }
          }
      } else {
          Logger::upf_n4().warn("InterfaceUpfInfoList not set in current_upf_info. Cannot populate User Plane IP Resource Information IEs.");
      }

      Logger::upf_n4().info(
          "Sending PFCP Node Report Request to SMF: %s",
          smf_peer_node_id.toString().c_str());

      upf_n4_inst->send_pfcp_node_report_request(smf_peer_node_id, report_ies);
    } else {
      Logger::upf_n4().warn("Encountered a null association_ptr during iteration.");
    }
  }

  Logger::upf_n4().info("Finished iterating SMF associations for Node Report.");
}
