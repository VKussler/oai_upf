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

/*! \file upf_app.hpp
   \author  Lionel GAUTHIER
   \date 2018
   \email: lionel.gauthier@eurecom.fr
*/

#ifndef FILE_UPF_APP_HPP_SEEN
#define FILE_UPF_APP_HPP_SEEN

#include "common_root_types.h"

#include "itti_msg_n4.hpp"
#include "itti_msg_n3.hpp"

#include <boost/atomic.hpp>

#include <map>
#include <string>
#include <thread>
#include <memory>
#include <map>
#include <set>

namespace oai {
namespace upf {
namespace app {

class upf_app {
 private:
  std::thread::id thread_id;
  std::thread thread;

 public:
  explicit upf_app(const std::string& config_file);
  ~upf_app();
  upf_app(upf_app const&) = delete;
  void operator=(upf_app const&) = delete;

  void stop();

  teid_t generate_s5s8_up_teid();

  void handle_itti_msg(std::shared_ptr<itti_n3_echo_request> m);

  //  void handle_itti_msg (itti_n4_heartbeat_request& m);
  //  void handle_itti_msg (itti_n4_heartbeat_response& m);
  //  void handle_itti_msg (itti_n4_pfcp_pfd_management_request& m);
  //  void handle_itti_msg (itti_n4_pfcp_pfd_management_response& m);
  //  void handle_itti_msg (itti_n4_pfcp_association_setup_request& m);
  //  void handle_itti_msg (itti_n4_pfcp_association_setup_response& m);
  //  void handle_itti_msg (itti_n4_pfcp_association_update_request& m);
  //  void handle_itti_msg (itti_n4_pfcp_association_update_response& m);
  //  void handle_itti_msg (itti_n4_pfcp_association_release_request& m);
  //  void handle_itti_msg (itti_n4_pfcp_association_release_response& m);
  //  void handle_itti_msg (itti_n4_pfcp_version_not_supported_response& m);
  //  void handle_itti_msg (itti_n4_pfcp_node_report_request& m);
  //  void handle_itti_msg (itti_n4_pfcp_node_report_response& m);
  void handle_itti_msg(
      std::shared_ptr<itti_n4_session_establishment_request> m);
  void handle_itti_msg(std::shared_ptr<itti_n4_session_modification_request> m);
  void handle_itti_msg(std::shared_ptr<itti_n4_session_deletion_request> m);
  //  void handle_itti_msg (itti_n4_session_deletion_response& m);
  //  void handle_itti_msg (itti_n4_session_report_request& m);
  void handle_itti_msg(std::shared_ptr<itti_n4_session_report_response> m);
};
}  // namespace app
}  // namespace upf
}  // namespace oai

#endif /* FILE_UPF_APP_HPP_SEEN */
