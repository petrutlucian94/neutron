# Copyright 2021 Cloudbase Solutions
# All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


from oslo_config import cfg

from neutron._i18n import _


SECURITY_GROUP_OPTS = [
    cfg.BoolOpt('default_sg_remote_rule',
                default=True,
                help=_("If set, new default security groups will contain "
                       "a 'remote' rule pointing to itself, enabling "
                       "intercommunication between the ports owned by the "
                       "same tenant.")),
]


def register_db_sg_opts(conf=cfg.CONF):
    conf.register_opts(SECURITY_GROUP_OPTS)
