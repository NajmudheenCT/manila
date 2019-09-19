# Copyright (c) 2016 EMC Corporation.
# All Rights Reserved.
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
"""Unity backend for the EMC Manila driver."""
import random

from oslo_config import cfg
from oslo_log import log
from oslo_utils import excutils
from oslo_utils import importutils
from oslo_utils import netutils

storops = importutils.try_import('storops')
if storops:
    # pylint: disable=import-error
    from storops import exception as storops_ex
    from storops.unity import enums

from manila.common import constants as const
from manila import exception
from manila.i18n import _
from manila.share.drivers.dell_emc.common.enas import utils as enas_utils
from manila.share.drivers.dell_emc.plugins import base as driver
from manila.share.drivers.dell_emc.plugins.unity import client
from manila.share.drivers.dell_emc.plugins.unity import utils as unity_utils
from manila.share import utils as share_utils
from manila import utils

VERSION = "6.1.0"

LOG = log.getLogger(__name__)
SUPPORTED_NETWORK_TYPES = (None, 'flat', 'vlan')

UNITY_OPTS = [
    cfg.StrOpt('unity_server_meta_pool',
               required=True,
               deprecated_name='emc_nas_server_pool',
               help='Pool to persist the meta-data of NAS server.'),
    cfg.ListOpt('unity_share_data_pools',
                deprecated_name='emc_nas_pool_names',
                help='Comma separated list of pools that can be used to '
                     'persist share data.'),
    cfg.ListOpt('unity_ethernet_ports',
                deprecated_name='emc_interface_ports',
                help='Comma separated list of ports that can be used for '
                     'share server interfaces. Members of the list '
                     'can be Unix-style glob expressions.'),
    cfg.StrOpt('emc_nas_server_container',
               deprecated_for_removal=True,
               deprecated_reason='Unity driver supports nas server auto load '
                                 'balance.',
               help='Storage processor to host the NAS server. Obsolete.'),
    cfg.StrOpt('unity_replication_rpo',
               default=60,
               help='maximum time in minute to wait before syncing the '
                    'replication source and destination. It could be set to '
                    '`0` which means the created replication is a sync one. '
                    'Make sure a sync type replication connection is set up '
                    'before using it. Refer to configuration doc for more '
                    'detail.'),
]

CONF = cfg.CONF
CONF.register_opts(UNITY_OPTS)


@enas_utils.decorate_all_methods(enas_utils.log_enter_exit,
                                 debug_only=True)
class UnityStorageConnection(driver.StorageConnection):
    """Implements Unity specific functionality for EMC Manila driver."""

    IP_ALLOCATIONS = 1

    @enas_utils.log_enter_exit
    def __init__(self, *args, **kwargs):
        super(UnityStorageConnection, self).__init__(*args, **kwargs)
        if 'configuration' in kwargs:
            kwargs['configuration'].append_config_values(UNITY_OPTS)

        self.client = None
        self.pool_set = None
        self.nas_server_pool = None
        self.reserved_percentage = None
        self.max_over_subscription_ratio = None
        self.port_ids_conf = None
        self.ipv6_implemented = True
        self.revert_to_snap_support = True
        self.shrink_share_support = True

        # props from super class.
        self.driver_handles_share_servers = True

        self.replication_rpo = 60
        self.replication_domain = None

    def connect(self, emc_share_driver, context):
        """Connect to Unity storage."""
        config = emc_share_driver.configuration
        storage_ip = config.emc_nas_server
        username = config.emc_nas_login
        password = config.emc_nas_password
        self.client = client.UnityClient(storage_ip, username, password)

        pool_conf = config.safe_get('unity_share_data_pools')
        self.pool_set = self._get_managed_pools(pool_conf)

        self.reserved_percentage = config.safe_get(
            'reserved_share_percentage')
        if self.reserved_percentage is None:
            self.reserved_percentage = 0

        self.max_over_subscription_ratio = config.safe_get(
            'max_over_subscription_ratio')
        self.port_ids_conf = config.safe_get('unity_ethernet_ports')
        self.validate_port_configuration(self.port_ids_conf)
        pool_name = config.unity_server_meta_pool
        self._config_pool(pool_name)

        self.replication_rpo = config.safe_get('unity_replication_rpo')
        self.replication_domain = config.safe_get('replication_domain')

    def validate_port_configuration(self, port_ids_conf):
        """Initializes the SP and ports based on the port option."""

        ports = self.client.get_file_ports()

        sp_ports_map, unmanaged_port_ids = unity_utils.match_ports(
            ports, port_ids_conf)

        if not sp_ports_map:
            msg = (_("All the specified storage ports to be managed "
                     "do not exist. Please check your configuration "
                     "unity_ethernet_ports in manila.conf. "
                     "The available ports in the backend are %s.") %
                   ",".join([port.get_id() for port in ports]))
            raise exception.BadConfigurationException(reason=msg)

        if unmanaged_port_ids:
            LOG.info("The following specified ports are not managed by "
                     "the backend: %(unmanaged)s. This host will only "
                     "manage the storage ports: %(exist)s",
                     {'unmanaged': ",".join(unmanaged_port_ids),
                      'exist': ",".join(map(",".join,
                                            sp_ports_map.values()))})
        else:
            LOG.debug("Ports: %s will be managed.",
                      ",".join(map(",".join, sp_ports_map.values())))

        if len(sp_ports_map) == 1:
            LOG.info("Only ports of %s are configured. Configure ports "
                     "of both SPA and SPB to use both of the SPs.",
                     list(sp_ports_map)[0])

        return sp_ports_map

    def check_for_setup_error(self):
        """Check for setup error."""

    def create_share(self, context, share, share_server=None):
        """Create a share and export it based on protocol used."""
        share_name = share['id']
        size = share['size']

        # Check share's protocol.
        # Throw an exception immediately if it is an invalid protocol.
        share_proto = share['share_proto'].upper()
        proto_enum = self._get_proto_enum(share_proto)

        # Get pool name from share host field
        pool_name = self._get_pool_name_from_host(share['host'])
        # Get share server name from share server
        server_name = self._get_server_name(share_server)

        pool = self.client.get_pool(pool_name)
        try:
            nas_server = self.client.get_nas_server(server_name)
        except storops_ex.UnityResourceNotFoundError:
            message = (_("Failed to get NAS server %(server)s when "
                         "creating the share %(share)s.") %
                       {'server': server_name, 'share': share_name})
            LOG.exception(message)
            raise exception.EMCUnityError(err=message)

        locations = None
        if share_proto == 'CIFS':
            filesystem = self.client.create_filesystem(
                pool, nas_server, share_name,
                size, proto=proto_enum)
            self.client.create_cifs_share(filesystem, share_name)

            locations = self._get_cifs_location(
                nas_server.file_interface, share_name)
        elif share_proto == 'NFS':
            self.client.create_nfs_filesystem_and_share(
                pool, nas_server, share_name, size)

            locations = self._get_nfs_location(
                nas_server.file_interface, share_name)

        return locations

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        """Create a share from a snapshot - clone a snapshot."""
        share_name = share['id']

        # Check share's protocol.
        # Throw an exception immediately if it is an invalid protocol.
        share_proto = share['share_proto'].upper()
        self._validate_share_protocol(share_proto)

        # Get share server name from share server
        server_name = self._get_server_name(share_server)

        try:
            nas_server = self.client.get_nas_server(server_name)
        except storops_ex.UnityResourceNotFoundError:
            message = (_("Failed to get NAS server %(server)s when "
                         "creating the share %(share)s.") %
                       {'server': server_name, 'share': share_name})
            LOG.exception(message)
            raise exception.EMCUnityError(err=message)

        backend_snap = self.client.create_snap_of_snap(snapshot['id'],
                                                       share_name)

        locations = None
        if share_proto == 'CIFS':
            self.client.create_cifs_share(backend_snap, share_name)

            locations = self._get_cifs_location(
                nas_server.file_interface, share_name)
        elif share_proto == 'NFS':
            self.client.create_nfs_share(backend_snap, share_name)

            locations = self._get_nfs_location(
                nas_server.file_interface, share_name)

        return locations

    def _delete_backend_share(self, backend_share):
        # Share created by the API create_share_from_snapshot()
        if self._is_share_from_snapshot(backend_share):
            filesystem = backend_share.snap.filesystem
            self.client.delete_snapshot(backend_share.snap)
        else:
            filesystem = backend_share.filesystem
            self.client.delete_share(backend_share)

        if self._is_isolated_filesystem(filesystem):
            self.client.delete_filesystem(filesystem)

    def delete_share(self, context, share, share_server=None):
        """Delete a share."""
        share_name = share['id']
        try:
            backend_share = self.client.get_share(share_name,
                                                  share['share_proto'])
        except storops_ex.UnityResourceNotFoundError:
            LOG.warning("Share %s is not found when deleting the share",
                        share_name)
            return

        self._delete_backend_share(backend_share)

    def extend_share(self, share, new_size, share_server=None):
        backend_share = self.client.get_share(share['id'],
                                              share['share_proto'])

        if not self._is_share_from_snapshot(backend_share):
            self.client.extend_filesystem(backend_share.filesystem,
                                          new_size)
        else:
            share_id = share['id']
            reason = ("Driver does not support extending a "
                      "snapshot based share.")
            raise exception.ShareExtendingError(share_id=share_id,
                                                reason=reason)

    def shrink_share(self, share, new_size, share_server=None):
        """Shrinks a share to new size.

        :param share: Share that will be shrunk.
        :param new_size: New size of share.
        :param share_server: Data structure with share server information.
            Not used by this driver.
        """
        share_id = share['id']
        backend_share = self.client.get_share(share_id,
                                              share['share_proto'])
        if self._is_share_from_snapshot(backend_share):
            reason = ("Driver does not support shrinking a "
                      "snapshot based share.")
            raise exception.ShareShrinkingError(share_id=share_id,
                                                reason=reason)
        self.client.shrink_filesystem(share_id, backend_share.filesystem,
                                      new_size)
        LOG.info("Share %(shr_id)s successfully shrunk to "
                 "%(shr_size)sG.",
                 {'shr_id': share_id,
                  'shr_size': new_size})

    def create_snapshot(self, context, snapshot, share_server=None):
        """Create snapshot from share."""
        share_name = snapshot['share_id']
        share_proto = snapshot['share']['share_proto']
        backend_share = self.client.get_share(share_name, share_proto)

        snapshot_name = snapshot['id']
        if self._is_share_from_snapshot(backend_share):
            self.client.create_snap_of_snap(backend_share.snap, snapshot_name)
        else:
            self.client.create_snapshot(backend_share.filesystem,
                                        snapshot_name)

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Delete a snapshot."""
        snap = self.client.get_snapshot(snapshot['id'])
        self.client.delete_snapshot(snap)

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        # adding rules
        if add_rules:
            for rule in add_rules:
                self.allow_access(context, share, rule, share_server)

        # deleting rules
        if delete_rules:
            for rule in delete_rules:
                self.deny_access(context, share, rule, share_server)

        # recovery mode
        if not (add_rules or delete_rules):
            white_list = []
            for rule in access_rules:
                self.allow_access(context, share, rule, share_server)
                white_list.append(rule['access_to'])
            self.clear_access(share, white_list)

    def clear_access(self, share, white_list=None):
        share_proto = share['share_proto'].upper()
        share_name = share['id']
        if share_proto == 'CIFS':
            self.client.cifs_clear_access(share_name, white_list)
        elif share_proto == 'NFS':
            self.client.nfs_clear_access(share_name, white_list)

    def allow_access(self, context, share, access, share_server=None):
        """Allow access to a share."""
        access_level = access['access_level']
        if access_level not in const.ACCESS_LEVELS:
            raise exception.InvalidShareAccessLevel(level=access_level)

        share_proto = share['share_proto'].upper()

        self._validate_share_protocol(share_proto)
        self._validate_share_access_type(share, access)

        if share_proto == 'CIFS':
            self._cifs_allow_access(share, access)
        elif share_proto == 'NFS':
            self._nfs_allow_access(share, access)

    def deny_access(self, context, share, access, share_server):
        """Deny access to a share."""
        share_proto = share['share_proto'].upper()

        self._validate_share_protocol(share_proto)
        self._validate_share_access_type(share, access)

        if share_proto == 'CIFS':
            self._cifs_deny_access(share, access)
        elif share_proto == 'NFS':
            self._nfs_deny_access(share, access)

    def ensure_share(self, context, share, share_server):
        """Ensure that the share is exported."""
        share_name = share['id']
        share_proto = share['share_proto']

        backend_share = self.client.get_share(share_name, share_proto)
        if not backend_share.existed:
            raise exception.ShareNotFound(share_id=share_name)

    def update_share_stats(self, stats_dict):
        """Communicate with EMCNASClient to get the stats."""
        stats_dict['driver_version'] = VERSION
        stats_dict['pools'] = []

        for pool in self.client.get_pool():
            if pool.name in self.pool_set:
                # the unit of following numbers are GB
                total_size = float(pool.size_total)
                used_size = float(pool.size_used)

                pool_stat = {
                    'pool_name': pool.name,
                    'thin_provisioning': True,
                    'total_capacity_gb': total_size,
                    'free_capacity_gb': total_size - used_size,
                    'allocated_capacity_gb': used_size,
                    'provisioned_capacity_gb': float(pool.size_subscribed),
                    'qos': False,
                    'reserved_percentage': self.reserved_percentage,
                    'max_over_subscription_ratio':
                        self.max_over_subscription_ratio,
                    'replication_type': const.REPLICATION_TYPE_DR,
                    'replication_domain': self.replication_domain,
                }
                stats_dict['pools'].append(pool_stat)

        if not stats_dict.get('pools'):
            message = _("Failed to update storage pool.")
            LOG.error(message)
            raise exception.EMCUnityError(err=message)

    def get_pool(self, share):
        """Get the pool name of the share."""
        backend_share = self.client.get_share(
            share['id'], share['share_proto'])

        return backend_share.filesystem.pool.name

    def get_network_allocations_number(self):
        """Returns number of network allocations for creating VIFs."""
        return self.IP_ALLOCATIONS

    def setup_server(self, network_info, metadata=None):
        """Set up and configures share server with given network parameters."""
        server_name = network_info['server_id']
        segmentation_id = network_info['segmentation_id']
        network = self.validate_network(network_info)
        mtu = network['mtu']
        tenant = self.client.get_tenant(network_info['server_id'],
                                        segmentation_id)

        sp_ports_map = unity_utils.find_ports_by_mtu(
            self.client.get_file_ports(),
            self.port_ids_conf, mtu)

        sp = self._choose_sp(sp_ports_map)
        nas_server = self.client.create_nas_server(server_name,
                                                   sp,
                                                   self.nas_server_pool,
                                                   tenant=tenant)
        sp = nas_server.home_sp
        port_id = self._choose_port(sp_ports_map, sp)
        try:
            self._create_network_interface(nas_server, network, port_id)

            self._handle_security_services(
                nas_server, network_info['security_services'])

            return {'share_server_name': server_name}

        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception('Could not setup server.')
                server_details = {'share_server_name': server_name}
                self.teardown_server(
                    server_details, network_info['security_services'])

    def teardown_server(self, server_details, security_services=None):
        """Teardown share server."""
        if not server_details:
            LOG.debug('Server details are empty.')
            return

        server_name = server_details.get('share_server_name')
        if not server_name:
            LOG.debug('No share server found for server %s.',
                      server_details.get('instance_id'))
            return

        username = None
        password = None
        for security_service in security_services:
            if security_service['type'] == 'active_directory':
                username = security_service['user']
                password = security_service['password']
                break

        self.client.delete_nas_server(server_name, username, password)

    def _cifs_allow_access(self, share, access):
        """Allow access to CIFS share."""
        self.client.cifs_allow_access(
            share['id'], access['access_to'], access['access_level'])

    def _cifs_deny_access(self, share, access):
        """Deny access to CIFS share."""
        self.client.cifs_deny_access(share['id'], access['access_to'])

    def _config_pool(self, pool_name):
        try:
            self.nas_server_pool = self.client.get_pool(pool_name)
        except storops_ex.UnityResourceNotFoundError:
            message = (_("The storage pools %s to store NAS server "
                         "configuration do not exist.") % pool_name)
            LOG.exception(message)
            raise exception.BadConfigurationException(reason=message)

    @staticmethod
    def validate_network(network_info):
        network = network_info['network_allocations'][0]
        if network['network_type'] not in SUPPORTED_NETWORK_TYPES:
            msg = _('The specified network type %s is unsupported by '
                    'the EMC Unity driver')
            raise exception.NetworkBadConfigurationException(
                reason=msg % network['network_type'])
        return network

    def _create_network_interface(self, nas_server, network, port_id):
        kargs = {'ip_addr': network['ip_address'],
                 'gateway': network['gateway'],
                 'vlan_id': network['segmentation_id'],
                 'port_id': port_id}

        if netutils.is_valid_ipv6_cidr(kargs['ip_addr']):
            kargs['netmask'] = None
            kargs['prefix_length'] = str(utils.cidr_to_prefixlen(
                network['cidr']))
        else:
            kargs['netmask'] = utils.cidr_to_netmask(network['cidr'])

        # Create the interfaces on NAS server
        self.client.create_interface(nas_server, **kargs)

    def _choose_sp(self, sp_ports_map):
        sp = None
        if len(sp_ports_map.keys()) == 1:
            # Only one storage processor has usable ports,
            # create NAS server on that SP.
            sp = self.client.get_storage_processor(
                sp_id=list(sp_ports_map.keys())[0])
            LOG.debug('All the usable ports belong to  %s. '
                      'Creating NAS server on this SP without '
                      'load balance.', sp.get_id())
        return sp

    @staticmethod
    def _choose_port(sp_ports_map, sp):
        ports = sp_ports_map[sp.get_id()]
        return random.choice(list(ports))

    @staticmethod
    def _get_cifs_location(file_interfaces, share_name):
        return [
            {'path': r'\\%(interface)s\%(share_name)s' % {
                'interface': enas_utils.export_unc_path(interface.ip_address),
                'share_name': share_name}
             }
            for interface in file_interfaces
        ]

    def _get_managed_pools(self, pool_conf):
        # Get the real pools from the backend storage
        real_pools = set(pool.name for pool in self.client.get_pool())

        if not pool_conf:
            LOG.debug("No storage pool is specified, so all pools in storage "
                      "system will be managed.")
            return real_pools

        matched_pools, unmanaged_pools = unity_utils.do_match(real_pools,
                                                              pool_conf)

        if not matched_pools:
            msg = (_("All the specified storage pools to be managed "
                     "do not exist. Please check your configuration "
                     "emc_nas_pool_names in manila.conf. "
                     "The available pools in the backend are %s") %
                   ",".join(real_pools))
            raise exception.BadConfigurationException(reason=msg)

        if unmanaged_pools:
            LOG.info("The following specified storage pools "
                     "are not managed by the backend: "
                     "%(un_managed)s. This host will only manage "
                     "the storage pools: %(exist)s",
                     {'un_managed': ",".join(unmanaged_pools),
                      'exist': ",".join(matched_pools)})
        else:
            LOG.debug("Storage pools: %s will be managed.",
                      ",".join(matched_pools))

        return matched_pools

    @staticmethod
    def _get_nfs_location(file_interfaces, share_name):
        return [
            {'path': '%(interface)s:/%(share_name)s' % {
                'interface': enas_utils.convert_ipv6_format_if_needed(
                    interface.ip_address),
                'share_name': share_name}
             }
            for interface in file_interfaces
        ]

    @staticmethod
    def _get_export_location(file_interfaces, share_proto, share_name):
        share_proto = share_proto.upper()
        if share_proto == 'CIFS':
            return UnityStorageConnection._get_cifs_location(file_interfaces,
                                                             share_name)
        else:  # NFS
            return UnityStorageConnection._get_nfs_location(file_interfaces,
                                                            share_name)

    @staticmethod
    def _get_pool_name_from_host(host):
        pool_name = share_utils.extract_host(host, level='pool')
        if not pool_name:
            message = (_("Pool is not available in the share host %s.") %
                       host)
            raise exception.InvalidHost(reason=message)

        return pool_name

    @staticmethod
    def _get_proto_enum(share_proto):
        share_proto = share_proto.upper()
        UnityStorageConnection._validate_share_protocol(share_proto)

        if share_proto == 'CIFS':
            return enums.FSSupportedProtocolEnum.CIFS
        elif share_proto == 'NFS':
            return enums.FSSupportedProtocolEnum.NFS

    @staticmethod
    def _get_server_name(share_server):
        if not share_server:
            msg = _('Share server not provided.')
            raise exception.InvalidInput(reason=msg)

        server_name = share_server.get(
            'backend_details', {}).get('share_server_name')

        if server_name is None:
            msg = (_("Name of the share server %s not found.")
                   % share_server['id'])
            LOG.error(msg)
            raise exception.InvalidInput(reason=msg)

        return server_name

    def _handle_security_services(self, nas_server, security_services):
        kerberos_enabled = False
        # Support 'active_directory' and 'kerberos'
        for security_service in security_services:
            service_type = security_service['type']
            if service_type == 'active_directory':
                # Create DNS server for NAS server
                domain = security_service['domain']
                dns_ip = security_service['dns_ip']
                self.client.create_dns_server(nas_server,
                                              domain,
                                              dns_ip)

                # Enable CIFS service
                username = security_service['user']
                password = security_service['password']
                self.client.enable_cifs_service(nas_server,
                                                domain=domain,
                                                username=username,
                                                password=password)
            elif service_type == 'kerberos':
                # Enable NFS service with kerberos
                kerberos_enabled = True
                # TODO(jay.xu): enable nfs service with kerberos
                LOG.warning('Kerberos is not supported by '
                            'EMC Unity manila driver plugin.')
            elif service_type == 'ldap':
                LOG.warning('LDAP is not supported by '
                            'EMC Unity manila driver plugin.')
            else:
                LOG.warning('Unknown security service type: %s.',
                            service_type)

        if not kerberos_enabled:
            # Enable NFS service without kerberos
            self.client.enable_nfs_service(nas_server)

    def _nfs_allow_access(self, share, access):
        """Allow access to NFS share."""
        self.client.nfs_allow_access(
            share['id'], access['access_to'], access['access_level'])

    def _nfs_deny_access(self, share, access):
        """Deny access to NFS share."""
        self.client.nfs_deny_access(share['id'], access['access_to'])

    @staticmethod
    def _is_isolated_filesystem(filesystem):
        filesystem.update()
        return (
            not filesystem.has_snap() and
            not (filesystem.cifs_share or filesystem.nfs_share)
        )

    @staticmethod
    def _is_share_from_snapshot(share):
        return True if share.snap else False

    @staticmethod
    def _validate_share_access_type(share, access):
        reason = None
        share_proto = share['share_proto'].upper()

        if share_proto == 'CIFS' and access['access_type'] != 'user':
            reason = _('Only user access type allowed for CIFS share.')
        elif share_proto == 'NFS' and access['access_type'] != 'ip':
            reason = _('Only IP access type allowed for NFS share.')

        if reason:
            raise exception.InvalidShareAccess(reason=reason)

    @staticmethod
    def _validate_share_protocol(share_proto):
        if share_proto not in ('NFS', 'CIFS'):
            raise exception.InvalidShare(
                reason=(_('Invalid NAS protocol supplied: %s.') %
                        share_proto))

    def revert_to_snapshot(self, context, snapshot, share_access_rules,
                           snapshot_access_rules, share_server=None):
        """Reverts a share (in place) to the specified snapshot."""
        return self.client.restore_snapshot(snapshot['id'])

    @staticmethod
    def _setup_replica_client(replica):
        src_backend_name = share_utils.extract_host(replica['host'],
                                                    level='backend_name')
        src_conf = unity_utils.get_backend_config(CONF, src_backend_name)
        return client.UnityClient(src_conf.emc_nas_server,
                                  src_conf.emc_nas_login,
                                  src_conf.emc_nas_password)

    def create_replica(self, context, replica_list, new_replica,
                       access_rules, replica_snapshots, share_server=None):
        """Replicate the active replica to a new replica on this backend.

        This call is made on the host that the new replica is being created
        upon.

        Unity only supports `dr` type of replications due to the destination
        share in the replication cannot be mounted for even read.
        """

        active_replica = share_utils.get_active_replica(replica_list)
        src_client = self._setup_replica_client(active_replica)
        src_share, dst_share = src_client.get_shares_of_replica(active_replica)
        # src_share and dst_share cannot be all None
        # src_share and dst_share could be one of below cases:
        # 1. src_share is None and dst_share is not, which means the active
        # replica is already a destination in a REMOTE replication.
        if not src_share:
            raise exception.EMCUnityError(
                err='active replica share: {} is already the destination of a '
                    'replication'.format(dst_share.get_id()))
        # 2. src_share is not None and dst_share is None, which means the
        # active replica is a) already a source in a REMOTE replication or
        # b) not in any replication.
        # 3. src_share is not None and dst_share is not None, which means the
        # active replica is already a source in a LOCAL replication.

        # For case #2 and #3, only check whether the active replica is
        # participating in a replication or not.
        rep_session = src_client.is_in_replication(src_share.filesystem,
                                                   is_source=True)
        if rep_session:
            raise exception.EMCUnityError(
                err='active replica share: {share} is already the source '
                    'of replication: {rep}'.format(share=src_share.get_id(),
                                                   rep=rep_session.name))

        dst_client = self.client
        dst_pool_name = share_utils.extract_host(new_replica['host'],
                                                 level='pool')
        dst_pool_id = dst_client.get_pool(name=dst_pool_name).get_id()
        src_serial_number = src_client.get_serial_number()
        dst_serial_number = dst_client.get_serial_number()
        # dst_system could be local system which is same as src system.
        # then local replication will be created in such case.
        dst_system = (None if src_serial_number == dst_serial_number else
                      src_client.get_remote_system(name=dst_serial_number))

        # Enable replication on nas server.
        src_client.enable_replication(
            src_share.filesystem.nas_server, dst_pool_id,
            remote_system=dst_system,
            max_out_of_sync_minutes=self.replication_rpo,
        )

        # Enable replication on filesystem.
        fs_rep = src_client.enable_replication(
            src_share.filesystem, dst_pool_id,
            remote_system=dst_system,
            max_out_of_sync_minutes=self.replication_rpo,
        )

        model_update = {
            'export_locations': [],
            'replica_state': (const.REPLICA_STATE_IN_SYNC
                              if src_client.is_replication_in_sync(fs_rep)
                              else const.REPLICA_STATE_OUT_OF_SYNC),
            'access_rules_status': const.ACCESS_STATE_ACTIVE,
        }
        return model_update

    @staticmethod
    def _delete_rep_from(_client, src_share, dst_share, force=False):

        # 1. Local replication exists if src_share and dst_share are not
        # None.
        # 2. Remote replication from src_share exists if src_share is not
        # None and dst_share is None.
        # 3. Remote replication to dst_share exists if src_share is None
        # and dst_share is not None.

        # Try to delete the replication session from source side if possible.

        if src_share:
            # Case #1 and #2.
            _client.disable_replication(src_share.filesystem,
                                        from_source=True)
            _client.disable_replication(src_share.filesystem.nas_server,
                                        from_source=True)
            return

        # Case #3.
        # Delete replication session from destination side only when
        # `force` is True.
        if force:
            LOG.info('deleting the replication from destination share: %s '
                     'because force is true',
                     dst_share.name)
            _client.disable_replication(dst_share.filesystem,
                                        from_source=False)
            _client.disable_replication(dst_share.filesystem.nas_server,
                                        from_source=False)
        else:
            raise DeleteRepSessionNotOnSrcError(
                'the system of replica is not the replication source side')

    @staticmethod
    def _is_system_down(_client, active_replica):
        try:
            src_share, dst_share = _client.get_shares_of_replica(
                active_replica)
            return False, src_share, dst_share
        except storops_ex.StoropsConnectTimeoutError as ex:
            LOG.info('the system of replica is down. Detail: %s', ex)
            return True, None, None

    def _delete_replica_resource(self, share, is_destination=False):
        if is_destination:
            # Unity doesn't allow to delete the share which on the destination
            # nas server. If that is the case, delete the filesystem directly.
            self.client.delete_filesystem(share.filesystem)
        else:
            # First delete share and filesystem.
            self._delete_backend_share(share)

        # Then delete nas server if it has no filesystem anymore.
        nas_server_name = share.filesystem.nas_server.name
        try:
            self.client.delete_nas_server(nas_server_name)
        except storops_ex.UnityNasServerHasFsError:
            LOG.info('nas server is used by filesystem. Skip the deletion of '
                     'nas server')

    def delete_replica(self, context, replica_list, replica_snapshots,
                       replica, share_server=None):
        """Delete a replica.

        This call is made on the host that hosts the replica being deleted.
        """

        replica_id = replica['id']
        active_replica = share_utils.get_active_replica(replica_list)
        if replica_id == active_replica['id']:
            raise exception.EMCUnityError(
                err='cannot delete active replica directly')

        dr_client = self.client
        active_client = self._setup_replica_client(active_replica)
        is_dr_down, dr_src_shr, dr_dst_shr = self._is_system_down(
            dr_client, active_replica)
        is_active_down, act_src_shr, act_dst_shr = self._is_system_down(
            active_client, active_replica)

        if is_dr_down and is_active_down:
            raise exception.EMCUnityError(
                err='both active and non-active replicas systems are down')

        if is_dr_down:  # active replica system is up
            LOG.info('the system of deleting replica: %s is down. Try to '
                     'delete the replication session on active replica system',
                     replica_id)
            try:
                self._delete_rep_from(active_client, act_src_shr, act_dst_shr)
            except DeleteRepSessionNotOnSrcError:
                LOG.info('the system of deleting replica is down but the '
                         'active replica system is not the source of '
                         'replication session. Deleting the replication '
                         'session of unreachable system from active '
                         'replica to make sure more replicas can be created')
                self._delete_rep_from(active_client, act_src_shr, act_dst_shr,
                                      force=True)

            # Just try to delete the replication session from the active
            # replica system and not to delete the non-active replica and its
            # nas server because its system is down.
            return

        if dr_src_shr and dr_dst_shr:
            # This is a LOCAL replication session.
            LOG.debug('replica: %(rep)s is involved in a local replication '
                      'session with source: %(src)s and destination: %(dst)s',
                      {'rep': replica_id, 'src': dr_src_shr.get_id(),
                       'dst': dr_dst_shr.get_id()})

            _, is_failover = dr_client.is_replication_failover(
                dr_src_shr.filesystem, is_source=True)

            self._delete_rep_from(dr_client, dr_src_shr, dr_dst_shr)

            if is_failover:
                # After the replication session failed over, the active replica
                # is the destination share. While the non-active replica is the
                # source share.
                LOG.debug('deleting the source share: %s because its '
                          'replication session was failed over',
                          dr_src_shr.get_id())
                self._delete_replica_resource(dr_src_shr)
            else:
                self._delete_replica_resource(dr_dst_shr, is_destination=True)
        elif dr_src_shr:
            # This is a REMOTE replication session with dr replica as the
            # source side and active replica as the destination.
            LOG.debug('replica: %s is involved in a remote replication '
                      'session and it is the source', replica_id)
            self._delete_rep_from(dr_client, dr_src_shr, dr_dst_shr)
            self._delete_replica_resource(dr_src_shr)
        elif dr_dst_shr:
            # This is a REMOTE replication session with active replica as the
            # source side and dr replica as the destination.
            LOG.debug('replica: %s is involved in a remote replication '
                      'session and it is the destination', replica_id)
            LOG.info('the system of deleting replica: %s is not the source of '
                     'the replication session. Try to delete the replication '
                     'session on active replica system',
                     replica_id)
            if is_active_down:
                LOG.info('although the system of deleting replica is not the '
                         'source of the replication session, still delete the '
                         'replication session from it because the active '
                         'replica system is down')
                self._delete_rep_from(dr_client, dr_src_shr, dr_dst_shr,
                                      force=True)  # force delete from dst
            else:
                LOG.debug('deleting replication session from active replica'
                          'system')
                self._delete_rep_from(active_client, act_src_shr, act_dst_shr)

            self._delete_replica_resource(dr_dst_shr, is_destination=True)

        else:
            # dr_src_shr and dr_dst_shr cannot be ALL None.
            raise exception.EMCUnityError(
                err='cannot get any backend share '
                    'for replica: {}'.format(replica_id))

    def promote_replica(self, context, replica_list, replica, access_rules,
                        share_server=None):
        """Promote a replica to 'active' replica state.

        This call is made on the host that hosts the replica being promoted.
        """
        active_replica = share_utils.get_active_replica(replica_list)
        src_share, dst_share = self.client.get_shares_of_replica(
            active_replica)

        # 1. Local replication exists if src_share and dst_share are not
        # None.
        # 2. Remote replication from src_share exists if src_share is not
        # None and dst_share is None.
        # 3. Remote replication to dst_share exists if src_share is None
        # and dst_share is not None.

        if dst_share:
            share = dst_share
            nas_server = share.filesytem.nas_server
            self.client.failover_replication(nas_server)
        else:
            share = src_share
            nas_server = share.filesytem.nas_server
            self.client.failback_replication(nas_server)
        # No need to fail over/back filesystem replication because it will be
        # failed over/back with nas server's.

        for rep in replica_list:
            if rep['id'] == replica['id']:
                rep['export_locations'] = self._get_export_location(
                    nas_server.file_interface,
                    active_replica['share_proto'],
                    share.name,
                )
            else:
                rep['export_locations'] = []
        return replica_list

    def update_replica_state(self, context, replica_list, replica,
                             access_rules, replica_snapshots,
                             share_server=None):
        """Update the replica_state of a replica.

        This call is made on the host which hosts the replica being updated.

        Three cases in consideration:
        1. the replication from active replica to non-active is normal.
        2. the replication is planned failed over.
        3. the replication is unplanned failed over.

        For different cases, the logic is different.
        1. Normal replication:
            1) call `sync` on replication session in the source side (active
               replica).
            2) return `in_sync` (but possibly within the RPO of the replication
               session) if the replication session status indicates in sync.
        2. Planned/unplanned failed over replication:
            1) call `resume` on replication session in the destination side (
               active replica).
            2) return `out_of_sync` (it could be in sync after next poll).
        """

        active_replica = share_utils.get_active_replica(replica_list)
        active_client = self._setup_replica_client(active_replica)
        try:
            src_share, dst_share = active_client.get_shares_of_replica(
                active_replica)
        except storops_ex.StoropsConnectTimeoutError:
            LOG.info('system of active replica: %s is down',
                     active_replica['id'])
            return const.REPLICA_STATE_OUT_OF_SYNC

        # 1. Local replication exists in the system of active replication if
        # src_share and dst_share are not None.
        # 2. Remote replication from src_share exists if src_share is not
        # None and dst_share is None. The system of active replica is the
        # source side of the replication session.
        # 3. Remote replication to dst_share exists if src_share is None
        # and dst_share is not None. The system of active replica is the
        # destination side of the replication session. It'll be this case after
        # planned/unplanned failover.

        if src_share:
            # Case #1 and #2, sync the replication session in active replica
            # system.
            fs = src_share.filesystem
            rep_session, is_failover = active_client.is_replication_failover(
                fs, is_source=True)
            if not rep_session:
                LOG.error('filesystem: %s of active replica is not in a '
                          'replication', fs.get_id())
                return const.STATUS_ERROR

            if not is_failover:
                # Sync the filesystem replication session and the data of the
                # share will be synced.
                rep_session.sync()
                rep_session.update()
                return (const.REPLICA_STATE_IN_SYNC
                        if active_client.is_replication_in_sync(rep_session)
                        else const.REPLICA_STATE_OUT_OF_SYNC)

        # For planned and unplanned failed-over replications.
        # dst_share cannot be None.
        nas_server = dst_share.filesystem.nas_server
        nas_session = active_client.is_in_replication(nas_server,
                                                      is_source=False)
        nas_session.resume()

        fs_session = active_client.is_in_replication(dst_share.filesystem,
                                                     is_source=False)
        return (const.REPLICA_STATE_IN_SYNC
                if active_client.is_replication_in_sync(fs_session)
                else const.REPLICA_STATE_OUT_OF_SYNC)


class DeleteRepSessionError(Exception):
    pass


class DeleteRepSessionNotOnSrcError(DeleteRepSessionError):
    pass
