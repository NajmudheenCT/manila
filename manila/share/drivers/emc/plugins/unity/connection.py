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

import fnmatch

from oslo_log import log
from oslo_utils import excutils
from oslo_utils import importutils
from oslo_utils import units

storops = importutils.try_import('storops')
if storops:
    from storops import exception as storops_ex
    from storops.unity import enums

from manila.common import constants as const
from manila import exception
from manila.i18n import _, _LE, _LW
from manila.share.drivers.emc.plugins import base as driver
from manila.share.drivers.emc.plugins.unity import client
from manila.share.drivers.emc.plugins.vnx import utils as vnx_utils
from manila.share import utils as share_utils
from manila import utils

VERSION = "1.0.0"

LOG = log.getLogger(__name__)


@vnx_utils.decorate_all_methods(vnx_utils.log_enter_exit,
                                debug_only=True)
class UnityStorageConnection(driver.StorageConnection):
    """Implements Unity specific functionality for EMC Manila driver."""

    IP_ALLOCATIONS = 2

    @vnx_utils.log_enter_exit
    def __init__(self, *args, **kwargs):
        super(UnityStorageConnection, self).__init__(*args, **kwargs)
        self.client = None
        self.pool_set = None
        self.port_set = None
        self.nas_server_pool = None
        self.storage_processor = None
        self.reserved_percentage = None

        # props from super class.
        self.driver_handles_share_servers = True

    def connect(self, emc_share_driver, context):
        """Connect to Unity storage."""
        storage_ip = emc_share_driver.configuration.emc_nas_server
        username = emc_share_driver.configuration.emc_nas_login
        password = emc_share_driver.configuration.emc_nas_password
        sp_name = emc_share_driver.configuration.emc_nas_server_container
        self.client = client.UnityClient(storage_ip, username, password)

        pool_conf = emc_share_driver.configuration.safe_get(
            'emc_nas_pool_names')
        self.pool_set = self._get_managed_pools(pool_conf)

        self.reserved_percentage = emc_share_driver.configuration.safe_get(
            'reserved_share_percentage')
        if self.reserved_percentage is None:
            self.reserved_percentage = 0

        self._config_sp(sp_name)

        port_conf = emc_share_driver.configuration.safe_get(
            'emc_interface_ports')
        self.port_set = self._get_managed_ports(
            port_conf, self.storage_processor)

        pool_name = emc_share_driver.configuration.emc_nas_server_pool
        self._config_pool(pool_name)

    def _config_pool(self, pool_name):
        try:
            self.nas_server_pool = self.client.get_pool(pool_name)
        except storops_ex.UnityResourceNotFoundError:
            message = (_LE("The storage pools %s to store nas server "
                           "configuration do not exist.") % pool_name)
            LOG.error(message)
            raise exception.InvalidParameterValue(err=message)

    def _config_sp(self, sp_name):
        self.storage_processor = self.client.get_storage_processor(
            sp_name.lower())
        if self.storage_processor is None:
            message = (_LE("The storage processor %s does not exist or "
                           "is unavailable. Please reconfigure it in "
                           "manila.conf.") % sp_name)
            LOG.error(message)
            raise exception.InvalidParameterValue(err=message)

    def check_for_setup_error(self):
        """Check for setup error."""

    def create_share(self, context, share, share_server=None):
        """Create a share and export it based on protocol used."""
        share_name = share['id']
        size = share['size'] * units.Gi

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
            message = (_LE("Failed to get NAS server %(server)s when "
                           "creating the share %(share)s.") %
                       {'server': server_name, 'share': share_name})
            LOG.error(message)
            raise exception.EMCUnityError(err=message)

        filesystem = self.client.create_filesystem(
            pool, nas_server, share_name, size, proto=proto_enum)

        location = None
        if share_proto == 'CIFS':
            cifs_share = self.client.create_cifs_share(filesystem, share_name)

            cifs_share.enable_ace()

            location = self._get_cifs_location(
                nas_server.file_interface, share_name)
        elif share_proto == 'NFS':
            self.client.create_nfs_share(filesystem, share_name)

            location = self._get_nfs_location(
                nas_server.file_interface, share_name)

        return location

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
            message = (_LE("Failed to get NAS server %(server)s when "
                           "creating the share %(share)s.") %
                       {'server': server_name, 'share': share_name})
            LOG.error(message)
            raise exception.EMCUnityError(err=message)

        backend_snap = self.client.create_snap_of_snap(snapshot['id'],
                                                       share_name,
                                                       snap_type='snapshot')

        location = None
        if share_proto == 'CIFS':
            self.client.create_cifs_share(backend_snap, share_name)

            location = self._get_cifs_location(
                nas_server.file_interface, share_name)
        elif share_proto == 'NFS':
            self.client.create_nfs_share(backend_snap, share_name)

            location = self._get_nfs_location(
                nas_server.file_interface, share_name)

        return location

    @staticmethod
    def _get_cifs_location(file_interfaces, share_name):
        return [
            {'path': r'\\%(interface)s\%(share_name)s' % {
                'interface': interface.ip_address,
                'share_name': share_name}
             }
            for interface in file_interfaces
        ]

    @staticmethod
    def _get_nfs_location(file_interfaces, share_name):
        return [
            {'path': '%(interface)s:/%(share_name)s' % {
                'interface': interface.ip_address,
                'share_name': share_name}
             }
            for interface in file_interfaces
        ]

    def delete_share(self, context, share, share_server=None):
        """Delete a share."""
        share_name = share['id']
        try:
            backend_share = self.client.get_share(share_name,
                                                  share['share_proto'])
        except storops_ex.UnityResourceNotFoundError:
            LOG.warning(_LW("Share %s is not found when deleting the share"),
                        share_name)
            return

        # Share created by the API create_share_from_snapshot()
        if self._is_share_from_snapshot(backend_share):
            filesystem = backend_share.snap.filesystem
            self.client.delete_snapshot(backend_share.snap)

            if self._is_isolated_filesystem(filesystem):
                self.client.delete_filesystem(filesystem)
        else:
            filesystem = backend_share.filesystem
            self.client.delete_share(backend_share)

            if self._is_isolated_filesystem(filesystem):
                self.client.delete_filesystem(filesystem)

    def extend_share(self, share, new_size, share_server=None):
        if new_size < share['size']:
            message = (_LE("Failed to extend file system %(name)s because "
                           "new size %(new_size)d is smaller than old size"
                           " %(size)d.") %
                       {'name': share['id'], 'new_size': new_size,
                        'size': share['size']})
            LOG.error(message)
            raise exception.InvalidInput(reason=message)
        elif new_size == share['size']:
            return

        backend_share = self.client.get_share(share['id'],
                                              share['share_proto'])

        if not self._is_share_from_snapshot(backend_share):
            backend_share.filesystem.extend(new_size * units.Gi)
        else:
            share_id = share['id']
            reason = _LE("Driver does not support extending a "
                         "snapshot based share.")
            raise exception.ShareExtendingError(share_id=share_id,
                                                reason=reason)

    def create_snapshot(self, context, snapshot, share_server=None):
        """Create snapshot from share."""
        share_name = snapshot['share_id']
        share_proto = snapshot['share']['share_proto']
        backend_share = self.client.get_share(share_name, share_proto)

        snapshot_name = snapshot['id']
        if self._is_share_from_snapshot(backend_share):
            self.client.create_snap_of_snap(backend_share.snap,
                                            snapshot_name,
                                            snap_type='checkpoint')
        else:
            self.client.create_snapshot(backend_share.filesystem,
                                        snapshot_name)

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Delete a snapshot."""
        snap = self.client.get_snapshot(snapshot['id'])
        self.client.delete_snapshot(snap)

    def update_access(self, context, share, access, add_rules,
                      delete_rules, share_server=None):
        # adding rules
        if add_rules:
            self.allow_access(context, share, add_rules, share_server)
        # deleting rules
        if delete_rules:
            self.deny_access(context, share, delete_rules, share_server)

        # recovery mode
        if not add_rules and not delete_rules:
            self.clear_access(share)
            self.allow_access(context, share, access, share_server)

    def clear_access(self, share):
        share_proto = share['share_proto'].upper()
        share_name = share['id']
        if share_proto == 'CIFS':
            self.client.cifs_clear_access(share_name)
        elif share_proto == 'NFS':
            self.client.nfs_clear_access(share_name)

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
                total_size = float(pool.size_total)
                used_size = float(pool.size_used)

                pool_stat = {
                    "pool_name": pool.name,
                    "total_capacity_gb": total_size,
                    "free_capacity_gb": total_size - used_size,
                    "QoS_support": False,
                    "reserved_percentage": self.reserved_percentage}
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
        nas_server = self.client.create_nas_server(server_name,
                                                   self.storage_processor,
                                                   self.nas_server_pool)

        try:
            for network in network_info['network_allocations']:
                ip_addr = network['ip_address']
                netmask = utils.cidr_to_netmask(network['cidr'])
                gateway = network['gateway']
                vlan_id = network['segmentation_id']

                # Create the interfaces on NAS server
                self.client.create_interface(nas_server,
                                             ip_addr,
                                             netmask,
                                             gateway,
                                             ports=self.port_set,
                                             vlan_id=vlan_id)

            kerberos_enabled = False
            if 'security_services' in network_info:
                for security_service in network_info['security_services']:
                    # Support 'active_directory' and 'kerberos'
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
                        LOG.warning(_LW('Kerberos is not supported by '
                                        'EMC Unity manila driver plugin.'))
                    elif service_type == 'ldap':
                        LOG.warning(_LW('LDAP is not supported by '
                                        'EMC Unity manila driver plugin.'))
                    else:
                        LOG.warning(_LW('Unknown security service type: %s.'),
                                    service_type)

            if not kerberos_enabled:
                # Enable NFS service without kerberos
                self.client.enable_nfs_service(nas_server)

            return {
                'share_server_name': server_name,
            }
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Could not setup server. Reason: %s.'), ex)
                server_details = {
                    'share_server_name': server_name,
                }
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

    @staticmethod
    def _do_match(full, matcher_list):
        matched = set()
        not_matched = set()

        full = set([item.strip() for item in full])
        matcher_list = set([item.strip() for item in matcher_list])
        for item in full:
            for matcher in matcher_list:
                if fnmatch.fnmatchcase(item, matcher):
                    matched.add(item)
                else:
                    not_matched.add(item)
        return matched, not_matched

    def _get_managed_pools(self, pool_conf):
        # Get the real pools from the backend storage
        real_pools = set([pool.name for pool in self.client.get_pool()])

        if not pool_conf:
            LOG.debug("No storage pool is specified, so all pools in storage "
                      "system will be managed.")
            return real_pools

        matched_pools, unmanaged_pools = self._do_match(real_pools, pool_conf)

        if not matched_pools:
            msg = (_("All the specified storage pools to be managed "
                     "do not exist. Please check your configuration "
                     "emc_nas_pool_names in manila.conf. "
                     "The available pools in the backend are %s") %
                   ",".join(real_pools))
            raise exception.InvalidParameterValue(err=msg)

        if unmanaged_pools:
            LOG.warning(_LW("The following specified storage pools "
                            "are not managed by the backend: "
                            "%(un_managed)s. This host will only manage "
                            "the storage pools: %(exist)s"),
                        {'un_managed': ",".join(unmanaged_pools),
                         'exist': ",".join(matched_pools)})
        else:
            LOG.debug("Storage pools: %s will be managed.",
                      ",".join(matched_pools))

        return matched_pools

    def _get_managed_ports(self, port_conf, sp):
        # Get the real ports from the backend storage
        real_ports = set([port.id for port in self.client.get_ip_ports(sp)])

        if not port_conf:
            LOG.debug("No ports are specified, so all ports in storage "
                      "system will be managed.")
            return real_ports

        matched_ports, unmanaged_ports = self._do_match(real_ports, port_conf)

        if not matched_ports:
            msg = (_("All the specified storage ports to be managed "
                     "do not exist. Please check your configuration "
                     "emc_interface_ports in manila.conf. "
                     "The available ports in the backend are %s") %
                   ",".join(real_ports))
            raise exception.InvalidParameterValue(err=msg)

        if unmanaged_ports:
            LOG.warning(_LW("The following specified ports "
                            "are not managed by the backend: "
                            "%(un_managed)s. This host will only manage "
                            "the storage ports: %(exist)s"),
                        {'un_managed': ",".join(unmanaged_ports),
                         'exist': ",".join(matched_ports)})
        else:
            LOG.debug("Ports: %s will be managed.",
                      ",".join(matched_ports))

        return matched_ports

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
            msg = _LE("Name of the share server %s not found.")
            LOG.error(msg, share_server['id'])
            raise exception.InvalidInput(reason=msg)

        return server_name

    def _cifs_allow_access(self, share, access):
        """Allow access to CIFS share."""
        self.client.cifs_allow_access(
            share['id'], access['access_to'], access['access_level'])

    def _nfs_allow_access(self, share, access):
        """Allow access to NFS share."""
        self.client.nfs_allow_access(
            share['id'], access['access_to'], access['access_level'])

    def _cifs_deny_access(self, share, access):
        """Deny access to CIFS share."""
        self.client.cifs_deny_access(share['id'], access['access_to'])

    def _nfs_deny_access(self, share, access):
        """Deny access to NFS share."""
        self.client.nfs_deny_access(share['id'], access['access_to'])

    @staticmethod
    def _is_isolated_filesystem(filesystem):
        filesystem.update()
        return (
            filesystem.snap_count == 0 and
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
            reason = _('Only user access type allowed for CIFS share')
        elif share_proto == 'NFS' and access['access_type'] != 'ip':
            reason = _('Only ip access type allowed for NFS share.')

        if reason:
            raise exception.InvalidShareAccess(reason=reason)

    @staticmethod
    def _validate_share_protocol(share_proto):
        if share_proto not in ('NFS', 'CIFS'):
            raise exception.InvalidShare(
                reason=(_('Invalid NAS protocol supplied: %s.') %
                        share_proto))
