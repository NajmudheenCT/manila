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
import six

from oslo_log import log
from oslo_utils import excutils
from oslo_utils import importutils

storops = importutils.try_import('storops')
if storops:
    # pylint: disable=import-error
    from storops import exception as storops_ex
    from storops.unity import enums

from manila.common import constants as const
from manila import exception
from manila.i18n import _
from manila.share.drivers.dell_emc.common.enas import utils as enas_utils
from manila.share.drivers.dell_emc.plugins.unity import utils

LOG = log.getLogger(__name__)


class UnityClient(object):
    def __init__(self, host, username, password):
        if storops is None:
            LOG.error('StorOps is required to run EMC Unity driver.')
        self.system = storops.UnitySystem(host, username, password)

    def create_cifs_share(self, resource, share_name):
        """Create CIFS share from the resource.

        :param resource: either UnityFilesystem or UnitySnap object
        :param share_name: CIFS share name
        :return: UnityCifsShare object
        """
        try:
            share = resource.create_cifs_share(share_name)
            try:
                # bug on unity: the enable ace API has bug for snap
                # based share.  Log the internal error if it happens.
                share.enable_ace()
            except storops_ex.UnityException:
                msg = ('Failed to enabled ACE for share: {}.')
                LOG.exception(msg.format(share_name))
            return share
        except storops_ex.UnitySmbShareNameExistedError:
            return self.get_share(share_name, 'CIFS')

    def create_nfs_share(self, resource, share_name):
        """Create NFS share from the resource.

        :param resource: either UnityFilesystem or UnitySnap object
        :param share_name: NFS share name
        :return: UnityNfsShare object
        """
        try:
            return resource.create_nfs_share(share_name)
        except storops_ex.UnityNfsShareNameExistedError:
            return self.get_share(share_name, 'NFS')

    def create_nfs_filesystem_and_share(self, pool, nas_server,
                                        share_name, size_gb):
        """Create filesystem and share from pool/NAS server.

        :param pool: pool for file system creation
        :param nas_server: nas server for file system creation
        :param share_name: file system and share name
        :param size_gb: file system size
        """
        size = utils.gib_to_byte(size_gb)
        pool.create_nfs_share(
            nas_server, share_name, size, user_cap=True)

    def get_share(self, name, share_proto):
        # Validate the share protocol
        proto = share_proto.upper()

        if proto == 'CIFS':
            return self.system.get_cifs_share(name=name)
        elif proto == 'NFS':
            return self.system.get_nfs_share(name=name)
        else:
            raise exception.BadConfigurationException(
                reason=_('Invalid NAS protocol supplied: %s.') % share_proto)

    @staticmethod
    def delete_share(share):
        share.delete()

    def create_filesystem(self, pool, nas_server, share_name, size_gb, proto):
        try:
            size = utils.gib_to_byte(size_gb)
            return pool.create_filesystem(nas_server,
                                          share_name,
                                          size,
                                          proto=proto,
                                          user_cap=True)
        except storops_ex.UnityFileSystemNameAlreadyExisted:
            LOG.debug('Filesystem %s already exists, '
                      'ignoring filesystem creation.', share_name)
            return self.system.get_filesystem(name=share_name)

    @staticmethod
    def delete_filesystem(filesystem):
        try:
            filesystem.delete()
        except storops_ex.UnityResourceNotFoundError:
            LOG.info('Filesystem %s is already removed.', filesystem.name)

    def create_nas_server(self, name, sp, pool, tenant=None):
        try:
            return self.system.create_nas_server(name, sp, pool,
                                                 tenant=tenant)
        except storops_ex.UnityNasServerNameUsedError:
            LOG.info('Share server %s already exists, ignoring share '
                     'server creation.', name)
            return self.get_nas_server(name)

    def get_nas_server(self, name):
        try:
            return self.system.get_nas_server(name=name)
        except storops_ex.UnityResourceNotFoundError:
            LOG.info('NAS server %s not found.', name)
            raise

    def delete_nas_server(self, name, username=None, password=None):
        tenant = None
        try:
            nas_server = self.get_nas_server(name=name)
            tenant = nas_server.tenant
            nas_server.delete(username=username, password=password)
        except storops_ex.UnityResourceNotFoundError:
            LOG.info('NAS server %s not found.', name)

        if tenant is not None:
            self._delete_tenant(tenant)

    @staticmethod
    def _delete_tenant(tenant):
        if tenant.nas_servers:
            LOG.debug('There are NAS servers belonging to the tenant %s. ',
                      'Do not delete it.',
                      tenant.get_id())
            return
        try:
            tenant.delete(delete_hosts=True)
        except storops_ex.UnityException as ex:
            LOG.warning('Delete tenant %(tenant)s failed with error: '
                        '%(ex)s. Leave the tenant on the system.',
                        {'tenant': tenant.get_id(),
                         'ex': ex})

    @staticmethod
    def create_dns_server(nas_server, domain, dns_ip):
        try:
            nas_server.create_dns_server(domain, dns_ip)
        except storops_ex.UnityOneDnsPerNasServerError:
            LOG.info('DNS server %s already exists, '
                     'ignoring DNS server creation.', domain)

    @staticmethod
    def create_interface(nas_server, ip_addr, netmask, gateway, port_id,
                         vlan_id=None, prefix_length=None):
        try:
            nas_server.create_file_interface(port_id,
                                             ip_addr,
                                             netmask=netmask,
                                             v6_prefix_length=prefix_length,
                                             gateway=gateway,
                                             vlan_id=vlan_id)
        except storops_ex.UnityIpAddressUsedError:
            raise exception.IPAddressInUse(ip=ip_addr)

    @staticmethod
    def enable_cifs_service(nas_server, domain, username, password):
        try:
            nas_server.enable_cifs_service(
                nas_server.file_interface,
                domain=domain,
                domain_username=username,
                domain_password=password)
        except storops_ex.UnitySmbNameInUseError:
            LOG.info('CIFS service on NAS server %s is '
                     'already enabled.', nas_server.name)

    @staticmethod
    def enable_nfs_service(nas_server):
        try:
            nas_server.enable_nfs_service()
        except storops_ex.UnityNfsAlreadyEnabledError:
            LOG.info('NFS service on NAS server %s is '
                     'already enabled.', nas_server.name)

    @staticmethod
    def create_snapshot(filesystem, name):
        access_type = enums.FilesystemSnapAccessTypeEnum.CHECKPOINT
        try:
            return filesystem.create_snap(name, fs_access_type=access_type)
        except storops_ex.UnitySnapNameInUseError:
            LOG.info('Snapshot %(snap)s on Filesystem %(fs)s already '
                     'exists.', {'snap': name, 'fs': filesystem.name})

    def create_snap_of_snap(self, src_snap, dst_snap_name):
        if isinstance(src_snap, six.string_types):
            snap = self.get_snapshot(name=src_snap)
        else:
            snap = src_snap

        try:
            return snap.create_snap(dst_snap_name)
        except storops_ex.UnitySnapNameInUseError:
            return self.get_snapshot(dst_snap_name)

    def get_snapshot(self, name):
        return self.system.get_snap(name=name)

    @staticmethod
    def delete_snapshot(snap):
        try:
            snap.delete()
        except storops_ex.UnityResourceNotFoundError:
            LOG.info('Snapshot %s is already removed.', snap.name)

    def get_pool(self, name=None):
        return self.system.get_pool(name=name)

    def get_storage_processor(self, sp_id=None):
        sp = self.system.get_sp(sp_id)
        if sp_id is None:
            # `sp` is a list of SPA and SPB.
            return [s for s in sp if s is not None and s.existed]
        else:
            return sp if sp.existed else None

    def cifs_clear_access(self, share_name, white_list=None):
        share = self.system.get_cifs_share(name=share_name)
        share.clear_access(white_list)

    def nfs_clear_access(self, share_name, white_list=None):
        share = self.system.get_nfs_share(name=share_name)
        share.clear_access(white_list, force_create_host=True)

    def cifs_allow_access(self, share_name, user_name, access_level):
        share = self.system.get_cifs_share(name=share_name)

        if access_level == const.ACCESS_LEVEL_RW:
            cifs_access = enums.ACEAccessLevelEnum.WRITE
        else:
            cifs_access = enums.ACEAccessLevelEnum.READ

        share.add_ace(user=user_name, access_level=cifs_access)

    def nfs_allow_access(self, share_name, host_ip, access_level):
        share = self.system.get_nfs_share(name=share_name)
        host_ip = enas_utils.convert_ipv6_format_if_needed(host_ip)
        if access_level == const.ACCESS_LEVEL_RW:
            share.allow_read_write_access(host_ip, force_create_host=True)
            share.allow_root_access(host_ip, force_create_host=True)
        else:
            share.allow_read_only_access(host_ip, force_create_host=True)

    def cifs_deny_access(self, share_name, user_name):
        share = self.system.get_cifs_share(name=share_name)

        share.delete_ace(user=user_name)

    def nfs_deny_access(self, share_name, host_ip):
        share = self.system.get_nfs_share(name=share_name)

        try:
            share.delete_access(host_ip)
        except storops_ex.UnityHostNotFoundException:
            LOG.info('%(host)s access to %(share)s is already removed.',
                     {'host': host_ip, 'share': share_name})

    def get_file_ports(self):
        ports = self.system.get_file_port()
        link_up_ports = []
        for port in ports:
            if port.is_link_up and self._is_external_port(port.id):
                link_up_ports.append(port)

        return link_up_ports

    def extend_filesystem(self, fs, new_size_gb):
        size = utils.gib_to_byte(new_size_gb)
        try:
            fs.extend(size, user_cap=True)
        except storops_ex.UnityNothingToModifyError:
            LOG.debug('The size of the file system %(id)s is %(size)s '
                      'bytes.', {'id': fs.get_id(), 'size': size})
        return size

    def shrink_filesystem(self, share_id, fs, new_size_gb):
        size = utils.gib_to_byte(new_size_gb)
        try:
            fs.shrink(size, user_cap=True)
        except storops_ex.UnityNothingToModifyError:
            LOG.debug('The size of the file system %(id)s is %(size)s '
                      'bytes.', {'id': fs.get_id(), 'size': size})
        except storops_ex.UnityShareShrinkSizeTooSmallError:
            LOG.error('The used size of the file system %(id)s is '
                      'bigger than input shrink size,'
                      'it may cause date loss.', {'id': fs.get_id()})
            raise exception.ShareShrinkingPossibleDataLoss(share_id=share_id)
        return size

    @staticmethod
    def _is_external_port(port_id):
        return 'eth' in port_id or '_la' in port_id

    def get_tenant(self, name, vlan_id):
        if not vlan_id:
            # Do not create vlan for flat network
            return None

        tenant = None
        try:
            tenant_name = "vlan_%(vlan_id)s_%(name)s" % {'vlan_id': vlan_id,
                                                         'name': name}
            tenant = self.system.create_tenant(tenant_name, vlans=[vlan_id])
        except (storops_ex.UnityVLANUsedByOtherTenantError,
                storops_ex.UnityTenantNameInUseError,
                storops_ex.UnityVLANAlreadyHasInterfaceError):
            with excutils.save_and_reraise_exception() as exc:
                tenant = self.system.get_tenant_use_vlan(vlan_id)
                if tenant is not None:
                    LOG.debug("The VLAN %s is already added into a tenant. "
                              "Use the existing VLAN tenant.", vlan_id)
                    exc.reraise = False
        except storops_ex.SystemAPINotSupported:
            LOG.info("This system doesn't support tenant.")

        return tenant

    def restore_snapshot(self, snap_name):
        snap = self.get_snapshot(snap_name)
        return snap.restore(delete_backup=True)

    def get_serial_number(self):
        return self.system.serial_number

    def get_remote_system(self, name=None):
        return self.system.get_remote_system(name=name)

    def get_replication_session(self,
                                src_resource_id=None, dst_resource_id=None):
        return self.system.get_replication_session(
            src_resource_id=src_resource_id, dst_resource_id=dst_resource_id)

    def get_shares_of_replica(self, active_replica):
        """Gets backend shares of the replica.

        :param active_replica: the active replica where to get the share name.
        :return a tuple of (src_share, dst_share). Only one of src_share and
            dst_share can have value for remote replication, the other is None.
            Both of src_share and dst_share are not None for local replication
            because these two shares are with same name.
        """

        def _is_dst(s):
            return s.filesystem.storage_resource.is_replication_destination

        # replica['id'] could be different from the share name on unity after
        # fail over. Parse the share name from export path.
        # Non-active replica has no export path because it is just a dr
        # replica, so always getting share from active replica.
        share_id = utils.get_share_id(active_replica)

        # For local replications, active and non-active replicas are different
        # unity shares but with same name. So, getting share by name could
        # return two shares. Need to get the right share based on the
        # is_replication_destination field of its resource. Active replica's
        # share has is_replication_destination=False while non-active replica's
        # share has is_replication_destination=True.
        shares = self.get_share(share_id, active_replica['share_proto'])
        src_share = None
        dst_share = None
        try:
            for share in shares:
                if _is_dst(share):
                    dst_share = share
                else:
                    src_share = share
        except TypeError:
            # shares is not iterable, which means it is a unity share instance,
            # not a list.
            share = shares
            if _is_dst(share):
                dst_share = share
            else:
                src_share = share

        return src_share, dst_share

    @staticmethod
    def is_replication_unplanned_failover(rep_session):
        enum = enums.ReplicationOpStatusEnum
        return rep_session.status in [
            # Some obvious status indicating it is failed over.
            enum.FAILED_OVER,
            enum.FAILED_OVER_MIXED,
        ]

    @staticmethod
    def is_replication_planned_failover(rep_session):
        enum = enums.ReplicationOpStatusEnum
        return rep_session.status in [
            # Some obvious status indicating it is failed over.
            enum.FAILED_OVER_WITH_SYNC,
            enum.FAILED_OVER_WITH_SYNC_MIXED,
        ]

    def is_replication_failover(self, resource, is_source=None):
        rep_session = self.is_in_replication(resource, is_source=is_source)
        if not rep_session:
            if is_source is None:
                role = 'any'
            elif is_source:
                role = 'source'
            else:
                role = 'destination'
            LOG.info('resource: %(res)s is not participating as %(role)s side '
                     'in any replication session',
                     {'res': resource.name, 'role': role})
            return None, False

        return (rep_session,
                (self.is_replication_unplanned_failover(rep_session)
                 or self.is_replication_planned_failover(rep_session)))

    @staticmethod
    def is_replication_in_sync(rep_session):
        enum = enums.ReplicationOpStatusEnum
        if rep_session.status not in [
            # Some obvious status indicating it is in sync.
            enum.ACTIVE,
            enum.IDLE,
            enum.IDLE_MIXED,
            enum.OK,
            enum.AUTO_SYNC_CONFIGURED,
            enum.AUTO_SYNC_CONFIGURED_MIXED,
        ]:
            return False

        enum = enums.ReplicationSessionSyncStateEnum
        if rep_session.sync_state not in [
            # Some obvious sync state indicating it is in sync.
            enum.IDLE,
            enum.IN_SYNC,
            enum.CONSISTENT,
        ]:
            return False
        return True

    def is_in_replication(self, resource, is_source=None):
        """Checks if `resource` is participating in a replication session.

        The implementation is based on the fact that only one replication
        session per nas server or filesystem is supported on unity.

        :param resource: could be nas server or filesystem instance.
        :param is_source: True - check if `resource` is the source of the
            replication, False - check if `resource` is the destination of the
            replication, None - just check if `resource` is participating in
            any replication, no matter is the source or destination.

        :return the replication session in which the `resource` is
            participating.
        """

        if isinstance(resource,
                      storops.unity.resource.filesystem.UnityFileSystem):
            resource = resource.storage_resource

        if is_source or is_source is None:
            rep_sessions = self.get_replication_session(
                src_resource_id=resource.get_id()
            )
            if len(rep_sessions):
                return rep_sessions[0]
        if not is_source:
            rep_sessions = self.get_replication_session(
                dst_resource_id=resource.get_id()
            )
            if len(rep_sessions):
                return rep_sessions[0]
        return None

    def enable_replication(self, resource, dst_pool_id, remote_system=None,
                           max_out_of_sync_minutes=60):
        """Create or update the replication with `resource` as source.

        It will validate if there is already replication session where the
        `resource` is participating. If yes, `max_time_out_of_sync` of
        the existing replication session will be updated to the value of
        `max_out_of_sync_minutes`. Otherwise, a new resource will be
        provisioned on the `dst_pool_id` of the `remote_system`.

        :param resource: the resource as the source of the replication, could
            be a nas server or a filesystem.
        :param dst_pool_id: the pool where the destination resource will be
            provisioned.
        :param remote_system: the remote system of the replication.
        :param max_out_of_sync_minutes: new max minutes out of sync.
        :return: the created replication session.
        """

        rep_session = self.is_in_replication(resource, is_source=True)
        if rep_session:
            # Only one replication session per resource is supported.
            LOG.info('resource: %(nas)s already participates in a '
                     'replication: %(rep)s',
                     {'nas': resource.name, 'rep': rep_session})

            # Check if the existing replication's destination system is as
            # expected.
            remote_system_name = (remote_system.name if remote_system
                                  else self.get_serial_number())
            if rep_session.remote_system.name != remote_system_name:
                raise exception.EMCUnityError(
                    err='the replication {rep} of resource: {res} not '
                        'target to the expected remote system: '
                        '{remote}'.format(res=resource.name,
                                          rep=rep_session,
                                          remote=remote_system_name)
                )

            # The replication of resource server already exists and valid.
            if rep_session.max_time_out_of_sync != max_out_of_sync_minutes:
                rep_session.modify(
                    max_time_out_of_sync=max_out_of_sync_minutes)
        else:
            rep_session = (
                resource.replicate_with_dst_resource_provisioning(
                    max_out_of_sync_minutes,
                    dst_pool_id,
                    remote_system=remote_system,
                )
            )
        return rep_session

    def disable_replication(self, resource, from_source=True):
        """Delete the replication of `resource`.

        The implementation is based on the fact that only one replication
        session per resource.

        :param resource: the replication of this resource will be deleted,
            could be a nas server or filesystem.
        :param from_source: True - delete the replication from the source
            resource, False - delete from the destination resource.
        :return None
        """
        # Suppose the existing replication is valid. No need to check, ie. if
        # the nas server is the source of the replication.
        rep_session = self.is_in_replication(resource, is_source=from_source)
        if rep_session:
            try:
                rep_session.delete()
            except storops_ex.UnityFileResourceReplicationInUseError:
                # This exception raised when deleting nas server replication
                # and its filesystem replication still exists.
                LOG.info('try to delete replication of nas server: %s but '
                         'failed because there is still filesystem '
                         'replication on the same nas server. Skip the '
                         'deletion of nas server replication this time',
                         resource.name)
        else:
            LOG.info('resource: %s is not in a replication.'
                     'Do nothing for replication deletion',
                     resource.name)

    def failover_replication(self, resource):
        """Fail over the replication of `resource`.

        This call must be made on the destination system of the replication
        session.

        :param resource: the resource whose replication session will be failed
            over.
        :return: None
        """
        rep_session = self.is_in_replication(resource, is_source=False)
        if not rep_session:
            LOG.info('resource: %s is not in a replication.'
                     'Do nothing for replication failover',
                     resource.name)
            return
        LOG.info('failing over the replication of resource: %s', resource.name)
        rep_session.failover()

    def failback_replication(self, resource):
        """Fail back the replication of `resource`.

        This call must be made on the source system of the replication
        session.

        :param resource: the resource whose replication session will be failed
            back.
        :return: None
        """
        rep_session = self.is_in_replication(resource, is_source=True)
        if not rep_session:
            LOG.info('resource: %s is not in a replication.'
                     'Do nothing for replication failback',
                     resource.name)
            return
        LOG.info('failing back the replication of resource: %s', resource.name)
        rep_session.failback()
