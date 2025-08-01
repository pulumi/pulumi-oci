# coding=utf-8
# *** WARNING: this file was generated by pulumi-language-python. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import builtins as _builtins
import warnings
import sys
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
if sys.version_info >= (3, 11):
    from typing import NotRequired, TypedDict, TypeAlias
else:
    from typing_extensions import NotRequired, TypedDict, TypeAlias
from .. import _utilities

__all__ = [
    'GetDbNodeResult',
    'AwaitableGetDbNodeResult',
    'get_db_node',
    'get_db_node_output',
]

@pulumi.output_type
class GetDbNodeResult:
    """
    A collection of values returned by getDbNode.
    """
    def __init__(__self__, additional_details=None, backup_ip_id=None, backup_ipv6id=None, backup_vnic2id=None, backup_vnic_id=None, cpu_core_count=None, db_node_id=None, db_node_storage_size_in_gbs=None, db_server_id=None, db_system_id=None, defined_tags=None, fault_domain=None, freeform_tags=None, host_ip_id=None, host_ipv6id=None, hostname=None, id=None, lifecycle_details=None, maintenance_type=None, memory_size_in_gbs=None, software_storage_size_in_gb=None, state=None, system_tags=None, time_created=None, time_maintenance_window_end=None, time_maintenance_window_start=None, total_cpu_core_count=None, vnic2id=None, vnic_id=None):
        if additional_details and not isinstance(additional_details, str):
            raise TypeError("Expected argument 'additional_details' to be a str")
        pulumi.set(__self__, "additional_details", additional_details)
        if backup_ip_id and not isinstance(backup_ip_id, str):
            raise TypeError("Expected argument 'backup_ip_id' to be a str")
        pulumi.set(__self__, "backup_ip_id", backup_ip_id)
        if backup_ipv6id and not isinstance(backup_ipv6id, str):
            raise TypeError("Expected argument 'backup_ipv6id' to be a str")
        pulumi.set(__self__, "backup_ipv6id", backup_ipv6id)
        if backup_vnic2id and not isinstance(backup_vnic2id, str):
            raise TypeError("Expected argument 'backup_vnic2id' to be a str")
        pulumi.set(__self__, "backup_vnic2id", backup_vnic2id)
        if backup_vnic_id and not isinstance(backup_vnic_id, str):
            raise TypeError("Expected argument 'backup_vnic_id' to be a str")
        pulumi.set(__self__, "backup_vnic_id", backup_vnic_id)
        if cpu_core_count and not isinstance(cpu_core_count, int):
            raise TypeError("Expected argument 'cpu_core_count' to be a int")
        pulumi.set(__self__, "cpu_core_count", cpu_core_count)
        if db_node_id and not isinstance(db_node_id, str):
            raise TypeError("Expected argument 'db_node_id' to be a str")
        pulumi.set(__self__, "db_node_id", db_node_id)
        if db_node_storage_size_in_gbs and not isinstance(db_node_storage_size_in_gbs, int):
            raise TypeError("Expected argument 'db_node_storage_size_in_gbs' to be a int")
        pulumi.set(__self__, "db_node_storage_size_in_gbs", db_node_storage_size_in_gbs)
        if db_server_id and not isinstance(db_server_id, str):
            raise TypeError("Expected argument 'db_server_id' to be a str")
        pulumi.set(__self__, "db_server_id", db_server_id)
        if db_system_id and not isinstance(db_system_id, str):
            raise TypeError("Expected argument 'db_system_id' to be a str")
        pulumi.set(__self__, "db_system_id", db_system_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if fault_domain and not isinstance(fault_domain, str):
            raise TypeError("Expected argument 'fault_domain' to be a str")
        pulumi.set(__self__, "fault_domain", fault_domain)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if host_ip_id and not isinstance(host_ip_id, str):
            raise TypeError("Expected argument 'host_ip_id' to be a str")
        pulumi.set(__self__, "host_ip_id", host_ip_id)
        if host_ipv6id and not isinstance(host_ipv6id, str):
            raise TypeError("Expected argument 'host_ipv6id' to be a str")
        pulumi.set(__self__, "host_ipv6id", host_ipv6id)
        if hostname and not isinstance(hostname, str):
            raise TypeError("Expected argument 'hostname' to be a str")
        pulumi.set(__self__, "hostname", hostname)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if maintenance_type and not isinstance(maintenance_type, str):
            raise TypeError("Expected argument 'maintenance_type' to be a str")
        pulumi.set(__self__, "maintenance_type", maintenance_type)
        if memory_size_in_gbs and not isinstance(memory_size_in_gbs, int):
            raise TypeError("Expected argument 'memory_size_in_gbs' to be a int")
        pulumi.set(__self__, "memory_size_in_gbs", memory_size_in_gbs)
        if software_storage_size_in_gb and not isinstance(software_storage_size_in_gb, int):
            raise TypeError("Expected argument 'software_storage_size_in_gb' to be a int")
        pulumi.set(__self__, "software_storage_size_in_gb", software_storage_size_in_gb)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if system_tags and not isinstance(system_tags, dict):
            raise TypeError("Expected argument 'system_tags' to be a dict")
        pulumi.set(__self__, "system_tags", system_tags)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_maintenance_window_end and not isinstance(time_maintenance_window_end, str):
            raise TypeError("Expected argument 'time_maintenance_window_end' to be a str")
        pulumi.set(__self__, "time_maintenance_window_end", time_maintenance_window_end)
        if time_maintenance_window_start and not isinstance(time_maintenance_window_start, str):
            raise TypeError("Expected argument 'time_maintenance_window_start' to be a str")
        pulumi.set(__self__, "time_maintenance_window_start", time_maintenance_window_start)
        if total_cpu_core_count and not isinstance(total_cpu_core_count, int):
            raise TypeError("Expected argument 'total_cpu_core_count' to be a int")
        pulumi.set(__self__, "total_cpu_core_count", total_cpu_core_count)
        if vnic2id and not isinstance(vnic2id, str):
            raise TypeError("Expected argument 'vnic2id' to be a str")
        pulumi.set(__self__, "vnic2id", vnic2id)
        if vnic_id and not isinstance(vnic_id, str):
            raise TypeError("Expected argument 'vnic_id' to be a str")
        pulumi.set(__self__, "vnic_id", vnic_id)

    @_builtins.property
    @pulumi.getter(name="additionalDetails")
    def additional_details(self) -> _builtins.str:
        """
        Additional information about the planned maintenance.
        """
        return pulumi.get(self, "additional_details")

    @_builtins.property
    @pulumi.getter(name="backupIpId")
    def backup_ip_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup IPv4 address associated with the database node. Use this OCID with either the [GetPrivateIp](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/PrivateIp/GetPrivateIp) or the [GetPublicIpByPrivateIpId](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/PublicIp/GetPublicIpByPrivateIpId) API to get the IPv4 address needed to make a database connection.
        """
        return pulumi.get(self, "backup_ip_id")

    @_builtins.property
    @pulumi.getter(name="backupIpv6id")
    def backup_ipv6id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup IPv6 address associated with the database node. Use this OCID with the [GetIpv6](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/Ipv6/GetIpv6) API to get the IPv6 address needed to make a database connection.
        """
        return pulumi.get(self, "backup_ipv6id")

    @_builtins.property
    @pulumi.getter(name="backupVnic2id")
    def backup_vnic2id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the second backup VNIC.
        """
        return pulumi.get(self, "backup_vnic2id")

    @_builtins.property
    @pulumi.getter(name="backupVnicId")
    def backup_vnic_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup VNIC.
        """
        return pulumi.get(self, "backup_vnic_id")

    @_builtins.property
    @pulumi.getter(name="cpuCoreCount")
    def cpu_core_count(self) -> _builtins.int:
        """
        The number of CPU cores enabled on the Db node.
        """
        return pulumi.get(self, "cpu_core_count")

    @_builtins.property
    @pulumi.getter(name="dbNodeId")
    def db_node_id(self) -> _builtins.str:
        return pulumi.get(self, "db_node_id")

    @_builtins.property
    @pulumi.getter(name="dbNodeStorageSizeInGbs")
    def db_node_storage_size_in_gbs(self) -> _builtins.int:
        """
        The allocated local node storage in GBs on the Db node.
        """
        return pulumi.get(self, "db_node_storage_size_in_gbs")

    @_builtins.property
    @pulumi.getter(name="dbServerId")
    def db_server_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exacc Db server associated with the database node.
        """
        return pulumi.get(self, "db_server_id")

    @_builtins.property
    @pulumi.getter(name="dbSystemId")
    def db_system_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system.
        """
        return pulumi.get(self, "db_system_id")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, _builtins.str]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter(name="faultDomain")
    def fault_domain(self) -> _builtins.str:
        """
        The name of the Fault Domain the instance is contained in.
        """
        return pulumi.get(self, "fault_domain")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, _builtins.str]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter(name="hostIpId")
    def host_ip_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the host IPv4 address associated with the database node. Use this OCID with either the [GetPrivateIp](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/PrivateIp/GetPrivateIp) or the [GetPublicIpByPrivateIpId](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/PublicIp/GetPublicIpByPrivateIpId) API to get the IPv4 address needed to make a database connection.
        """
        return pulumi.get(self, "host_ip_id")

    @_builtins.property
    @pulumi.getter(name="hostIpv6id")
    def host_ipv6id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the host IPv6 address associated with the database node. Use this OCID with the [GetIpv6](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/Ipv6/GetIpv6) API to get the IPv6 address needed to make a database connection.
        """
        return pulumi.get(self, "host_ipv6id")

    @_builtins.property
    @pulumi.getter
    def hostname(self) -> _builtins.str:
        """
        The host name for the database node.
        """
        return pulumi.get(self, "hostname")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database node.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> _builtins.str:
        """
        Information about the current lifecycle state.
        """
        return pulumi.get(self, "lifecycle_details")

    @_builtins.property
    @pulumi.getter(name="maintenanceType")
    def maintenance_type(self) -> _builtins.str:
        """
        The type of database node maintenance.
        """
        return pulumi.get(self, "maintenance_type")

    @_builtins.property
    @pulumi.getter(name="memorySizeInGbs")
    def memory_size_in_gbs(self) -> _builtins.int:
        """
        The allocated memory in GBs on the Db node.
        """
        return pulumi.get(self, "memory_size_in_gbs")

    @_builtins.property
    @pulumi.getter(name="softwareStorageSizeInGb")
    def software_storage_size_in_gb(self) -> _builtins.int:
        """
        The size (in GB) of the block storage volume allocation for the DB system. This attribute applies only for virtual machine DB systems.
        """
        return pulumi.get(self, "software_storage_size_in_gb")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current state of the database node.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, _builtins.str]:
        """
        System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        """
        return pulumi.get(self, "system_tags")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        The date and time that the database node was created.
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeMaintenanceWindowEnd")
    def time_maintenance_window_end(self) -> _builtins.str:
        """
        End date and time of maintenance window.
        """
        return pulumi.get(self, "time_maintenance_window_end")

    @_builtins.property
    @pulumi.getter(name="timeMaintenanceWindowStart")
    def time_maintenance_window_start(self) -> _builtins.str:
        """
        Start date and time of maintenance window.
        """
        return pulumi.get(self, "time_maintenance_window_start")

    @_builtins.property
    @pulumi.getter(name="totalCpuCoreCount")
    def total_cpu_core_count(self) -> _builtins.int:
        """
        The total number of CPU cores reserved on the Db node.
        """
        return pulumi.get(self, "total_cpu_core_count")

    @_builtins.property
    @pulumi.getter
    def vnic2id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the second VNIC.
        """
        return pulumi.get(self, "vnic2id")

    @_builtins.property
    @pulumi.getter(name="vnicId")
    def vnic_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VNIC.
        """
        return pulumi.get(self, "vnic_id")


class AwaitableGetDbNodeResult(GetDbNodeResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDbNodeResult(
            additional_details=self.additional_details,
            backup_ip_id=self.backup_ip_id,
            backup_ipv6id=self.backup_ipv6id,
            backup_vnic2id=self.backup_vnic2id,
            backup_vnic_id=self.backup_vnic_id,
            cpu_core_count=self.cpu_core_count,
            db_node_id=self.db_node_id,
            db_node_storage_size_in_gbs=self.db_node_storage_size_in_gbs,
            db_server_id=self.db_server_id,
            db_system_id=self.db_system_id,
            defined_tags=self.defined_tags,
            fault_domain=self.fault_domain,
            freeform_tags=self.freeform_tags,
            host_ip_id=self.host_ip_id,
            host_ipv6id=self.host_ipv6id,
            hostname=self.hostname,
            id=self.id,
            lifecycle_details=self.lifecycle_details,
            maintenance_type=self.maintenance_type,
            memory_size_in_gbs=self.memory_size_in_gbs,
            software_storage_size_in_gb=self.software_storage_size_in_gb,
            state=self.state,
            system_tags=self.system_tags,
            time_created=self.time_created,
            time_maintenance_window_end=self.time_maintenance_window_end,
            time_maintenance_window_start=self.time_maintenance_window_start,
            total_cpu_core_count=self.total_cpu_core_count,
            vnic2id=self.vnic2id,
            vnic_id=self.vnic_id)


def get_db_node(db_node_id: Optional[_builtins.str] = None,
                opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDbNodeResult:
    """
    This data source provides details about a specific Db Node resource in Oracle Cloud Infrastructure Database service.

    Gets information about the specified database node.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_db_node = oci.Database.get_db_node(db_node_id=db_node_id)
    ```


    :param _builtins.str db_node_id: The database node [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    """
    __args__ = dict()
    __args__['dbNodeId'] = db_node_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Database/getDbNode:getDbNode', __args__, opts=opts, typ=GetDbNodeResult).value

    return AwaitableGetDbNodeResult(
        additional_details=pulumi.get(__ret__, 'additional_details'),
        backup_ip_id=pulumi.get(__ret__, 'backup_ip_id'),
        backup_ipv6id=pulumi.get(__ret__, 'backup_ipv6id'),
        backup_vnic2id=pulumi.get(__ret__, 'backup_vnic2id'),
        backup_vnic_id=pulumi.get(__ret__, 'backup_vnic_id'),
        cpu_core_count=pulumi.get(__ret__, 'cpu_core_count'),
        db_node_id=pulumi.get(__ret__, 'db_node_id'),
        db_node_storage_size_in_gbs=pulumi.get(__ret__, 'db_node_storage_size_in_gbs'),
        db_server_id=pulumi.get(__ret__, 'db_server_id'),
        db_system_id=pulumi.get(__ret__, 'db_system_id'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        fault_domain=pulumi.get(__ret__, 'fault_domain'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        host_ip_id=pulumi.get(__ret__, 'host_ip_id'),
        host_ipv6id=pulumi.get(__ret__, 'host_ipv6id'),
        hostname=pulumi.get(__ret__, 'hostname'),
        id=pulumi.get(__ret__, 'id'),
        lifecycle_details=pulumi.get(__ret__, 'lifecycle_details'),
        maintenance_type=pulumi.get(__ret__, 'maintenance_type'),
        memory_size_in_gbs=pulumi.get(__ret__, 'memory_size_in_gbs'),
        software_storage_size_in_gb=pulumi.get(__ret__, 'software_storage_size_in_gb'),
        state=pulumi.get(__ret__, 'state'),
        system_tags=pulumi.get(__ret__, 'system_tags'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_maintenance_window_end=pulumi.get(__ret__, 'time_maintenance_window_end'),
        time_maintenance_window_start=pulumi.get(__ret__, 'time_maintenance_window_start'),
        total_cpu_core_count=pulumi.get(__ret__, 'total_cpu_core_count'),
        vnic2id=pulumi.get(__ret__, 'vnic2id'),
        vnic_id=pulumi.get(__ret__, 'vnic_id'))
def get_db_node_output(db_node_id: Optional[pulumi.Input[_builtins.str]] = None,
                       opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetDbNodeResult]:
    """
    This data source provides details about a specific Db Node resource in Oracle Cloud Infrastructure Database service.

    Gets information about the specified database node.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_db_node = oci.Database.get_db_node(db_node_id=db_node_id)
    ```


    :param _builtins.str db_node_id: The database node [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    """
    __args__ = dict()
    __args__['dbNodeId'] = db_node_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Database/getDbNode:getDbNode', __args__, opts=opts, typ=GetDbNodeResult)
    return __ret__.apply(lambda __response__: GetDbNodeResult(
        additional_details=pulumi.get(__response__, 'additional_details'),
        backup_ip_id=pulumi.get(__response__, 'backup_ip_id'),
        backup_ipv6id=pulumi.get(__response__, 'backup_ipv6id'),
        backup_vnic2id=pulumi.get(__response__, 'backup_vnic2id'),
        backup_vnic_id=pulumi.get(__response__, 'backup_vnic_id'),
        cpu_core_count=pulumi.get(__response__, 'cpu_core_count'),
        db_node_id=pulumi.get(__response__, 'db_node_id'),
        db_node_storage_size_in_gbs=pulumi.get(__response__, 'db_node_storage_size_in_gbs'),
        db_server_id=pulumi.get(__response__, 'db_server_id'),
        db_system_id=pulumi.get(__response__, 'db_system_id'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        fault_domain=pulumi.get(__response__, 'fault_domain'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        host_ip_id=pulumi.get(__response__, 'host_ip_id'),
        host_ipv6id=pulumi.get(__response__, 'host_ipv6id'),
        hostname=pulumi.get(__response__, 'hostname'),
        id=pulumi.get(__response__, 'id'),
        lifecycle_details=pulumi.get(__response__, 'lifecycle_details'),
        maintenance_type=pulumi.get(__response__, 'maintenance_type'),
        memory_size_in_gbs=pulumi.get(__response__, 'memory_size_in_gbs'),
        software_storage_size_in_gb=pulumi.get(__response__, 'software_storage_size_in_gb'),
        state=pulumi.get(__response__, 'state'),
        system_tags=pulumi.get(__response__, 'system_tags'),
        time_created=pulumi.get(__response__, 'time_created'),
        time_maintenance_window_end=pulumi.get(__response__, 'time_maintenance_window_end'),
        time_maintenance_window_start=pulumi.get(__response__, 'time_maintenance_window_start'),
        total_cpu_core_count=pulumi.get(__response__, 'total_cpu_core_count'),
        vnic2id=pulumi.get(__response__, 'vnic2id'),
        vnic_id=pulumi.get(__response__, 'vnic_id')))
