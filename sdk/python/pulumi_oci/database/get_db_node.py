# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
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
    def __init__(__self__, additional_details=None, backup_ip_id=None, backup_vnic2id=None, backup_vnic_id=None, cpu_core_count=None, db_node_id=None, db_node_storage_size_in_gbs=None, db_server_id=None, db_system_id=None, fault_domain=None, host_ip_id=None, hostname=None, id=None, maintenance_type=None, memory_size_in_gbs=None, software_storage_size_in_gb=None, state=None, time_created=None, time_maintenance_window_end=None, time_maintenance_window_start=None, vnic2id=None, vnic_id=None):
        if additional_details and not isinstance(additional_details, str):
            raise TypeError("Expected argument 'additional_details' to be a str")
        pulumi.set(__self__, "additional_details", additional_details)
        if backup_ip_id and not isinstance(backup_ip_id, str):
            raise TypeError("Expected argument 'backup_ip_id' to be a str")
        pulumi.set(__self__, "backup_ip_id", backup_ip_id)
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
        if fault_domain and not isinstance(fault_domain, str):
            raise TypeError("Expected argument 'fault_domain' to be a str")
        pulumi.set(__self__, "fault_domain", fault_domain)
        if host_ip_id and not isinstance(host_ip_id, str):
            raise TypeError("Expected argument 'host_ip_id' to be a str")
        pulumi.set(__self__, "host_ip_id", host_ip_id)
        if hostname and not isinstance(hostname, str):
            raise TypeError("Expected argument 'hostname' to be a str")
        pulumi.set(__self__, "hostname", hostname)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
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
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_maintenance_window_end and not isinstance(time_maintenance_window_end, str):
            raise TypeError("Expected argument 'time_maintenance_window_end' to be a str")
        pulumi.set(__self__, "time_maintenance_window_end", time_maintenance_window_end)
        if time_maintenance_window_start and not isinstance(time_maintenance_window_start, str):
            raise TypeError("Expected argument 'time_maintenance_window_start' to be a str")
        pulumi.set(__self__, "time_maintenance_window_start", time_maintenance_window_start)
        if vnic2id and not isinstance(vnic2id, str):
            raise TypeError("Expected argument 'vnic2id' to be a str")
        pulumi.set(__self__, "vnic2id", vnic2id)
        if vnic_id and not isinstance(vnic_id, str):
            raise TypeError("Expected argument 'vnic_id' to be a str")
        pulumi.set(__self__, "vnic_id", vnic_id)

    @property
    @pulumi.getter(name="additionalDetails")
    def additional_details(self) -> str:
        """
        Additional information about the planned maintenance.
        """
        return pulumi.get(self, "additional_details")

    @property
    @pulumi.getter(name="backupIpId")
    def backup_ip_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup IP address associated with the database node. Use this OCID with either the [GetPrivateIp](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/PrivateIp/GetPrivateIp) or the [GetPublicIpByPrivateIpId](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/PublicIp/GetPublicIpByPrivateIpId) API to get the IP address  needed to make a database connection.
        """
        return pulumi.get(self, "backup_ip_id")

    @property
    @pulumi.getter(name="backupVnic2id")
    def backup_vnic2id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the second backup VNIC.
        """
        return pulumi.get(self, "backup_vnic2id")

    @property
    @pulumi.getter(name="backupVnicId")
    def backup_vnic_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup VNIC.
        """
        return pulumi.get(self, "backup_vnic_id")

    @property
    @pulumi.getter(name="cpuCoreCount")
    def cpu_core_count(self) -> int:
        """
        The number of CPU cores enabled on the Db node.
        """
        return pulumi.get(self, "cpu_core_count")

    @property
    @pulumi.getter(name="dbNodeId")
    def db_node_id(self) -> str:
        return pulumi.get(self, "db_node_id")

    @property
    @pulumi.getter(name="dbNodeStorageSizeInGbs")
    def db_node_storage_size_in_gbs(self) -> int:
        """
        The allocated local node storage in GBs on the Db node.
        """
        return pulumi.get(self, "db_node_storage_size_in_gbs")

    @property
    @pulumi.getter(name="dbServerId")
    def db_server_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exacc Db server associated with the database node.
        """
        return pulumi.get(self, "db_server_id")

    @property
    @pulumi.getter(name="dbSystemId")
    def db_system_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system.
        """
        return pulumi.get(self, "db_system_id")

    @property
    @pulumi.getter(name="faultDomain")
    def fault_domain(self) -> str:
        """
        The name of the Fault Domain the instance is contained in.
        """
        return pulumi.get(self, "fault_domain")

    @property
    @pulumi.getter(name="hostIpId")
    def host_ip_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the host IP address associated with the database node. Use this OCID with either the  [GetPrivateIp](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/PrivateIp/GetPrivateIp) or the [GetPublicIpByPrivateIpId](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/PublicIp/GetPublicIpByPrivateIpId) API to get the IP address  needed to make a database connection.
        """
        return pulumi.get(self, "host_ip_id")

    @property
    @pulumi.getter
    def hostname(self) -> str:
        """
        The host name for the database node.
        """
        return pulumi.get(self, "hostname")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="maintenanceType")
    def maintenance_type(self) -> str:
        """
        The type of database node maintenance.
        """
        return pulumi.get(self, "maintenance_type")

    @property
    @pulumi.getter(name="memorySizeInGbs")
    def memory_size_in_gbs(self) -> int:
        """
        The allocated memory in GBs on the Db node.
        """
        return pulumi.get(self, "memory_size_in_gbs")

    @property
    @pulumi.getter(name="softwareStorageSizeInGb")
    def software_storage_size_in_gb(self) -> int:
        """
        The size (in GB) of the block storage volume allocation for the DB system. This attribute applies only for virtual machine DB systems.
        """
        return pulumi.get(self, "software_storage_size_in_gb")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The current state of the database node.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The date and time that the database node was created.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeMaintenanceWindowEnd")
    def time_maintenance_window_end(self) -> str:
        """
        End date and time of maintenance window.
        """
        return pulumi.get(self, "time_maintenance_window_end")

    @property
    @pulumi.getter(name="timeMaintenanceWindowStart")
    def time_maintenance_window_start(self) -> str:
        """
        Start date and time of maintenance window.
        """
        return pulumi.get(self, "time_maintenance_window_start")

    @property
    @pulumi.getter
    def vnic2id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the second VNIC.
        """
        return pulumi.get(self, "vnic2id")

    @property
    @pulumi.getter(name="vnicId")
    def vnic_id(self) -> str:
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
            backup_vnic2id=self.backup_vnic2id,
            backup_vnic_id=self.backup_vnic_id,
            cpu_core_count=self.cpu_core_count,
            db_node_id=self.db_node_id,
            db_node_storage_size_in_gbs=self.db_node_storage_size_in_gbs,
            db_server_id=self.db_server_id,
            db_system_id=self.db_system_id,
            fault_domain=self.fault_domain,
            host_ip_id=self.host_ip_id,
            hostname=self.hostname,
            id=self.id,
            maintenance_type=self.maintenance_type,
            memory_size_in_gbs=self.memory_size_in_gbs,
            software_storage_size_in_gb=self.software_storage_size_in_gb,
            state=self.state,
            time_created=self.time_created,
            time_maintenance_window_end=self.time_maintenance_window_end,
            time_maintenance_window_start=self.time_maintenance_window_start,
            vnic2id=self.vnic2id,
            vnic_id=self.vnic_id)


def get_db_node(db_node_id: Optional[str] = None,
                opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDbNodeResult:
    """
    This data source provides details about a specific Db Node resource in Oracle Cloud Infrastructure Database service.

    Gets information about the specified database node.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_db_node = oci.Database.get_db_node(db_node_id=var["db_node_id"])
    ```


    :param str db_node_id: The database node [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    """
    __args__ = dict()
    __args__['dbNodeId'] = db_node_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Database/getDbNode:getDbNode', __args__, opts=opts, typ=GetDbNodeResult).value

    return AwaitableGetDbNodeResult(
        additional_details=__ret__.additional_details,
        backup_ip_id=__ret__.backup_ip_id,
        backup_vnic2id=__ret__.backup_vnic2id,
        backup_vnic_id=__ret__.backup_vnic_id,
        cpu_core_count=__ret__.cpu_core_count,
        db_node_id=__ret__.db_node_id,
        db_node_storage_size_in_gbs=__ret__.db_node_storage_size_in_gbs,
        db_server_id=__ret__.db_server_id,
        db_system_id=__ret__.db_system_id,
        fault_domain=__ret__.fault_domain,
        host_ip_id=__ret__.host_ip_id,
        hostname=__ret__.hostname,
        id=__ret__.id,
        maintenance_type=__ret__.maintenance_type,
        memory_size_in_gbs=__ret__.memory_size_in_gbs,
        software_storage_size_in_gb=__ret__.software_storage_size_in_gb,
        state=__ret__.state,
        time_created=__ret__.time_created,
        time_maintenance_window_end=__ret__.time_maintenance_window_end,
        time_maintenance_window_start=__ret__.time_maintenance_window_start,
        vnic2id=__ret__.vnic2id,
        vnic_id=__ret__.vnic_id)


@_utilities.lift_output_func(get_db_node)
def get_db_node_output(db_node_id: Optional[pulumi.Input[str]] = None,
                       opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetDbNodeResult]:
    """
    This data source provides details about a specific Db Node resource in Oracle Cloud Infrastructure Database service.

    Gets information about the specified database node.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_db_node = oci.Database.get_db_node(db_node_id=var["db_node_id"])
    ```


    :param str db_node_id: The database node [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    """
    ...