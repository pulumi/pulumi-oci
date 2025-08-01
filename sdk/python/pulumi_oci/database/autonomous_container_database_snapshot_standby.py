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

__all__ = ['AutonomousContainerDatabaseSnapshotStandbyArgs', 'AutonomousContainerDatabaseSnapshotStandby']

@pulumi.input_type
class AutonomousContainerDatabaseSnapshotStandbyArgs:
    def __init__(__self__, *,
                 autonomous_container_database_id: pulumi.Input[_builtins.str],
                 role: pulumi.Input[_builtins.str],
                 connection_strings_type: Optional[pulumi.Input[_builtins.str]] = None):
        """
        The set of arguments for constructing a AutonomousContainerDatabaseSnapshotStandby resource.
        :param pulumi.Input[_builtins.str] autonomous_container_database_id: The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        :param pulumi.Input[_builtins.str] role: The Data Guard role of the Autonomous Container Database or Autonomous Database, if Autonomous Data Guard is enabled. 
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[_builtins.str] connection_strings_type: type of connection strings when converting database to snapshot mode
        """
        pulumi.set(__self__, "autonomous_container_database_id", autonomous_container_database_id)
        pulumi.set(__self__, "role", role)
        if connection_strings_type is not None:
            pulumi.set(__self__, "connection_strings_type", connection_strings_type)

    @_builtins.property
    @pulumi.getter(name="autonomousContainerDatabaseId")
    def autonomous_container_database_id(self) -> pulumi.Input[_builtins.str]:
        """
        The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        """
        return pulumi.get(self, "autonomous_container_database_id")

    @autonomous_container_database_id.setter
    def autonomous_container_database_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "autonomous_container_database_id", value)

    @_builtins.property
    @pulumi.getter
    def role(self) -> pulumi.Input[_builtins.str]:
        """
        The Data Guard role of the Autonomous Container Database or Autonomous Database, if Autonomous Data Guard is enabled. 


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "role")

    @role.setter
    def role(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "role", value)

    @_builtins.property
    @pulumi.getter(name="connectionStringsType")
    def connection_strings_type(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        type of connection strings when converting database to snapshot mode
        """
        return pulumi.get(self, "connection_strings_type")

    @connection_strings_type.setter
    def connection_strings_type(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "connection_strings_type", value)


@pulumi.input_type
class _AutonomousContainerDatabaseSnapshotStandbyState:
    def __init__(__self__, *,
                 autonomous_container_database_id: Optional[pulumi.Input[_builtins.str]] = None,
                 connection_strings_type: Optional[pulumi.Input[_builtins.str]] = None,
                 role: Optional[pulumi.Input[_builtins.str]] = None):
        """
        Input properties used for looking up and filtering AutonomousContainerDatabaseSnapshotStandby resources.
        :param pulumi.Input[_builtins.str] autonomous_container_database_id: The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        :param pulumi.Input[_builtins.str] connection_strings_type: type of connection strings when converting database to snapshot mode
        :param pulumi.Input[_builtins.str] role: The Data Guard role of the Autonomous Container Database or Autonomous Database, if Autonomous Data Guard is enabled. 
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        if autonomous_container_database_id is not None:
            pulumi.set(__self__, "autonomous_container_database_id", autonomous_container_database_id)
        if connection_strings_type is not None:
            pulumi.set(__self__, "connection_strings_type", connection_strings_type)
        if role is not None:
            pulumi.set(__self__, "role", role)

    @_builtins.property
    @pulumi.getter(name="autonomousContainerDatabaseId")
    def autonomous_container_database_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        """
        return pulumi.get(self, "autonomous_container_database_id")

    @autonomous_container_database_id.setter
    def autonomous_container_database_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "autonomous_container_database_id", value)

    @_builtins.property
    @pulumi.getter(name="connectionStringsType")
    def connection_strings_type(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        type of connection strings when converting database to snapshot mode
        """
        return pulumi.get(self, "connection_strings_type")

    @connection_strings_type.setter
    def connection_strings_type(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "connection_strings_type", value)

    @_builtins.property
    @pulumi.getter
    def role(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The Data Guard role of the Autonomous Container Database or Autonomous Database, if Autonomous Data Guard is enabled. 


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "role")

    @role.setter
    def role(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "role", value)


@pulumi.type_token("oci:Database/autonomousContainerDatabaseSnapshotStandby:AutonomousContainerDatabaseSnapshotStandby")
class AutonomousContainerDatabaseSnapshotStandby(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 autonomous_container_database_id: Optional[pulumi.Input[_builtins.str]] = None,
                 connection_strings_type: Optional[pulumi.Input[_builtins.str]] = None,
                 role: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        """
        This resource provides the Autonomous Container Database Snapshot Standby resource in Oracle Cloud Infrastructure Database service.

        Convert the standby Autonomous Container Database (ACD) between physical standby and snapshot standby ACD. For more information about converting standby ACDs, see
        [Convert Physical Standby to Snapshot Standby](https://docs.oracle.com/en/cloud/paas/autonomous-database/dedicated/adbcl/index.html#ADBCL-GUID-D3B503F1-0032-4B0D-9F00-ACAE8151AB80) and [Convert Snapshot Standby to Physical Standby](https://docs.oracle.com/en/cloud/paas/autonomous-database/dedicated/adbcl/index.html#ADBCL-GUID-E8D7E0EE-8244-467D-B33A-1BC6F969A0A4).

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_autonomous_container_database_snapshot_standby = oci.database.AutonomousContainerDatabaseSnapshotStandby("test_autonomous_container_database_snapshot_standby",
            autonomous_container_database_id=test_autonomous_container_database["id"],
            role=autonomous_container_database_snapshot_standby_role,
            connection_strings_type=autonomous_container_database_snapshot_standby_connection_strings_type)
        ```

        ## Import

        AutonomousContainerDatabaseSnapshotStandby can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:Database/autonomousContainerDatabaseSnapshotStandby:AutonomousContainerDatabaseSnapshotStandby test_autonomous_container_database_snapshot_standby "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] autonomous_container_database_id: The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        :param pulumi.Input[_builtins.str] connection_strings_type: type of connection strings when converting database to snapshot mode
        :param pulumi.Input[_builtins.str] role: The Data Guard role of the Autonomous Container Database or Autonomous Database, if Autonomous Data Guard is enabled. 
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: AutonomousContainerDatabaseSnapshotStandbyArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Autonomous Container Database Snapshot Standby resource in Oracle Cloud Infrastructure Database service.

        Convert the standby Autonomous Container Database (ACD) between physical standby and snapshot standby ACD. For more information about converting standby ACDs, see
        [Convert Physical Standby to Snapshot Standby](https://docs.oracle.com/en/cloud/paas/autonomous-database/dedicated/adbcl/index.html#ADBCL-GUID-D3B503F1-0032-4B0D-9F00-ACAE8151AB80) and [Convert Snapshot Standby to Physical Standby](https://docs.oracle.com/en/cloud/paas/autonomous-database/dedicated/adbcl/index.html#ADBCL-GUID-E8D7E0EE-8244-467D-B33A-1BC6F969A0A4).

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_autonomous_container_database_snapshot_standby = oci.database.AutonomousContainerDatabaseSnapshotStandby("test_autonomous_container_database_snapshot_standby",
            autonomous_container_database_id=test_autonomous_container_database["id"],
            role=autonomous_container_database_snapshot_standby_role,
            connection_strings_type=autonomous_container_database_snapshot_standby_connection_strings_type)
        ```

        ## Import

        AutonomousContainerDatabaseSnapshotStandby can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:Database/autonomousContainerDatabaseSnapshotStandby:AutonomousContainerDatabaseSnapshotStandby test_autonomous_container_database_snapshot_standby "id"
        ```

        :param str resource_name: The name of the resource.
        :param AutonomousContainerDatabaseSnapshotStandbyArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(AutonomousContainerDatabaseSnapshotStandbyArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 autonomous_container_database_id: Optional[pulumi.Input[_builtins.str]] = None,
                 connection_strings_type: Optional[pulumi.Input[_builtins.str]] = None,
                 role: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = AutonomousContainerDatabaseSnapshotStandbyArgs.__new__(AutonomousContainerDatabaseSnapshotStandbyArgs)

            if autonomous_container_database_id is None and not opts.urn:
                raise TypeError("Missing required property 'autonomous_container_database_id'")
            __props__.__dict__["autonomous_container_database_id"] = autonomous_container_database_id
            __props__.__dict__["connection_strings_type"] = connection_strings_type
            if role is None and not opts.urn:
                raise TypeError("Missing required property 'role'")
            __props__.__dict__["role"] = role
        super(AutonomousContainerDatabaseSnapshotStandby, __self__).__init__(
            'oci:Database/autonomousContainerDatabaseSnapshotStandby:AutonomousContainerDatabaseSnapshotStandby',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            autonomous_container_database_id: Optional[pulumi.Input[_builtins.str]] = None,
            connection_strings_type: Optional[pulumi.Input[_builtins.str]] = None,
            role: Optional[pulumi.Input[_builtins.str]] = None) -> 'AutonomousContainerDatabaseSnapshotStandby':
        """
        Get an existing AutonomousContainerDatabaseSnapshotStandby resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] autonomous_container_database_id: The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        :param pulumi.Input[_builtins.str] connection_strings_type: type of connection strings when converting database to snapshot mode
        :param pulumi.Input[_builtins.str] role: The Data Guard role of the Autonomous Container Database or Autonomous Database, if Autonomous Data Guard is enabled. 
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _AutonomousContainerDatabaseSnapshotStandbyState.__new__(_AutonomousContainerDatabaseSnapshotStandbyState)

        __props__.__dict__["autonomous_container_database_id"] = autonomous_container_database_id
        __props__.__dict__["connection_strings_type"] = connection_strings_type
        __props__.__dict__["role"] = role
        return AutonomousContainerDatabaseSnapshotStandby(resource_name, opts=opts, __props__=__props__)

    @_builtins.property
    @pulumi.getter(name="autonomousContainerDatabaseId")
    def autonomous_container_database_id(self) -> pulumi.Output[_builtins.str]:
        """
        The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        """
        return pulumi.get(self, "autonomous_container_database_id")

    @_builtins.property
    @pulumi.getter(name="connectionStringsType")
    def connection_strings_type(self) -> pulumi.Output[_builtins.str]:
        """
        type of connection strings when converting database to snapshot mode
        """
        return pulumi.get(self, "connection_strings_type")

    @_builtins.property
    @pulumi.getter
    def role(self) -> pulumi.Output[_builtins.str]:
        """
        The Data Guard role of the Autonomous Container Database or Autonomous Database, if Autonomous Data Guard is enabled. 


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "role")

