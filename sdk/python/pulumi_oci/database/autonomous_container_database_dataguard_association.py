# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = ['AutonomousContainerDatabaseDataguardAssociationArgs', 'AutonomousContainerDatabaseDataguardAssociation']

@pulumi.input_type
class AutonomousContainerDatabaseDataguardAssociationArgs:
    def __init__(__self__, *,
                 autonomous_container_database_dataguard_association_id: pulumi.Input[str],
                 autonomous_container_database_id: pulumi.Input[str],
                 is_automatic_failover_enabled: Optional[pulumi.Input[bool]] = None):
        """
        The set of arguments for constructing a AutonomousContainerDatabaseDataguardAssociation resource.
        :param pulumi.Input[str] autonomous_container_database_dataguard_association_id: The Autonomous Container Database-Autonomous Data Guard association [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        :param pulumi.Input[str] autonomous_container_database_id: The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        :param pulumi.Input[bool] is_automatic_failover_enabled: (Updatable) Indicates whether Automatic Failover is enabled for Autonomous Container Database Dataguard Association
        """
        pulumi.set(__self__, "autonomous_container_database_dataguard_association_id", autonomous_container_database_dataguard_association_id)
        pulumi.set(__self__, "autonomous_container_database_id", autonomous_container_database_id)
        if is_automatic_failover_enabled is not None:
            pulumi.set(__self__, "is_automatic_failover_enabled", is_automatic_failover_enabled)

    @property
    @pulumi.getter(name="autonomousContainerDatabaseDataguardAssociationId")
    def autonomous_container_database_dataguard_association_id(self) -> pulumi.Input[str]:
        """
        The Autonomous Container Database-Autonomous Data Guard association [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        """
        return pulumi.get(self, "autonomous_container_database_dataguard_association_id")

    @autonomous_container_database_dataguard_association_id.setter
    def autonomous_container_database_dataguard_association_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "autonomous_container_database_dataguard_association_id", value)

    @property
    @pulumi.getter(name="autonomousContainerDatabaseId")
    def autonomous_container_database_id(self) -> pulumi.Input[str]:
        """
        The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        """
        return pulumi.get(self, "autonomous_container_database_id")

    @autonomous_container_database_id.setter
    def autonomous_container_database_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "autonomous_container_database_id", value)

    @property
    @pulumi.getter(name="isAutomaticFailoverEnabled")
    def is_automatic_failover_enabled(self) -> Optional[pulumi.Input[bool]]:
        """
        (Updatable) Indicates whether Automatic Failover is enabled for Autonomous Container Database Dataguard Association
        """
        return pulumi.get(self, "is_automatic_failover_enabled")

    @is_automatic_failover_enabled.setter
    def is_automatic_failover_enabled(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "is_automatic_failover_enabled", value)


@pulumi.input_type
class _AutonomousContainerDatabaseDataguardAssociationState:
    def __init__(__self__, *,
                 apply_lag: Optional[pulumi.Input[str]] = None,
                 apply_rate: Optional[pulumi.Input[str]] = None,
                 autonomous_container_database_dataguard_association_id: Optional[pulumi.Input[str]] = None,
                 autonomous_container_database_id: Optional[pulumi.Input[str]] = None,
                 is_automatic_failover_enabled: Optional[pulumi.Input[bool]] = None,
                 lifecycle_details: Optional[pulumi.Input[str]] = None,
                 peer_autonomous_container_database_dataguard_association_id: Optional[pulumi.Input[str]] = None,
                 peer_autonomous_container_database_id: Optional[pulumi.Input[str]] = None,
                 peer_lifecycle_state: Optional[pulumi.Input[str]] = None,
                 peer_role: Optional[pulumi.Input[str]] = None,
                 protection_mode: Optional[pulumi.Input[str]] = None,
                 role: Optional[pulumi.Input[str]] = None,
                 state: Optional[pulumi.Input[str]] = None,
                 time_created: Optional[pulumi.Input[str]] = None,
                 time_last_role_changed: Optional[pulumi.Input[str]] = None,
                 time_last_synced: Optional[pulumi.Input[str]] = None,
                 transport_lag: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering AutonomousContainerDatabaseDataguardAssociation resources.
        :param pulumi.Input[str] apply_lag: The lag time between updates to the primary Autonomous Container Database and application of the redo data on the standby Autonomous Container Database, as computed by the reporting database.  Example: `9 seconds`
        :param pulumi.Input[str] apply_rate: The rate at which redo logs are synchronized between the associated Autonomous Container Databases.  Example: `180 Mb per second`
        :param pulumi.Input[str] autonomous_container_database_dataguard_association_id: The Autonomous Container Database-Autonomous Data Guard association [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        :param pulumi.Input[str] autonomous_container_database_id: The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        :param pulumi.Input[bool] is_automatic_failover_enabled: (Updatable) Indicates whether Automatic Failover is enabled for Autonomous Container Database Dataguard Association
        :param pulumi.Input[str] lifecycle_details: Additional information about the current lifecycleState, if available.
        :param pulumi.Input[str] peer_autonomous_container_database_dataguard_association_id: The OCID of the peer Autonomous Container Database-Autonomous Data Guard association.
        :param pulumi.Input[str] peer_autonomous_container_database_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the peer Autonomous Container Database.
        :param pulumi.Input[str] peer_lifecycle_state: The current state of Autonomous Data Guard.
        :param pulumi.Input[str] peer_role: The Data Guard role of the Autonomous Container Database or Autonomous Database, if Autonomous Data Guard is enabled.
        :param pulumi.Input[str] protection_mode: The protection mode of this Autonomous Data Guard association. For more information, see [Oracle Data Guard Protection Modes](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-protection-modes.htm#SBYDB02000) in the Oracle Data Guard documentation.
        :param pulumi.Input[str] role: The Data Guard role of the Autonomous Container Database or Autonomous Database, if Autonomous Data Guard is enabled.
        :param pulumi.Input[str] state: The current state of Autonomous Data Guard.
        :param pulumi.Input[str] time_created: The date and time the Autonomous DataGuard association was created.
        :param pulumi.Input[str] time_last_role_changed: The date and time when the last role change action happened.
        :param pulumi.Input[str] time_last_synced: The date and time of the last update to the apply lag, apply rate, and transport lag values.
        :param pulumi.Input[str] transport_lag: The approximate number of seconds of redo data not yet available on the standby Autonomous Container Database, as computed by the reporting database.  Example: `7 seconds`
        """
        if apply_lag is not None:
            pulumi.set(__self__, "apply_lag", apply_lag)
        if apply_rate is not None:
            pulumi.set(__self__, "apply_rate", apply_rate)
        if autonomous_container_database_dataguard_association_id is not None:
            pulumi.set(__self__, "autonomous_container_database_dataguard_association_id", autonomous_container_database_dataguard_association_id)
        if autonomous_container_database_id is not None:
            pulumi.set(__self__, "autonomous_container_database_id", autonomous_container_database_id)
        if is_automatic_failover_enabled is not None:
            pulumi.set(__self__, "is_automatic_failover_enabled", is_automatic_failover_enabled)
        if lifecycle_details is not None:
            pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if peer_autonomous_container_database_dataguard_association_id is not None:
            pulumi.set(__self__, "peer_autonomous_container_database_dataguard_association_id", peer_autonomous_container_database_dataguard_association_id)
        if peer_autonomous_container_database_id is not None:
            pulumi.set(__self__, "peer_autonomous_container_database_id", peer_autonomous_container_database_id)
        if peer_lifecycle_state is not None:
            pulumi.set(__self__, "peer_lifecycle_state", peer_lifecycle_state)
        if peer_role is not None:
            pulumi.set(__self__, "peer_role", peer_role)
        if protection_mode is not None:
            pulumi.set(__self__, "protection_mode", protection_mode)
        if role is not None:
            pulumi.set(__self__, "role", role)
        if state is not None:
            pulumi.set(__self__, "state", state)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)
        if time_last_role_changed is not None:
            pulumi.set(__self__, "time_last_role_changed", time_last_role_changed)
        if time_last_synced is not None:
            pulumi.set(__self__, "time_last_synced", time_last_synced)
        if transport_lag is not None:
            pulumi.set(__self__, "transport_lag", transport_lag)

    @property
    @pulumi.getter(name="applyLag")
    def apply_lag(self) -> Optional[pulumi.Input[str]]:
        """
        The lag time between updates to the primary Autonomous Container Database and application of the redo data on the standby Autonomous Container Database, as computed by the reporting database.  Example: `9 seconds`
        """
        return pulumi.get(self, "apply_lag")

    @apply_lag.setter
    def apply_lag(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "apply_lag", value)

    @property
    @pulumi.getter(name="applyRate")
    def apply_rate(self) -> Optional[pulumi.Input[str]]:
        """
        The rate at which redo logs are synchronized between the associated Autonomous Container Databases.  Example: `180 Mb per second`
        """
        return pulumi.get(self, "apply_rate")

    @apply_rate.setter
    def apply_rate(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "apply_rate", value)

    @property
    @pulumi.getter(name="autonomousContainerDatabaseDataguardAssociationId")
    def autonomous_container_database_dataguard_association_id(self) -> Optional[pulumi.Input[str]]:
        """
        The Autonomous Container Database-Autonomous Data Guard association [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        """
        return pulumi.get(self, "autonomous_container_database_dataguard_association_id")

    @autonomous_container_database_dataguard_association_id.setter
    def autonomous_container_database_dataguard_association_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "autonomous_container_database_dataguard_association_id", value)

    @property
    @pulumi.getter(name="autonomousContainerDatabaseId")
    def autonomous_container_database_id(self) -> Optional[pulumi.Input[str]]:
        """
        The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        """
        return pulumi.get(self, "autonomous_container_database_id")

    @autonomous_container_database_id.setter
    def autonomous_container_database_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "autonomous_container_database_id", value)

    @property
    @pulumi.getter(name="isAutomaticFailoverEnabled")
    def is_automatic_failover_enabled(self) -> Optional[pulumi.Input[bool]]:
        """
        (Updatable) Indicates whether Automatic Failover is enabled for Autonomous Container Database Dataguard Association
        """
        return pulumi.get(self, "is_automatic_failover_enabled")

    @is_automatic_failover_enabled.setter
    def is_automatic_failover_enabled(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "is_automatic_failover_enabled", value)

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> Optional[pulumi.Input[str]]:
        """
        Additional information about the current lifecycleState, if available.
        """
        return pulumi.get(self, "lifecycle_details")

    @lifecycle_details.setter
    def lifecycle_details(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "lifecycle_details", value)

    @property
    @pulumi.getter(name="peerAutonomousContainerDatabaseDataguardAssociationId")
    def peer_autonomous_container_database_dataguard_association_id(self) -> Optional[pulumi.Input[str]]:
        """
        The OCID of the peer Autonomous Container Database-Autonomous Data Guard association.
        """
        return pulumi.get(self, "peer_autonomous_container_database_dataguard_association_id")

    @peer_autonomous_container_database_dataguard_association_id.setter
    def peer_autonomous_container_database_dataguard_association_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "peer_autonomous_container_database_dataguard_association_id", value)

    @property
    @pulumi.getter(name="peerAutonomousContainerDatabaseId")
    def peer_autonomous_container_database_id(self) -> Optional[pulumi.Input[str]]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the peer Autonomous Container Database.
        """
        return pulumi.get(self, "peer_autonomous_container_database_id")

    @peer_autonomous_container_database_id.setter
    def peer_autonomous_container_database_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "peer_autonomous_container_database_id", value)

    @property
    @pulumi.getter(name="peerLifecycleState")
    def peer_lifecycle_state(self) -> Optional[pulumi.Input[str]]:
        """
        The current state of Autonomous Data Guard.
        """
        return pulumi.get(self, "peer_lifecycle_state")

    @peer_lifecycle_state.setter
    def peer_lifecycle_state(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "peer_lifecycle_state", value)

    @property
    @pulumi.getter(name="peerRole")
    def peer_role(self) -> Optional[pulumi.Input[str]]:
        """
        The Data Guard role of the Autonomous Container Database or Autonomous Database, if Autonomous Data Guard is enabled.
        """
        return pulumi.get(self, "peer_role")

    @peer_role.setter
    def peer_role(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "peer_role", value)

    @property
    @pulumi.getter(name="protectionMode")
    def protection_mode(self) -> Optional[pulumi.Input[str]]:
        """
        The protection mode of this Autonomous Data Guard association. For more information, see [Oracle Data Guard Protection Modes](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-protection-modes.htm#SBYDB02000) in the Oracle Data Guard documentation.
        """
        return pulumi.get(self, "protection_mode")

    @protection_mode.setter
    def protection_mode(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "protection_mode", value)

    @property
    @pulumi.getter
    def role(self) -> Optional[pulumi.Input[str]]:
        """
        The Data Guard role of the Autonomous Container Database or Autonomous Database, if Autonomous Data Guard is enabled.
        """
        return pulumi.get(self, "role")

    @role.setter
    def role(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "role", value)

    @property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[str]]:
        """
        The current state of Autonomous Data Guard.
        """
        return pulumi.get(self, "state")

    @state.setter
    def state(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "state", value)

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[str]]:
        """
        The date and time the Autonomous DataGuard association was created.
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_created", value)

    @property
    @pulumi.getter(name="timeLastRoleChanged")
    def time_last_role_changed(self) -> Optional[pulumi.Input[str]]:
        """
        The date and time when the last role change action happened.
        """
        return pulumi.get(self, "time_last_role_changed")

    @time_last_role_changed.setter
    def time_last_role_changed(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_last_role_changed", value)

    @property
    @pulumi.getter(name="timeLastSynced")
    def time_last_synced(self) -> Optional[pulumi.Input[str]]:
        """
        The date and time of the last update to the apply lag, apply rate, and transport lag values.
        """
        return pulumi.get(self, "time_last_synced")

    @time_last_synced.setter
    def time_last_synced(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_last_synced", value)

    @property
    @pulumi.getter(name="transportLag")
    def transport_lag(self) -> Optional[pulumi.Input[str]]:
        """
        The approximate number of seconds of redo data not yet available on the standby Autonomous Container Database, as computed by the reporting database.  Example: `7 seconds`
        """
        return pulumi.get(self, "transport_lag")

    @transport_lag.setter
    def transport_lag(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "transport_lag", value)


class AutonomousContainerDatabaseDataguardAssociation(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 autonomous_container_database_dataguard_association_id: Optional[pulumi.Input[str]] = None,
                 autonomous_container_database_id: Optional[pulumi.Input[str]] = None,
                 is_automatic_failover_enabled: Optional[pulumi.Input[bool]] = None,
                 __props__=None):
        """
        This resource provides the Autonomous Container Database Dataguard Association resource in Oracle Cloud Infrastructure Database service.

        Update Autonomous Data Guard association.

        ## Import

        AutonomousContainerDatabaseDataguardAssociations can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:Database/autonomousContainerDatabaseDataguardAssociation:AutonomousContainerDatabaseDataguardAssociation test_autonomous_container_database_dataguard_association "autonomousContainerDatabases/{autonomousContainerDatabaseId}/autonomousContainerDatabaseDataguardAssociations/{autonomousContainerDatabaseDataguardAssociationId}"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] autonomous_container_database_dataguard_association_id: The Autonomous Container Database-Autonomous Data Guard association [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        :param pulumi.Input[str] autonomous_container_database_id: The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        :param pulumi.Input[bool] is_automatic_failover_enabled: (Updatable) Indicates whether Automatic Failover is enabled for Autonomous Container Database Dataguard Association
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: AutonomousContainerDatabaseDataguardAssociationArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Autonomous Container Database Dataguard Association resource in Oracle Cloud Infrastructure Database service.

        Update Autonomous Data Guard association.

        ## Import

        AutonomousContainerDatabaseDataguardAssociations can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:Database/autonomousContainerDatabaseDataguardAssociation:AutonomousContainerDatabaseDataguardAssociation test_autonomous_container_database_dataguard_association "autonomousContainerDatabases/{autonomousContainerDatabaseId}/autonomousContainerDatabaseDataguardAssociations/{autonomousContainerDatabaseDataguardAssociationId}"
        ```

        :param str resource_name: The name of the resource.
        :param AutonomousContainerDatabaseDataguardAssociationArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(AutonomousContainerDatabaseDataguardAssociationArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 autonomous_container_database_dataguard_association_id: Optional[pulumi.Input[str]] = None,
                 autonomous_container_database_id: Optional[pulumi.Input[str]] = None,
                 is_automatic_failover_enabled: Optional[pulumi.Input[bool]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = AutonomousContainerDatabaseDataguardAssociationArgs.__new__(AutonomousContainerDatabaseDataguardAssociationArgs)

            if autonomous_container_database_dataguard_association_id is None and not opts.urn:
                raise TypeError("Missing required property 'autonomous_container_database_dataguard_association_id'")
            __props__.__dict__["autonomous_container_database_dataguard_association_id"] = autonomous_container_database_dataguard_association_id
            if autonomous_container_database_id is None and not opts.urn:
                raise TypeError("Missing required property 'autonomous_container_database_id'")
            __props__.__dict__["autonomous_container_database_id"] = autonomous_container_database_id
            __props__.__dict__["is_automatic_failover_enabled"] = is_automatic_failover_enabled
            __props__.__dict__["apply_lag"] = None
            __props__.__dict__["apply_rate"] = None
            __props__.__dict__["lifecycle_details"] = None
            __props__.__dict__["peer_autonomous_container_database_dataguard_association_id"] = None
            __props__.__dict__["peer_autonomous_container_database_id"] = None
            __props__.__dict__["peer_lifecycle_state"] = None
            __props__.__dict__["peer_role"] = None
            __props__.__dict__["protection_mode"] = None
            __props__.__dict__["role"] = None
            __props__.__dict__["state"] = None
            __props__.__dict__["time_created"] = None
            __props__.__dict__["time_last_role_changed"] = None
            __props__.__dict__["time_last_synced"] = None
            __props__.__dict__["transport_lag"] = None
        super(AutonomousContainerDatabaseDataguardAssociation, __self__).__init__(
            'oci:Database/autonomousContainerDatabaseDataguardAssociation:AutonomousContainerDatabaseDataguardAssociation',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            apply_lag: Optional[pulumi.Input[str]] = None,
            apply_rate: Optional[pulumi.Input[str]] = None,
            autonomous_container_database_dataguard_association_id: Optional[pulumi.Input[str]] = None,
            autonomous_container_database_id: Optional[pulumi.Input[str]] = None,
            is_automatic_failover_enabled: Optional[pulumi.Input[bool]] = None,
            lifecycle_details: Optional[pulumi.Input[str]] = None,
            peer_autonomous_container_database_dataguard_association_id: Optional[pulumi.Input[str]] = None,
            peer_autonomous_container_database_id: Optional[pulumi.Input[str]] = None,
            peer_lifecycle_state: Optional[pulumi.Input[str]] = None,
            peer_role: Optional[pulumi.Input[str]] = None,
            protection_mode: Optional[pulumi.Input[str]] = None,
            role: Optional[pulumi.Input[str]] = None,
            state: Optional[pulumi.Input[str]] = None,
            time_created: Optional[pulumi.Input[str]] = None,
            time_last_role_changed: Optional[pulumi.Input[str]] = None,
            time_last_synced: Optional[pulumi.Input[str]] = None,
            transport_lag: Optional[pulumi.Input[str]] = None) -> 'AutonomousContainerDatabaseDataguardAssociation':
        """
        Get an existing AutonomousContainerDatabaseDataguardAssociation resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] apply_lag: The lag time between updates to the primary Autonomous Container Database and application of the redo data on the standby Autonomous Container Database, as computed by the reporting database.  Example: `9 seconds`
        :param pulumi.Input[str] apply_rate: The rate at which redo logs are synchronized between the associated Autonomous Container Databases.  Example: `180 Mb per second`
        :param pulumi.Input[str] autonomous_container_database_dataguard_association_id: The Autonomous Container Database-Autonomous Data Guard association [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        :param pulumi.Input[str] autonomous_container_database_id: The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        :param pulumi.Input[bool] is_automatic_failover_enabled: (Updatable) Indicates whether Automatic Failover is enabled for Autonomous Container Database Dataguard Association
        :param pulumi.Input[str] lifecycle_details: Additional information about the current lifecycleState, if available.
        :param pulumi.Input[str] peer_autonomous_container_database_dataguard_association_id: The OCID of the peer Autonomous Container Database-Autonomous Data Guard association.
        :param pulumi.Input[str] peer_autonomous_container_database_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the peer Autonomous Container Database.
        :param pulumi.Input[str] peer_lifecycle_state: The current state of Autonomous Data Guard.
        :param pulumi.Input[str] peer_role: The Data Guard role of the Autonomous Container Database or Autonomous Database, if Autonomous Data Guard is enabled.
        :param pulumi.Input[str] protection_mode: The protection mode of this Autonomous Data Guard association. For more information, see [Oracle Data Guard Protection Modes](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-protection-modes.htm#SBYDB02000) in the Oracle Data Guard documentation.
        :param pulumi.Input[str] role: The Data Guard role of the Autonomous Container Database or Autonomous Database, if Autonomous Data Guard is enabled.
        :param pulumi.Input[str] state: The current state of Autonomous Data Guard.
        :param pulumi.Input[str] time_created: The date and time the Autonomous DataGuard association was created.
        :param pulumi.Input[str] time_last_role_changed: The date and time when the last role change action happened.
        :param pulumi.Input[str] time_last_synced: The date and time of the last update to the apply lag, apply rate, and transport lag values.
        :param pulumi.Input[str] transport_lag: The approximate number of seconds of redo data not yet available on the standby Autonomous Container Database, as computed by the reporting database.  Example: `7 seconds`
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _AutonomousContainerDatabaseDataguardAssociationState.__new__(_AutonomousContainerDatabaseDataguardAssociationState)

        __props__.__dict__["apply_lag"] = apply_lag
        __props__.__dict__["apply_rate"] = apply_rate
        __props__.__dict__["autonomous_container_database_dataguard_association_id"] = autonomous_container_database_dataguard_association_id
        __props__.__dict__["autonomous_container_database_id"] = autonomous_container_database_id
        __props__.__dict__["is_automatic_failover_enabled"] = is_automatic_failover_enabled
        __props__.__dict__["lifecycle_details"] = lifecycle_details
        __props__.__dict__["peer_autonomous_container_database_dataguard_association_id"] = peer_autonomous_container_database_dataguard_association_id
        __props__.__dict__["peer_autonomous_container_database_id"] = peer_autonomous_container_database_id
        __props__.__dict__["peer_lifecycle_state"] = peer_lifecycle_state
        __props__.__dict__["peer_role"] = peer_role
        __props__.__dict__["protection_mode"] = protection_mode
        __props__.__dict__["role"] = role
        __props__.__dict__["state"] = state
        __props__.__dict__["time_created"] = time_created
        __props__.__dict__["time_last_role_changed"] = time_last_role_changed
        __props__.__dict__["time_last_synced"] = time_last_synced
        __props__.__dict__["transport_lag"] = transport_lag
        return AutonomousContainerDatabaseDataguardAssociation(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter(name="applyLag")
    def apply_lag(self) -> pulumi.Output[str]:
        """
        The lag time between updates to the primary Autonomous Container Database and application of the redo data on the standby Autonomous Container Database, as computed by the reporting database.  Example: `9 seconds`
        """
        return pulumi.get(self, "apply_lag")

    @property
    @pulumi.getter(name="applyRate")
    def apply_rate(self) -> pulumi.Output[str]:
        """
        The rate at which redo logs are synchronized between the associated Autonomous Container Databases.  Example: `180 Mb per second`
        """
        return pulumi.get(self, "apply_rate")

    @property
    @pulumi.getter(name="autonomousContainerDatabaseDataguardAssociationId")
    def autonomous_container_database_dataguard_association_id(self) -> pulumi.Output[str]:
        """
        The Autonomous Container Database-Autonomous Data Guard association [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        """
        return pulumi.get(self, "autonomous_container_database_dataguard_association_id")

    @property
    @pulumi.getter(name="autonomousContainerDatabaseId")
    def autonomous_container_database_id(self) -> pulumi.Output[str]:
        """
        The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        """
        return pulumi.get(self, "autonomous_container_database_id")

    @property
    @pulumi.getter(name="isAutomaticFailoverEnabled")
    def is_automatic_failover_enabled(self) -> pulumi.Output[bool]:
        """
        (Updatable) Indicates whether Automatic Failover is enabled for Autonomous Container Database Dataguard Association
        """
        return pulumi.get(self, "is_automatic_failover_enabled")

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> pulumi.Output[str]:
        """
        Additional information about the current lifecycleState, if available.
        """
        return pulumi.get(self, "lifecycle_details")

    @property
    @pulumi.getter(name="peerAutonomousContainerDatabaseDataguardAssociationId")
    def peer_autonomous_container_database_dataguard_association_id(self) -> pulumi.Output[str]:
        """
        The OCID of the peer Autonomous Container Database-Autonomous Data Guard association.
        """
        return pulumi.get(self, "peer_autonomous_container_database_dataguard_association_id")

    @property
    @pulumi.getter(name="peerAutonomousContainerDatabaseId")
    def peer_autonomous_container_database_id(self) -> pulumi.Output[str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the peer Autonomous Container Database.
        """
        return pulumi.get(self, "peer_autonomous_container_database_id")

    @property
    @pulumi.getter(name="peerLifecycleState")
    def peer_lifecycle_state(self) -> pulumi.Output[str]:
        """
        The current state of Autonomous Data Guard.
        """
        return pulumi.get(self, "peer_lifecycle_state")

    @property
    @pulumi.getter(name="peerRole")
    def peer_role(self) -> pulumi.Output[str]:
        """
        The Data Guard role of the Autonomous Container Database or Autonomous Database, if Autonomous Data Guard is enabled.
        """
        return pulumi.get(self, "peer_role")

    @property
    @pulumi.getter(name="protectionMode")
    def protection_mode(self) -> pulumi.Output[str]:
        """
        The protection mode of this Autonomous Data Guard association. For more information, see [Oracle Data Guard Protection Modes](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-protection-modes.htm#SBYDB02000) in the Oracle Data Guard documentation.
        """
        return pulumi.get(self, "protection_mode")

    @property
    @pulumi.getter
    def role(self) -> pulumi.Output[str]:
        """
        The Data Guard role of the Autonomous Container Database or Autonomous Database, if Autonomous Data Guard is enabled.
        """
        return pulumi.get(self, "role")

    @property
    @pulumi.getter
    def state(self) -> pulumi.Output[str]:
        """
        The current state of Autonomous Data Guard.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> pulumi.Output[str]:
        """
        The date and time the Autonomous DataGuard association was created.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeLastRoleChanged")
    def time_last_role_changed(self) -> pulumi.Output[str]:
        """
        The date and time when the last role change action happened.
        """
        return pulumi.get(self, "time_last_role_changed")

    @property
    @pulumi.getter(name="timeLastSynced")
    def time_last_synced(self) -> pulumi.Output[str]:
        """
        The date and time of the last update to the apply lag, apply rate, and transport lag values.
        """
        return pulumi.get(self, "time_last_synced")

    @property
    @pulumi.getter(name="transportLag")
    def transport_lag(self) -> pulumi.Output[str]:
        """
        The approximate number of seconds of redo data not yet available on the standby Autonomous Container Database, as computed by the reporting database.  Example: `7 seconds`
        """
        return pulumi.get(self, "transport_lag")
