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
from . import outputs
from ._inputs import *

__all__ = ['CalculateAuditVolumeCollectedArgs', 'CalculateAuditVolumeCollected']

@pulumi.input_type
class CalculateAuditVolumeCollectedArgs:
    def __init__(__self__, *,
                 audit_profile_id: pulumi.Input[_builtins.str],
                 time_from_month: pulumi.Input[_builtins.str],
                 time_to_month: Optional[pulumi.Input[_builtins.str]] = None):
        """
        The set of arguments for constructing a CalculateAuditVolumeCollected resource.
        :param pulumi.Input[_builtins.str] audit_profile_id: The OCID of the audit.
        :param pulumi.Input[_builtins.str] time_from_month: The date from which the audit volume collected by data safe has to be calculated, in the format defined by RFC3339.
        :param pulumi.Input[_builtins.str] time_to_month: The date from which the audit volume collected by data safe has to be calculated, in the format defined by RFC3339. If not specified, this will default to the current date.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        pulumi.set(__self__, "audit_profile_id", audit_profile_id)
        pulumi.set(__self__, "time_from_month", time_from_month)
        if time_to_month is not None:
            pulumi.set(__self__, "time_to_month", time_to_month)

    @_builtins.property
    @pulumi.getter(name="auditProfileId")
    def audit_profile_id(self) -> pulumi.Input[_builtins.str]:
        """
        The OCID of the audit.
        """
        return pulumi.get(self, "audit_profile_id")

    @audit_profile_id.setter
    def audit_profile_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "audit_profile_id", value)

    @_builtins.property
    @pulumi.getter(name="timeFromMonth")
    def time_from_month(self) -> pulumi.Input[_builtins.str]:
        """
        The date from which the audit volume collected by data safe has to be calculated, in the format defined by RFC3339.
        """
        return pulumi.get(self, "time_from_month")

    @time_from_month.setter
    def time_from_month(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "time_from_month", value)

    @_builtins.property
    @pulumi.getter(name="timeToMonth")
    def time_to_month(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The date from which the audit volume collected by data safe has to be calculated, in the format defined by RFC3339. If not specified, this will default to the current date.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "time_to_month")

    @time_to_month.setter
    def time_to_month(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "time_to_month", value)


@pulumi.input_type
class _CalculateAuditVolumeCollectedState:
    def __init__(__self__, *,
                 audit_profile_id: Optional[pulumi.Input[_builtins.str]] = None,
                 collected_audit_volumes: Optional[pulumi.Input[Sequence[pulumi.Input['CalculateAuditVolumeCollectedCollectedAuditVolumeArgs']]]] = None,
                 time_from_month: Optional[pulumi.Input[_builtins.str]] = None,
                 time_to_month: Optional[pulumi.Input[_builtins.str]] = None):
        """
        Input properties used for looking up and filtering CalculateAuditVolumeCollected resources.
        :param pulumi.Input[_builtins.str] audit_profile_id: The OCID of the audit.
        :param pulumi.Input[Sequence[pulumi.Input['CalculateAuditVolumeCollectedCollectedAuditVolumeArgs']]] collected_audit_volumes: List of collected audit volumes.
        :param pulumi.Input[_builtins.str] time_from_month: The date from which the audit volume collected by data safe has to be calculated, in the format defined by RFC3339.
        :param pulumi.Input[_builtins.str] time_to_month: The date from which the audit volume collected by data safe has to be calculated, in the format defined by RFC3339. If not specified, this will default to the current date.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        if audit_profile_id is not None:
            pulumi.set(__self__, "audit_profile_id", audit_profile_id)
        if collected_audit_volumes is not None:
            pulumi.set(__self__, "collected_audit_volumes", collected_audit_volumes)
        if time_from_month is not None:
            pulumi.set(__self__, "time_from_month", time_from_month)
        if time_to_month is not None:
            pulumi.set(__self__, "time_to_month", time_to_month)

    @_builtins.property
    @pulumi.getter(name="auditProfileId")
    def audit_profile_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The OCID of the audit.
        """
        return pulumi.get(self, "audit_profile_id")

    @audit_profile_id.setter
    def audit_profile_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "audit_profile_id", value)

    @_builtins.property
    @pulumi.getter(name="collectedAuditVolumes")
    def collected_audit_volumes(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['CalculateAuditVolumeCollectedCollectedAuditVolumeArgs']]]]:
        """
        List of collected audit volumes.
        """
        return pulumi.get(self, "collected_audit_volumes")

    @collected_audit_volumes.setter
    def collected_audit_volumes(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['CalculateAuditVolumeCollectedCollectedAuditVolumeArgs']]]]):
        pulumi.set(self, "collected_audit_volumes", value)

    @_builtins.property
    @pulumi.getter(name="timeFromMonth")
    def time_from_month(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The date from which the audit volume collected by data safe has to be calculated, in the format defined by RFC3339.
        """
        return pulumi.get(self, "time_from_month")

    @time_from_month.setter
    def time_from_month(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "time_from_month", value)

    @_builtins.property
    @pulumi.getter(name="timeToMonth")
    def time_to_month(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The date from which the audit volume collected by data safe has to be calculated, in the format defined by RFC3339. If not specified, this will default to the current date.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "time_to_month")

    @time_to_month.setter
    def time_to_month(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "time_to_month", value)


@pulumi.type_token("oci:DataSafe/calculateAuditVolumeCollected:CalculateAuditVolumeCollected")
class CalculateAuditVolumeCollected(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 audit_profile_id: Optional[pulumi.Input[_builtins.str]] = None,
                 time_from_month: Optional[pulumi.Input[_builtins.str]] = None,
                 time_to_month: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        """
        This resource provides the Calculate Audit Volume Collected resource in Oracle Cloud Infrastructure Data Safe service.

        Calculates the volume of audit events collected by data safe.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_calculate_audit_volume_collected = oci.datasafe.CalculateAuditVolumeCollected("test_calculate_audit_volume_collected",
            audit_profile_id=test_audit_profile["id"],
            time_from_month=calculate_audit_volume_collected_time_from_month,
            time_to_month=calculate_audit_volume_collected_time_to_month)
        ```

        ## Import

        CalculateAuditVolumeCollected can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:DataSafe/calculateAuditVolumeCollected:CalculateAuditVolumeCollected test_calculate_audit_volume_collected "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] audit_profile_id: The OCID of the audit.
        :param pulumi.Input[_builtins.str] time_from_month: The date from which the audit volume collected by data safe has to be calculated, in the format defined by RFC3339.
        :param pulumi.Input[_builtins.str] time_to_month: The date from which the audit volume collected by data safe has to be calculated, in the format defined by RFC3339. If not specified, this will default to the current date.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: CalculateAuditVolumeCollectedArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Calculate Audit Volume Collected resource in Oracle Cloud Infrastructure Data Safe service.

        Calculates the volume of audit events collected by data safe.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_calculate_audit_volume_collected = oci.datasafe.CalculateAuditVolumeCollected("test_calculate_audit_volume_collected",
            audit_profile_id=test_audit_profile["id"],
            time_from_month=calculate_audit_volume_collected_time_from_month,
            time_to_month=calculate_audit_volume_collected_time_to_month)
        ```

        ## Import

        CalculateAuditVolumeCollected can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:DataSafe/calculateAuditVolumeCollected:CalculateAuditVolumeCollected test_calculate_audit_volume_collected "id"
        ```

        :param str resource_name: The name of the resource.
        :param CalculateAuditVolumeCollectedArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(CalculateAuditVolumeCollectedArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 audit_profile_id: Optional[pulumi.Input[_builtins.str]] = None,
                 time_from_month: Optional[pulumi.Input[_builtins.str]] = None,
                 time_to_month: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = CalculateAuditVolumeCollectedArgs.__new__(CalculateAuditVolumeCollectedArgs)

            if audit_profile_id is None and not opts.urn:
                raise TypeError("Missing required property 'audit_profile_id'")
            __props__.__dict__["audit_profile_id"] = audit_profile_id
            if time_from_month is None and not opts.urn:
                raise TypeError("Missing required property 'time_from_month'")
            __props__.__dict__["time_from_month"] = time_from_month
            __props__.__dict__["time_to_month"] = time_to_month
            __props__.__dict__["collected_audit_volumes"] = None
        super(CalculateAuditVolumeCollected, __self__).__init__(
            'oci:DataSafe/calculateAuditVolumeCollected:CalculateAuditVolumeCollected',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            audit_profile_id: Optional[pulumi.Input[_builtins.str]] = None,
            collected_audit_volumes: Optional[pulumi.Input[Sequence[pulumi.Input[Union['CalculateAuditVolumeCollectedCollectedAuditVolumeArgs', 'CalculateAuditVolumeCollectedCollectedAuditVolumeArgsDict']]]]] = None,
            time_from_month: Optional[pulumi.Input[_builtins.str]] = None,
            time_to_month: Optional[pulumi.Input[_builtins.str]] = None) -> 'CalculateAuditVolumeCollected':
        """
        Get an existing CalculateAuditVolumeCollected resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] audit_profile_id: The OCID of the audit.
        :param pulumi.Input[Sequence[pulumi.Input[Union['CalculateAuditVolumeCollectedCollectedAuditVolumeArgs', 'CalculateAuditVolumeCollectedCollectedAuditVolumeArgsDict']]]] collected_audit_volumes: List of collected audit volumes.
        :param pulumi.Input[_builtins.str] time_from_month: The date from which the audit volume collected by data safe has to be calculated, in the format defined by RFC3339.
        :param pulumi.Input[_builtins.str] time_to_month: The date from which the audit volume collected by data safe has to be calculated, in the format defined by RFC3339. If not specified, this will default to the current date.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _CalculateAuditVolumeCollectedState.__new__(_CalculateAuditVolumeCollectedState)

        __props__.__dict__["audit_profile_id"] = audit_profile_id
        __props__.__dict__["collected_audit_volumes"] = collected_audit_volumes
        __props__.__dict__["time_from_month"] = time_from_month
        __props__.__dict__["time_to_month"] = time_to_month
        return CalculateAuditVolumeCollected(resource_name, opts=opts, __props__=__props__)

    @_builtins.property
    @pulumi.getter(name="auditProfileId")
    def audit_profile_id(self) -> pulumi.Output[_builtins.str]:
        """
        The OCID of the audit.
        """
        return pulumi.get(self, "audit_profile_id")

    @_builtins.property
    @pulumi.getter(name="collectedAuditVolumes")
    def collected_audit_volumes(self) -> pulumi.Output[Sequence['outputs.CalculateAuditVolumeCollectedCollectedAuditVolume']]:
        """
        List of collected audit volumes.
        """
        return pulumi.get(self, "collected_audit_volumes")

    @_builtins.property
    @pulumi.getter(name="timeFromMonth")
    def time_from_month(self) -> pulumi.Output[_builtins.str]:
        """
        The date from which the audit volume collected by data safe has to be calculated, in the format defined by RFC3339.
        """
        return pulumi.get(self, "time_from_month")

    @_builtins.property
    @pulumi.getter(name="timeToMonth")
    def time_to_month(self) -> pulumi.Output[_builtins.str]:
        """
        The date from which the audit volume collected by data safe has to be calculated, in the format defined by RFC3339. If not specified, this will default to the current date.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "time_to_month")

