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

__all__ = ['LifecycleStageDetachManagedInstancesManagementArgs', 'LifecycleStageDetachManagedInstancesManagement']

@pulumi.input_type
class LifecycleStageDetachManagedInstancesManagementArgs:
    def __init__(__self__, *,
                 lifecycle_stage_id: pulumi.Input[_builtins.str],
                 managed_instance_details: pulumi.Input['LifecycleStageDetachManagedInstancesManagementManagedInstanceDetailsArgs']):
        """
        The set of arguments for constructing a LifecycleStageDetachManagedInstancesManagement resource.
        :param pulumi.Input[_builtins.str] lifecycle_stage_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the lifecycle stage.
        :param pulumi.Input['LifecycleStageDetachManagedInstancesManagementManagedInstanceDetailsArgs'] managed_instance_details: The details about the managed instances.
        """
        pulumi.set(__self__, "lifecycle_stage_id", lifecycle_stage_id)
        pulumi.set(__self__, "managed_instance_details", managed_instance_details)

    @_builtins.property
    @pulumi.getter(name="lifecycleStageId")
    def lifecycle_stage_id(self) -> pulumi.Input[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the lifecycle stage.
        """
        return pulumi.get(self, "lifecycle_stage_id")

    @lifecycle_stage_id.setter
    def lifecycle_stage_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "lifecycle_stage_id", value)

    @_builtins.property
    @pulumi.getter(name="managedInstanceDetails")
    def managed_instance_details(self) -> pulumi.Input['LifecycleStageDetachManagedInstancesManagementManagedInstanceDetailsArgs']:
        """
        The details about the managed instances.
        """
        return pulumi.get(self, "managed_instance_details")

    @managed_instance_details.setter
    def managed_instance_details(self, value: pulumi.Input['LifecycleStageDetachManagedInstancesManagementManagedInstanceDetailsArgs']):
        pulumi.set(self, "managed_instance_details", value)


@pulumi.input_type
class _LifecycleStageDetachManagedInstancesManagementState:
    def __init__(__self__, *,
                 lifecycle_stage_id: Optional[pulumi.Input[_builtins.str]] = None,
                 managed_instance_details: Optional[pulumi.Input['LifecycleStageDetachManagedInstancesManagementManagedInstanceDetailsArgs']] = None):
        """
        Input properties used for looking up and filtering LifecycleStageDetachManagedInstancesManagement resources.
        :param pulumi.Input[_builtins.str] lifecycle_stage_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the lifecycle stage.
        :param pulumi.Input['LifecycleStageDetachManagedInstancesManagementManagedInstanceDetailsArgs'] managed_instance_details: The details about the managed instances.
        """
        if lifecycle_stage_id is not None:
            pulumi.set(__self__, "lifecycle_stage_id", lifecycle_stage_id)
        if managed_instance_details is not None:
            pulumi.set(__self__, "managed_instance_details", managed_instance_details)

    @_builtins.property
    @pulumi.getter(name="lifecycleStageId")
    def lifecycle_stage_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the lifecycle stage.
        """
        return pulumi.get(self, "lifecycle_stage_id")

    @lifecycle_stage_id.setter
    def lifecycle_stage_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "lifecycle_stage_id", value)

    @_builtins.property
    @pulumi.getter(name="managedInstanceDetails")
    def managed_instance_details(self) -> Optional[pulumi.Input['LifecycleStageDetachManagedInstancesManagementManagedInstanceDetailsArgs']]:
        """
        The details about the managed instances.
        """
        return pulumi.get(self, "managed_instance_details")

    @managed_instance_details.setter
    def managed_instance_details(self, value: Optional[pulumi.Input['LifecycleStageDetachManagedInstancesManagementManagedInstanceDetailsArgs']]):
        pulumi.set(self, "managed_instance_details", value)


@pulumi.type_token("oci:OsManagementHub/lifecycleStageDetachManagedInstancesManagement:LifecycleStageDetachManagedInstancesManagement")
class LifecycleStageDetachManagedInstancesManagement(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 lifecycle_stage_id: Optional[pulumi.Input[_builtins.str]] = None,
                 managed_instance_details: Optional[pulumi.Input[Union['LifecycleStageDetachManagedInstancesManagementManagedInstanceDetailsArgs', 'LifecycleStageDetachManagedInstancesManagementManagedInstanceDetailsArgsDict']]] = None,
                 __props__=None):
        """
        This resource provides the Lifecycle Stage Detach Managed Instances Management resource in Oracle Cloud Infrastructure Os Management Hub service.

        Detaches (removes) a managed instance from a lifecycle stage.

        ## Import

        LifecycleStageDetachManagedInstancesManagement can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:OsManagementHub/lifecycleStageDetachManagedInstancesManagement:LifecycleStageDetachManagedInstancesManagement test_lifecycle_stage_detach_managed_instances_management "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] lifecycle_stage_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the lifecycle stage.
        :param pulumi.Input[Union['LifecycleStageDetachManagedInstancesManagementManagedInstanceDetailsArgs', 'LifecycleStageDetachManagedInstancesManagementManagedInstanceDetailsArgsDict']] managed_instance_details: The details about the managed instances.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: LifecycleStageDetachManagedInstancesManagementArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Lifecycle Stage Detach Managed Instances Management resource in Oracle Cloud Infrastructure Os Management Hub service.

        Detaches (removes) a managed instance from a lifecycle stage.

        ## Import

        LifecycleStageDetachManagedInstancesManagement can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:OsManagementHub/lifecycleStageDetachManagedInstancesManagement:LifecycleStageDetachManagedInstancesManagement test_lifecycle_stage_detach_managed_instances_management "id"
        ```

        :param str resource_name: The name of the resource.
        :param LifecycleStageDetachManagedInstancesManagementArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(LifecycleStageDetachManagedInstancesManagementArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 lifecycle_stage_id: Optional[pulumi.Input[_builtins.str]] = None,
                 managed_instance_details: Optional[pulumi.Input[Union['LifecycleStageDetachManagedInstancesManagementManagedInstanceDetailsArgs', 'LifecycleStageDetachManagedInstancesManagementManagedInstanceDetailsArgsDict']]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = LifecycleStageDetachManagedInstancesManagementArgs.__new__(LifecycleStageDetachManagedInstancesManagementArgs)

            if lifecycle_stage_id is None and not opts.urn:
                raise TypeError("Missing required property 'lifecycle_stage_id'")
            __props__.__dict__["lifecycle_stage_id"] = lifecycle_stage_id
            if managed_instance_details is None and not opts.urn:
                raise TypeError("Missing required property 'managed_instance_details'")
            __props__.__dict__["managed_instance_details"] = managed_instance_details
        super(LifecycleStageDetachManagedInstancesManagement, __self__).__init__(
            'oci:OsManagementHub/lifecycleStageDetachManagedInstancesManagement:LifecycleStageDetachManagedInstancesManagement',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            lifecycle_stage_id: Optional[pulumi.Input[_builtins.str]] = None,
            managed_instance_details: Optional[pulumi.Input[Union['LifecycleStageDetachManagedInstancesManagementManagedInstanceDetailsArgs', 'LifecycleStageDetachManagedInstancesManagementManagedInstanceDetailsArgsDict']]] = None) -> 'LifecycleStageDetachManagedInstancesManagement':
        """
        Get an existing LifecycleStageDetachManagedInstancesManagement resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] lifecycle_stage_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the lifecycle stage.
        :param pulumi.Input[Union['LifecycleStageDetachManagedInstancesManagementManagedInstanceDetailsArgs', 'LifecycleStageDetachManagedInstancesManagementManagedInstanceDetailsArgsDict']] managed_instance_details: The details about the managed instances.
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _LifecycleStageDetachManagedInstancesManagementState.__new__(_LifecycleStageDetachManagedInstancesManagementState)

        __props__.__dict__["lifecycle_stage_id"] = lifecycle_stage_id
        __props__.__dict__["managed_instance_details"] = managed_instance_details
        return LifecycleStageDetachManagedInstancesManagement(resource_name, opts=opts, __props__=__props__)

    @_builtins.property
    @pulumi.getter(name="lifecycleStageId")
    def lifecycle_stage_id(self) -> pulumi.Output[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the lifecycle stage.
        """
        return pulumi.get(self, "lifecycle_stage_id")

    @_builtins.property
    @pulumi.getter(name="managedInstanceDetails")
    def managed_instance_details(self) -> pulumi.Output['outputs.LifecycleStageDetachManagedInstancesManagementManagedInstanceDetails']:
        """
        The details about the managed instances.
        """
        return pulumi.get(self, "managed_instance_details")

