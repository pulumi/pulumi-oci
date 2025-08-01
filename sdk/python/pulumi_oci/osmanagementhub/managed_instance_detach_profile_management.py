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

__all__ = ['ManagedInstanceDetachProfileManagementArgs', 'ManagedInstanceDetachProfileManagement']

@pulumi.input_type
class ManagedInstanceDetachProfileManagementArgs:
    def __init__(__self__, *,
                 managed_instance_id: pulumi.Input[_builtins.str]):
        """
        The set of arguments for constructing a ManagedInstanceDetachProfileManagement resource.
        :param pulumi.Input[_builtins.str] managed_instance_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        pulumi.set(__self__, "managed_instance_id", managed_instance_id)

    @_builtins.property
    @pulumi.getter(name="managedInstanceId")
    def managed_instance_id(self) -> pulumi.Input[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "managed_instance_id")

    @managed_instance_id.setter
    def managed_instance_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "managed_instance_id", value)


@pulumi.input_type
class _ManagedInstanceDetachProfileManagementState:
    def __init__(__self__, *,
                 managed_instance_id: Optional[pulumi.Input[_builtins.str]] = None):
        """
        Input properties used for looking up and filtering ManagedInstanceDetachProfileManagement resources.
        :param pulumi.Input[_builtins.str] managed_instance_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        if managed_instance_id is not None:
            pulumi.set(__self__, "managed_instance_id", managed_instance_id)

    @_builtins.property
    @pulumi.getter(name="managedInstanceId")
    def managed_instance_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "managed_instance_id")

    @managed_instance_id.setter
    def managed_instance_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "managed_instance_id", value)


@pulumi.type_token("oci:OsManagementHub/managedInstanceDetachProfileManagement:ManagedInstanceDetachProfileManagement")
class ManagedInstanceDetachProfileManagement(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 managed_instance_id: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        """
        This resource provides the Managed Instance Detach Profile Management resource in Oracle Cloud Infrastructure Os Management Hub service.

        Detaches profile from a managed instance. After the profile has been removed,
        the instance cannot be registered as a managed instance.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_managed_instance_detach_profile_management = oci.osmanagementhub.ManagedInstanceDetachProfileManagement("test_managed_instance_detach_profile_management", managed_instance_id=test_managed_instance["id"])
        ```

        ## Import

        ManagedInstanceDetachProfileManagement can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:OsManagementHub/managedInstanceDetachProfileManagement:ManagedInstanceDetachProfileManagement test_managed_instance_detach_profile_management "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] managed_instance_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: ManagedInstanceDetachProfileManagementArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Managed Instance Detach Profile Management resource in Oracle Cloud Infrastructure Os Management Hub service.

        Detaches profile from a managed instance. After the profile has been removed,
        the instance cannot be registered as a managed instance.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_managed_instance_detach_profile_management = oci.osmanagementhub.ManagedInstanceDetachProfileManagement("test_managed_instance_detach_profile_management", managed_instance_id=test_managed_instance["id"])
        ```

        ## Import

        ManagedInstanceDetachProfileManagement can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:OsManagementHub/managedInstanceDetachProfileManagement:ManagedInstanceDetachProfileManagement test_managed_instance_detach_profile_management "id"
        ```

        :param str resource_name: The name of the resource.
        :param ManagedInstanceDetachProfileManagementArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(ManagedInstanceDetachProfileManagementArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 managed_instance_id: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = ManagedInstanceDetachProfileManagementArgs.__new__(ManagedInstanceDetachProfileManagementArgs)

            if managed_instance_id is None and not opts.urn:
                raise TypeError("Missing required property 'managed_instance_id'")
            __props__.__dict__["managed_instance_id"] = managed_instance_id
        super(ManagedInstanceDetachProfileManagement, __self__).__init__(
            'oci:OsManagementHub/managedInstanceDetachProfileManagement:ManagedInstanceDetachProfileManagement',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            managed_instance_id: Optional[pulumi.Input[_builtins.str]] = None) -> 'ManagedInstanceDetachProfileManagement':
        """
        Get an existing ManagedInstanceDetachProfileManagement resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] managed_instance_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _ManagedInstanceDetachProfileManagementState.__new__(_ManagedInstanceDetachProfileManagementState)

        __props__.__dict__["managed_instance_id"] = managed_instance_id
        return ManagedInstanceDetachProfileManagement(resource_name, opts=opts, __props__=__props__)

    @_builtins.property
    @pulumi.getter(name="managedInstanceId")
    def managed_instance_id(self) -> pulumi.Output[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "managed_instance_id")

