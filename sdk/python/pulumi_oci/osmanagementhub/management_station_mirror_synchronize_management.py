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

__all__ = ['ManagementStationMirrorSynchronizeManagementArgs', 'ManagementStationMirrorSynchronizeManagement']

@pulumi.input_type
class ManagementStationMirrorSynchronizeManagementArgs:
    def __init__(__self__, *,
                 management_station_id: pulumi.Input[_builtins.str],
                 mirror_id: pulumi.Input[_builtins.str]):
        """
        The set of arguments for constructing a ManagementStationMirrorSynchronizeManagement resource.
        :param pulumi.Input[_builtins.str] management_station_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station.
        :param pulumi.Input[_builtins.str] mirror_id: Unique Software Source identifier
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        pulumi.set(__self__, "management_station_id", management_station_id)
        pulumi.set(__self__, "mirror_id", mirror_id)

    @_builtins.property
    @pulumi.getter(name="managementStationId")
    def management_station_id(self) -> pulumi.Input[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station.
        """
        return pulumi.get(self, "management_station_id")

    @management_station_id.setter
    def management_station_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "management_station_id", value)

    @_builtins.property
    @pulumi.getter(name="mirrorId")
    def mirror_id(self) -> pulumi.Input[_builtins.str]:
        """
        Unique Software Source identifier


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "mirror_id")

    @mirror_id.setter
    def mirror_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "mirror_id", value)


@pulumi.input_type
class _ManagementStationMirrorSynchronizeManagementState:
    def __init__(__self__, *,
                 management_station_id: Optional[pulumi.Input[_builtins.str]] = None,
                 mirror_id: Optional[pulumi.Input[_builtins.str]] = None):
        """
        Input properties used for looking up and filtering ManagementStationMirrorSynchronizeManagement resources.
        :param pulumi.Input[_builtins.str] management_station_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station.
        :param pulumi.Input[_builtins.str] mirror_id: Unique Software Source identifier
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        if management_station_id is not None:
            pulumi.set(__self__, "management_station_id", management_station_id)
        if mirror_id is not None:
            pulumi.set(__self__, "mirror_id", mirror_id)

    @_builtins.property
    @pulumi.getter(name="managementStationId")
    def management_station_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station.
        """
        return pulumi.get(self, "management_station_id")

    @management_station_id.setter
    def management_station_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "management_station_id", value)

    @_builtins.property
    @pulumi.getter(name="mirrorId")
    def mirror_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        Unique Software Source identifier


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "mirror_id")

    @mirror_id.setter
    def mirror_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "mirror_id", value)


@pulumi.type_token("oci:OsManagementHub/managementStationMirrorSynchronizeManagement:ManagementStationMirrorSynchronizeManagement")
class ManagementStationMirrorSynchronizeManagement(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 management_station_id: Optional[pulumi.Input[_builtins.str]] = None,
                 mirror_id: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        """
        This resource provides the Management Station Mirror Synchronize Management resource in Oracle Cloud Infrastructure Os Management Hub service.

        Synchronize the specified software source mirrors on the management station.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_management_station_mirror_synchronize_management = oci.osmanagementhub.ManagementStationMirrorSynchronizeManagement("test_management_station_mirror_synchronize_management",
            management_station_id=test_management_station["id"],
            mirror_id=test_mirror["id"])
        ```

        ## Import

        ManagementStationMirrorSynchronizeManagement can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:OsManagementHub/managementStationMirrorSynchronizeManagement:ManagementStationMirrorSynchronizeManagement test_management_station_mirror_synchronize_management "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] management_station_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station.
        :param pulumi.Input[_builtins.str] mirror_id: Unique Software Source identifier
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: ManagementStationMirrorSynchronizeManagementArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Management Station Mirror Synchronize Management resource in Oracle Cloud Infrastructure Os Management Hub service.

        Synchronize the specified software source mirrors on the management station.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_management_station_mirror_synchronize_management = oci.osmanagementhub.ManagementStationMirrorSynchronizeManagement("test_management_station_mirror_synchronize_management",
            management_station_id=test_management_station["id"],
            mirror_id=test_mirror["id"])
        ```

        ## Import

        ManagementStationMirrorSynchronizeManagement can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:OsManagementHub/managementStationMirrorSynchronizeManagement:ManagementStationMirrorSynchronizeManagement test_management_station_mirror_synchronize_management "id"
        ```

        :param str resource_name: The name of the resource.
        :param ManagementStationMirrorSynchronizeManagementArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(ManagementStationMirrorSynchronizeManagementArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 management_station_id: Optional[pulumi.Input[_builtins.str]] = None,
                 mirror_id: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = ManagementStationMirrorSynchronizeManagementArgs.__new__(ManagementStationMirrorSynchronizeManagementArgs)

            if management_station_id is None and not opts.urn:
                raise TypeError("Missing required property 'management_station_id'")
            __props__.__dict__["management_station_id"] = management_station_id
            if mirror_id is None and not opts.urn:
                raise TypeError("Missing required property 'mirror_id'")
            __props__.__dict__["mirror_id"] = mirror_id
        super(ManagementStationMirrorSynchronizeManagement, __self__).__init__(
            'oci:OsManagementHub/managementStationMirrorSynchronizeManagement:ManagementStationMirrorSynchronizeManagement',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            management_station_id: Optional[pulumi.Input[_builtins.str]] = None,
            mirror_id: Optional[pulumi.Input[_builtins.str]] = None) -> 'ManagementStationMirrorSynchronizeManagement':
        """
        Get an existing ManagementStationMirrorSynchronizeManagement resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] management_station_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station.
        :param pulumi.Input[_builtins.str] mirror_id: Unique Software Source identifier
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _ManagementStationMirrorSynchronizeManagementState.__new__(_ManagementStationMirrorSynchronizeManagementState)

        __props__.__dict__["management_station_id"] = management_station_id
        __props__.__dict__["mirror_id"] = mirror_id
        return ManagementStationMirrorSynchronizeManagement(resource_name, opts=opts, __props__=__props__)

    @_builtins.property
    @pulumi.getter(name="managementStationId")
    def management_station_id(self) -> pulumi.Output[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station.
        """
        return pulumi.get(self, "management_station_id")

    @_builtins.property
    @pulumi.getter(name="mirrorId")
    def mirror_id(self) -> pulumi.Output[_builtins.str]:
        """
        Unique Software Source identifier


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "mirror_id")

