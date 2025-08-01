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

__all__ = ['ProfileAttachManagementStationManagementArgs', 'ProfileAttachManagementStationManagement']

@pulumi.input_type
class ProfileAttachManagementStationManagementArgs:
    def __init__(__self__, *,
                 management_station_id: pulumi.Input[_builtins.str],
                 profile_id: pulumi.Input[_builtins.str]):
        """
        The set of arguments for constructing a ProfileAttachManagementStationManagement resource.
        :param pulumi.Input[_builtins.str] management_station_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station that the instance will be associated with.
        :param pulumi.Input[_builtins.str] profile_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the registration profile.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        pulumi.set(__self__, "management_station_id", management_station_id)
        pulumi.set(__self__, "profile_id", profile_id)

    @_builtins.property
    @pulumi.getter(name="managementStationId")
    def management_station_id(self) -> pulumi.Input[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station that the instance will be associated with.
        """
        return pulumi.get(self, "management_station_id")

    @management_station_id.setter
    def management_station_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "management_station_id", value)

    @_builtins.property
    @pulumi.getter(name="profileId")
    def profile_id(self) -> pulumi.Input[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the registration profile.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "profile_id")

    @profile_id.setter
    def profile_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "profile_id", value)


@pulumi.input_type
class _ProfileAttachManagementStationManagementState:
    def __init__(__self__, *,
                 management_station_id: Optional[pulumi.Input[_builtins.str]] = None,
                 profile_id: Optional[pulumi.Input[_builtins.str]] = None):
        """
        Input properties used for looking up and filtering ProfileAttachManagementStationManagement resources.
        :param pulumi.Input[_builtins.str] management_station_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station that the instance will be associated with.
        :param pulumi.Input[_builtins.str] profile_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the registration profile.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        if management_station_id is not None:
            pulumi.set(__self__, "management_station_id", management_station_id)
        if profile_id is not None:
            pulumi.set(__self__, "profile_id", profile_id)

    @_builtins.property
    @pulumi.getter(name="managementStationId")
    def management_station_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station that the instance will be associated with.
        """
        return pulumi.get(self, "management_station_id")

    @management_station_id.setter
    def management_station_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "management_station_id", value)

    @_builtins.property
    @pulumi.getter(name="profileId")
    def profile_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the registration profile.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "profile_id")

    @profile_id.setter
    def profile_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "profile_id", value)


@pulumi.type_token("oci:OsManagementHub/profileAttachManagementStationManagement:ProfileAttachManagementStationManagement")
class ProfileAttachManagementStationManagement(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 management_station_id: Optional[pulumi.Input[_builtins.str]] = None,
                 profile_id: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        """
        This resource provides the Profile Attach Management Station Management resource in Oracle Cloud Infrastructure Os Management Hub service.

        Attaches the specified management station to a profile.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_profile_attach_management_station_management = oci.osmanagementhub.ProfileAttachManagementStationManagement("test_profile_attach_management_station_management",
            management_station_id=test_management_station["id"],
            profile_id=test_profile["id"])
        ```

        ## Import

        ProfileAttachManagementStationManagement can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:OsManagementHub/profileAttachManagementStationManagement:ProfileAttachManagementStationManagement test_profile_attach_management_station_management "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] management_station_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station that the instance will be associated with.
        :param pulumi.Input[_builtins.str] profile_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the registration profile.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: ProfileAttachManagementStationManagementArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Profile Attach Management Station Management resource in Oracle Cloud Infrastructure Os Management Hub service.

        Attaches the specified management station to a profile.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_profile_attach_management_station_management = oci.osmanagementhub.ProfileAttachManagementStationManagement("test_profile_attach_management_station_management",
            management_station_id=test_management_station["id"],
            profile_id=test_profile["id"])
        ```

        ## Import

        ProfileAttachManagementStationManagement can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:OsManagementHub/profileAttachManagementStationManagement:ProfileAttachManagementStationManagement test_profile_attach_management_station_management "id"
        ```

        :param str resource_name: The name of the resource.
        :param ProfileAttachManagementStationManagementArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(ProfileAttachManagementStationManagementArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 management_station_id: Optional[pulumi.Input[_builtins.str]] = None,
                 profile_id: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = ProfileAttachManagementStationManagementArgs.__new__(ProfileAttachManagementStationManagementArgs)

            if management_station_id is None and not opts.urn:
                raise TypeError("Missing required property 'management_station_id'")
            __props__.__dict__["management_station_id"] = management_station_id
            if profile_id is None and not opts.urn:
                raise TypeError("Missing required property 'profile_id'")
            __props__.__dict__["profile_id"] = profile_id
        super(ProfileAttachManagementStationManagement, __self__).__init__(
            'oci:OsManagementHub/profileAttachManagementStationManagement:ProfileAttachManagementStationManagement',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            management_station_id: Optional[pulumi.Input[_builtins.str]] = None,
            profile_id: Optional[pulumi.Input[_builtins.str]] = None) -> 'ProfileAttachManagementStationManagement':
        """
        Get an existing ProfileAttachManagementStationManagement resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] management_station_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station that the instance will be associated with.
        :param pulumi.Input[_builtins.str] profile_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the registration profile.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _ProfileAttachManagementStationManagementState.__new__(_ProfileAttachManagementStationManagementState)

        __props__.__dict__["management_station_id"] = management_station_id
        __props__.__dict__["profile_id"] = profile_id
        return ProfileAttachManagementStationManagement(resource_name, opts=opts, __props__=__props__)

    @_builtins.property
    @pulumi.getter(name="managementStationId")
    def management_station_id(self) -> pulumi.Output[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station that the instance will be associated with.
        """
        return pulumi.get(self, "management_station_id")

    @_builtins.property
    @pulumi.getter(name="profileId")
    def profile_id(self) -> pulumi.Output[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the registration profile.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "profile_id")

