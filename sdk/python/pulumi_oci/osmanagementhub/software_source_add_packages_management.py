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

__all__ = ['SoftwareSourceAddPackagesManagementArgs', 'SoftwareSourceAddPackagesManagement']

@pulumi.input_type
class SoftwareSourceAddPackagesManagementArgs:
    def __init__(__self__, *,
                 packages: pulumi.Input[Sequence[pulumi.Input[_builtins.str]]],
                 software_source_id: pulumi.Input[_builtins.str],
                 is_continue_on_missing_packages: Optional[pulumi.Input[_builtins.bool]] = None):
        """
        The set of arguments for constructing a SoftwareSourceAddPackagesManagement resource.
        :param pulumi.Input[Sequence[pulumi.Input[_builtins.str]]] packages: List of packages specified by the name of the package (N) or the full package name (NVRA or NEVRA).
        :param pulumi.Input[_builtins.str] software_source_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[_builtins.bool] is_continue_on_missing_packages: Indicates whether the service should generate a custom software source when the package list contains invalid values. When set to true, the service ignores any invalid packages and generates the custom software source with using the valid packages.
        """
        pulumi.set(__self__, "packages", packages)
        pulumi.set(__self__, "software_source_id", software_source_id)
        if is_continue_on_missing_packages is not None:
            pulumi.set(__self__, "is_continue_on_missing_packages", is_continue_on_missing_packages)

    @_builtins.property
    @pulumi.getter
    def packages(self) -> pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]:
        """
        List of packages specified by the name of the package (N) or the full package name (NVRA or NEVRA).
        """
        return pulumi.get(self, "packages")

    @packages.setter
    def packages(self, value: pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]):
        pulumi.set(self, "packages", value)

    @_builtins.property
    @pulumi.getter(name="softwareSourceId")
    def software_source_id(self) -> pulumi.Input[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "software_source_id")

    @software_source_id.setter
    def software_source_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "software_source_id", value)

    @_builtins.property
    @pulumi.getter(name="isContinueOnMissingPackages")
    def is_continue_on_missing_packages(self) -> Optional[pulumi.Input[_builtins.bool]]:
        """
        Indicates whether the service should generate a custom software source when the package list contains invalid values. When set to true, the service ignores any invalid packages and generates the custom software source with using the valid packages.
        """
        return pulumi.get(self, "is_continue_on_missing_packages")

    @is_continue_on_missing_packages.setter
    def is_continue_on_missing_packages(self, value: Optional[pulumi.Input[_builtins.bool]]):
        pulumi.set(self, "is_continue_on_missing_packages", value)


@pulumi.input_type
class _SoftwareSourceAddPackagesManagementState:
    def __init__(__self__, *,
                 is_continue_on_missing_packages: Optional[pulumi.Input[_builtins.bool]] = None,
                 packages: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]] = None,
                 software_source_id: Optional[pulumi.Input[_builtins.str]] = None):
        """
        Input properties used for looking up and filtering SoftwareSourceAddPackagesManagement resources.
        :param pulumi.Input[_builtins.bool] is_continue_on_missing_packages: Indicates whether the service should generate a custom software source when the package list contains invalid values. When set to true, the service ignores any invalid packages and generates the custom software source with using the valid packages.
        :param pulumi.Input[Sequence[pulumi.Input[_builtins.str]]] packages: List of packages specified by the name of the package (N) or the full package name (NVRA or NEVRA).
        :param pulumi.Input[_builtins.str] software_source_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        if is_continue_on_missing_packages is not None:
            pulumi.set(__self__, "is_continue_on_missing_packages", is_continue_on_missing_packages)
        if packages is not None:
            pulumi.set(__self__, "packages", packages)
        if software_source_id is not None:
            pulumi.set(__self__, "software_source_id", software_source_id)

    @_builtins.property
    @pulumi.getter(name="isContinueOnMissingPackages")
    def is_continue_on_missing_packages(self) -> Optional[pulumi.Input[_builtins.bool]]:
        """
        Indicates whether the service should generate a custom software source when the package list contains invalid values. When set to true, the service ignores any invalid packages and generates the custom software source with using the valid packages.
        """
        return pulumi.get(self, "is_continue_on_missing_packages")

    @is_continue_on_missing_packages.setter
    def is_continue_on_missing_packages(self, value: Optional[pulumi.Input[_builtins.bool]]):
        pulumi.set(self, "is_continue_on_missing_packages", value)

    @_builtins.property
    @pulumi.getter
    def packages(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]]:
        """
        List of packages specified by the name of the package (N) or the full package name (NVRA or NEVRA).
        """
        return pulumi.get(self, "packages")

    @packages.setter
    def packages(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]]):
        pulumi.set(self, "packages", value)

    @_builtins.property
    @pulumi.getter(name="softwareSourceId")
    def software_source_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "software_source_id")

    @software_source_id.setter
    def software_source_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "software_source_id", value)


@pulumi.type_token("oci:OsManagementHub/softwareSourceAddPackagesManagement:SoftwareSourceAddPackagesManagement")
class SoftwareSourceAddPackagesManagement(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 is_continue_on_missing_packages: Optional[pulumi.Input[_builtins.bool]] = None,
                 packages: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]] = None,
                 software_source_id: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        """
        This resource provides the Software Source Add Packages Management resource in Oracle Cloud Infrastructure Os Management Hub service.

        Adds packages to a software source. This operation can only be done for custom and versioned custom software sources that are not created using filters.
        For a versioned custom software source, you can only add packages when the source is created. Once content is added to a versioned custom software source, it is immutable.
        Packages can be of the format:
          * name (for example: git). If isLatestContentOnly is true, only the latest version of the package will be added, otherwise all versions of the package will be added.
          * name-version-release.architecture (for example: git-2.43.5-1.el8_10.x86_64)
          * name-epoch:version-release.architecture (for example: git-0:2.43.5-1.el8_10.x86_64)

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_software_source_add_packages_management = oci.osmanagementhub.SoftwareSourceAddPackagesManagement("test_software_source_add_packages_management",
            packages=software_source_add_packages_management_packages,
            software_source_id=test_software_source["id"],
            is_continue_on_missing_packages=software_source_add_packages_management_is_continue_on_missing_packages)
        ```

        ## Import

        SoftwareSourceAddPackagesManagement can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:OsManagementHub/softwareSourceAddPackagesManagement:SoftwareSourceAddPackagesManagement test_software_source_add_packages_management "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.bool] is_continue_on_missing_packages: Indicates whether the service should generate a custom software source when the package list contains invalid values. When set to true, the service ignores any invalid packages and generates the custom software source with using the valid packages.
        :param pulumi.Input[Sequence[pulumi.Input[_builtins.str]]] packages: List of packages specified by the name of the package (N) or the full package name (NVRA or NEVRA).
        :param pulumi.Input[_builtins.str] software_source_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: SoftwareSourceAddPackagesManagementArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Software Source Add Packages Management resource in Oracle Cloud Infrastructure Os Management Hub service.

        Adds packages to a software source. This operation can only be done for custom and versioned custom software sources that are not created using filters.
        For a versioned custom software source, you can only add packages when the source is created. Once content is added to a versioned custom software source, it is immutable.
        Packages can be of the format:
          * name (for example: git). If isLatestContentOnly is true, only the latest version of the package will be added, otherwise all versions of the package will be added.
          * name-version-release.architecture (for example: git-2.43.5-1.el8_10.x86_64)
          * name-epoch:version-release.architecture (for example: git-0:2.43.5-1.el8_10.x86_64)

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_software_source_add_packages_management = oci.osmanagementhub.SoftwareSourceAddPackagesManagement("test_software_source_add_packages_management",
            packages=software_source_add_packages_management_packages,
            software_source_id=test_software_source["id"],
            is_continue_on_missing_packages=software_source_add_packages_management_is_continue_on_missing_packages)
        ```

        ## Import

        SoftwareSourceAddPackagesManagement can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:OsManagementHub/softwareSourceAddPackagesManagement:SoftwareSourceAddPackagesManagement test_software_source_add_packages_management "id"
        ```

        :param str resource_name: The name of the resource.
        :param SoftwareSourceAddPackagesManagementArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(SoftwareSourceAddPackagesManagementArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 is_continue_on_missing_packages: Optional[pulumi.Input[_builtins.bool]] = None,
                 packages: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]] = None,
                 software_source_id: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = SoftwareSourceAddPackagesManagementArgs.__new__(SoftwareSourceAddPackagesManagementArgs)

            __props__.__dict__["is_continue_on_missing_packages"] = is_continue_on_missing_packages
            if packages is None and not opts.urn:
                raise TypeError("Missing required property 'packages'")
            __props__.__dict__["packages"] = packages
            if software_source_id is None and not opts.urn:
                raise TypeError("Missing required property 'software_source_id'")
            __props__.__dict__["software_source_id"] = software_source_id
        super(SoftwareSourceAddPackagesManagement, __self__).__init__(
            'oci:OsManagementHub/softwareSourceAddPackagesManagement:SoftwareSourceAddPackagesManagement',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            is_continue_on_missing_packages: Optional[pulumi.Input[_builtins.bool]] = None,
            packages: Optional[pulumi.Input[Sequence[pulumi.Input[_builtins.str]]]] = None,
            software_source_id: Optional[pulumi.Input[_builtins.str]] = None) -> 'SoftwareSourceAddPackagesManagement':
        """
        Get an existing SoftwareSourceAddPackagesManagement resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.bool] is_continue_on_missing_packages: Indicates whether the service should generate a custom software source when the package list contains invalid values. When set to true, the service ignores any invalid packages and generates the custom software source with using the valid packages.
        :param pulumi.Input[Sequence[pulumi.Input[_builtins.str]]] packages: List of packages specified by the name of the package (N) or the full package name (NVRA or NEVRA).
        :param pulumi.Input[_builtins.str] software_source_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _SoftwareSourceAddPackagesManagementState.__new__(_SoftwareSourceAddPackagesManagementState)

        __props__.__dict__["is_continue_on_missing_packages"] = is_continue_on_missing_packages
        __props__.__dict__["packages"] = packages
        __props__.__dict__["software_source_id"] = software_source_id
        return SoftwareSourceAddPackagesManagement(resource_name, opts=opts, __props__=__props__)

    @_builtins.property
    @pulumi.getter(name="isContinueOnMissingPackages")
    def is_continue_on_missing_packages(self) -> pulumi.Output[_builtins.bool]:
        """
        Indicates whether the service should generate a custom software source when the package list contains invalid values. When set to true, the service ignores any invalid packages and generates the custom software source with using the valid packages.
        """
        return pulumi.get(self, "is_continue_on_missing_packages")

    @_builtins.property
    @pulumi.getter
    def packages(self) -> pulumi.Output[Sequence[_builtins.str]]:
        """
        List of packages specified by the name of the package (N) or the full package name (NVRA or NEVRA).
        """
        return pulumi.get(self, "packages")

    @_builtins.property
    @pulumi.getter(name="softwareSourceId")
    def software_source_id(self) -> pulumi.Output[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "software_source_id")

