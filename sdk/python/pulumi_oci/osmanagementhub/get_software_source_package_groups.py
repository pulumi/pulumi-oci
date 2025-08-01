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

__all__ = [
    'GetSoftwareSourcePackageGroupsResult',
    'AwaitableGetSoftwareSourcePackageGroupsResult',
    'get_software_source_package_groups',
    'get_software_source_package_groups_output',
]

@pulumi.output_type
class GetSoftwareSourcePackageGroupsResult:
    """
    A collection of values returned by getSoftwareSourcePackageGroups.
    """
    def __init__(__self__, compartment_id=None, filters=None, group_types=None, id=None, name=None, name_contains=None, package_group_collections=None, software_source_id=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if group_types and not isinstance(group_types, list):
            raise TypeError("Expected argument 'group_types' to be a list")
        pulumi.set(__self__, "group_types", group_types)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if name_contains and not isinstance(name_contains, str):
            raise TypeError("Expected argument 'name_contains' to be a str")
        pulumi.set(__self__, "name_contains", name_contains)
        if package_group_collections and not isinstance(package_group_collections, list):
            raise TypeError("Expected argument 'package_group_collections' to be a list")
        pulumi.set(__self__, "package_group_collections", package_group_collections)
        if software_source_id and not isinstance(software_source_id, str):
            raise TypeError("Expected argument 'software_source_id' to be a str")
        pulumi.set(__self__, "software_source_id", software_source_id)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetSoftwareSourcePackageGroupsFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter(name="groupTypes")
    def group_types(self) -> Optional[Sequence[_builtins.str]]:
        """
        Indicates if this is a group, category, or environment.
        """
        return pulumi.get(self, "group_types")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter
    def name(self) -> Optional[_builtins.str]:
        """
        Package group name.
        """
        return pulumi.get(self, "name")

    @_builtins.property
    @pulumi.getter(name="nameContains")
    def name_contains(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "name_contains")

    @_builtins.property
    @pulumi.getter(name="packageGroupCollections")
    def package_group_collections(self) -> Sequence['outputs.GetSoftwareSourcePackageGroupsPackageGroupCollectionResult']:
        """
        The list of package_group_collection.
        """
        return pulumi.get(self, "package_group_collections")

    @_builtins.property
    @pulumi.getter(name="softwareSourceId")
    def software_source_id(self) -> _builtins.str:
        return pulumi.get(self, "software_source_id")


class AwaitableGetSoftwareSourcePackageGroupsResult(GetSoftwareSourcePackageGroupsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetSoftwareSourcePackageGroupsResult(
            compartment_id=self.compartment_id,
            filters=self.filters,
            group_types=self.group_types,
            id=self.id,
            name=self.name,
            name_contains=self.name_contains,
            package_group_collections=self.package_group_collections,
            software_source_id=self.software_source_id)


def get_software_source_package_groups(compartment_id: Optional[_builtins.str] = None,
                                       filters: Optional[Sequence[Union['GetSoftwareSourcePackageGroupsFilterArgs', 'GetSoftwareSourcePackageGroupsFilterArgsDict']]] = None,
                                       group_types: Optional[Sequence[_builtins.str]] = None,
                                       name: Optional[_builtins.str] = None,
                                       name_contains: Optional[_builtins.str] = None,
                                       software_source_id: Optional[_builtins.str] = None,
                                       opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetSoftwareSourcePackageGroupsResult:
    """
    This data source provides the list of Software Source Package Groups in Oracle Cloud Infrastructure Os Management Hub service.

    Lists package groups that are associated with the specified software source [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Filter the list against a
    variety of criteria including but not limited to its name, and package group type.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_software_source_package_groups = oci.OsManagementHub.get_software_source_package_groups(software_source_id=test_software_source["id"],
        compartment_id=compartment_id,
        group_types=software_source_package_group_group_type,
        name=software_source_package_group_name,
        name_contains=software_source_package_group_name_contains)
    ```


    :param _builtins.str compartment_id: The OCID of the compartment that contains the resources to list. This filter returns only resources contained within the specified compartment.
    :param Sequence[_builtins.str] group_types: A filter to return only package groups of the specified type.
    :param _builtins.str name: The name of the entity to be queried.
    :param _builtins.str name_contains: A filter to return resources that may partially match the name given.
    :param _builtins.str software_source_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    __args__['groupTypes'] = group_types
    __args__['name'] = name
    __args__['nameContains'] = name_contains
    __args__['softwareSourceId'] = software_source_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:OsManagementHub/getSoftwareSourcePackageGroups:getSoftwareSourcePackageGroups', __args__, opts=opts, typ=GetSoftwareSourcePackageGroupsResult).value

    return AwaitableGetSoftwareSourcePackageGroupsResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        filters=pulumi.get(__ret__, 'filters'),
        group_types=pulumi.get(__ret__, 'group_types'),
        id=pulumi.get(__ret__, 'id'),
        name=pulumi.get(__ret__, 'name'),
        name_contains=pulumi.get(__ret__, 'name_contains'),
        package_group_collections=pulumi.get(__ret__, 'package_group_collections'),
        software_source_id=pulumi.get(__ret__, 'software_source_id'))
def get_software_source_package_groups_output(compartment_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                              filters: Optional[pulumi.Input[Optional[Sequence[Union['GetSoftwareSourcePackageGroupsFilterArgs', 'GetSoftwareSourcePackageGroupsFilterArgsDict']]]]] = None,
                                              group_types: Optional[pulumi.Input[Optional[Sequence[_builtins.str]]]] = None,
                                              name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                              name_contains: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                              software_source_id: Optional[pulumi.Input[_builtins.str]] = None,
                                              opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetSoftwareSourcePackageGroupsResult]:
    """
    This data source provides the list of Software Source Package Groups in Oracle Cloud Infrastructure Os Management Hub service.

    Lists package groups that are associated with the specified software source [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Filter the list against a
    variety of criteria including but not limited to its name, and package group type.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_software_source_package_groups = oci.OsManagementHub.get_software_source_package_groups(software_source_id=test_software_source["id"],
        compartment_id=compartment_id,
        group_types=software_source_package_group_group_type,
        name=software_source_package_group_name,
        name_contains=software_source_package_group_name_contains)
    ```


    :param _builtins.str compartment_id: The OCID of the compartment that contains the resources to list. This filter returns only resources contained within the specified compartment.
    :param Sequence[_builtins.str] group_types: A filter to return only package groups of the specified type.
    :param _builtins.str name: The name of the entity to be queried.
    :param _builtins.str name_contains: A filter to return resources that may partially match the name given.
    :param _builtins.str software_source_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    __args__['groupTypes'] = group_types
    __args__['name'] = name
    __args__['nameContains'] = name_contains
    __args__['softwareSourceId'] = software_source_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:OsManagementHub/getSoftwareSourcePackageGroups:getSoftwareSourcePackageGroups', __args__, opts=opts, typ=GetSoftwareSourcePackageGroupsResult)
    return __ret__.apply(lambda __response__: GetSoftwareSourcePackageGroupsResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        filters=pulumi.get(__response__, 'filters'),
        group_types=pulumi.get(__response__, 'group_types'),
        id=pulumi.get(__response__, 'id'),
        name=pulumi.get(__response__, 'name'),
        name_contains=pulumi.get(__response__, 'name_contains'),
        package_group_collections=pulumi.get(__response__, 'package_group_collections'),
        software_source_id=pulumi.get(__response__, 'software_source_id')))
