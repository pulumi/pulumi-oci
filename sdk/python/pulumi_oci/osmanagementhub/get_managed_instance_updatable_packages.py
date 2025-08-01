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
    'GetManagedInstanceUpdatablePackagesResult',
    'AwaitableGetManagedInstanceUpdatablePackagesResult',
    'get_managed_instance_updatable_packages',
    'get_managed_instance_updatable_packages_output',
]

@pulumi.output_type
class GetManagedInstanceUpdatablePackagesResult:
    """
    A collection of values returned by getManagedInstanceUpdatablePackages.
    """
    def __init__(__self__, advisory_names=None, classification_types=None, compartment_id=None, display_name_contains=None, display_names=None, filters=None, id=None, managed_instance_id=None, updatable_package_collections=None):
        if advisory_names and not isinstance(advisory_names, list):
            raise TypeError("Expected argument 'advisory_names' to be a list")
        pulumi.set(__self__, "advisory_names", advisory_names)
        if classification_types and not isinstance(classification_types, list):
            raise TypeError("Expected argument 'classification_types' to be a list")
        pulumi.set(__self__, "classification_types", classification_types)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if display_name_contains and not isinstance(display_name_contains, str):
            raise TypeError("Expected argument 'display_name_contains' to be a str")
        pulumi.set(__self__, "display_name_contains", display_name_contains)
        if display_names and not isinstance(display_names, list):
            raise TypeError("Expected argument 'display_names' to be a list")
        pulumi.set(__self__, "display_names", display_names)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if managed_instance_id and not isinstance(managed_instance_id, str):
            raise TypeError("Expected argument 'managed_instance_id' to be a str")
        pulumi.set(__self__, "managed_instance_id", managed_instance_id)
        if updatable_package_collections and not isinstance(updatable_package_collections, list):
            raise TypeError("Expected argument 'updatable_package_collections' to be a list")
        pulumi.set(__self__, "updatable_package_collections", updatable_package_collections)

    @_builtins.property
    @pulumi.getter(name="advisoryNames")
    def advisory_names(self) -> Optional[Sequence[_builtins.str]]:
        return pulumi.get(self, "advisory_names")

    @_builtins.property
    @pulumi.getter(name="classificationTypes")
    def classification_types(self) -> Optional[Sequence[_builtins.str]]:
        return pulumi.get(self, "classification_types")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="displayNameContains")
    def display_name_contains(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "display_name_contains")

    @_builtins.property
    @pulumi.getter(name="displayNames")
    def display_names(self) -> Optional[Sequence[_builtins.str]]:
        """
        Software source name.
        """
        return pulumi.get(self, "display_names")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetManagedInstanceUpdatablePackagesFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="managedInstanceId")
    def managed_instance_id(self) -> _builtins.str:
        return pulumi.get(self, "managed_instance_id")

    @_builtins.property
    @pulumi.getter(name="updatablePackageCollections")
    def updatable_package_collections(self) -> Sequence['outputs.GetManagedInstanceUpdatablePackagesUpdatablePackageCollectionResult']:
        """
        The list of updatable_package_collection.
        """
        return pulumi.get(self, "updatable_package_collections")


class AwaitableGetManagedInstanceUpdatablePackagesResult(GetManagedInstanceUpdatablePackagesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetManagedInstanceUpdatablePackagesResult(
            advisory_names=self.advisory_names,
            classification_types=self.classification_types,
            compartment_id=self.compartment_id,
            display_name_contains=self.display_name_contains,
            display_names=self.display_names,
            filters=self.filters,
            id=self.id,
            managed_instance_id=self.managed_instance_id,
            updatable_package_collections=self.updatable_package_collections)


def get_managed_instance_updatable_packages(advisory_names: Optional[Sequence[_builtins.str]] = None,
                                            classification_types: Optional[Sequence[_builtins.str]] = None,
                                            compartment_id: Optional[_builtins.str] = None,
                                            display_name_contains: Optional[_builtins.str] = None,
                                            display_names: Optional[Sequence[_builtins.str]] = None,
                                            filters: Optional[Sequence[Union['GetManagedInstanceUpdatablePackagesFilterArgs', 'GetManagedInstanceUpdatablePackagesFilterArgsDict']]] = None,
                                            managed_instance_id: Optional[_builtins.str] = None,
                                            opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetManagedInstanceUpdatablePackagesResult:
    """
    This data source provides the list of Managed Instance Updatable Packages in Oracle Cloud Infrastructure Os Management Hub service.

    Returns a list of updatable packages for a managed instance.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_managed_instance_updatable_packages = oci.OsManagementHub.get_managed_instance_updatable_packages(managed_instance_id=test_managed_instance["id"],
        advisory_names=managed_instance_updatable_package_advisory_name,
        classification_types=managed_instance_updatable_package_classification_type,
        compartment_id=compartment_id,
        display_names=managed_instance_updatable_package_display_name,
        display_name_contains=managed_instance_updatable_package_display_name_contains)
    ```


    :param Sequence[_builtins.str] advisory_names: The assigned erratum name. It's unique and not changeable.  Example: `ELSA-2020-5804`
    :param Sequence[_builtins.str] classification_types: A filter to return only packages that match the given update classification type.
    :param _builtins.str compartment_id: The OCID of the compartment that contains the resources to list. This filter returns only resources contained within the specified compartment.
    :param _builtins.str display_name_contains: A filter to return resources that may partially match the given display name.
    :param Sequence[_builtins.str] display_names: A filter to return resources that match the given display names.
    :param _builtins.str managed_instance_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
    """
    __args__ = dict()
    __args__['advisoryNames'] = advisory_names
    __args__['classificationTypes'] = classification_types
    __args__['compartmentId'] = compartment_id
    __args__['displayNameContains'] = display_name_contains
    __args__['displayNames'] = display_names
    __args__['filters'] = filters
    __args__['managedInstanceId'] = managed_instance_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:OsManagementHub/getManagedInstanceUpdatablePackages:getManagedInstanceUpdatablePackages', __args__, opts=opts, typ=GetManagedInstanceUpdatablePackagesResult).value

    return AwaitableGetManagedInstanceUpdatablePackagesResult(
        advisory_names=pulumi.get(__ret__, 'advisory_names'),
        classification_types=pulumi.get(__ret__, 'classification_types'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        display_name_contains=pulumi.get(__ret__, 'display_name_contains'),
        display_names=pulumi.get(__ret__, 'display_names'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        managed_instance_id=pulumi.get(__ret__, 'managed_instance_id'),
        updatable_package_collections=pulumi.get(__ret__, 'updatable_package_collections'))
def get_managed_instance_updatable_packages_output(advisory_names: Optional[pulumi.Input[Optional[Sequence[_builtins.str]]]] = None,
                                                   classification_types: Optional[pulumi.Input[Optional[Sequence[_builtins.str]]]] = None,
                                                   compartment_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                   display_name_contains: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                   display_names: Optional[pulumi.Input[Optional[Sequence[_builtins.str]]]] = None,
                                                   filters: Optional[pulumi.Input[Optional[Sequence[Union['GetManagedInstanceUpdatablePackagesFilterArgs', 'GetManagedInstanceUpdatablePackagesFilterArgsDict']]]]] = None,
                                                   managed_instance_id: Optional[pulumi.Input[_builtins.str]] = None,
                                                   opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetManagedInstanceUpdatablePackagesResult]:
    """
    This data source provides the list of Managed Instance Updatable Packages in Oracle Cloud Infrastructure Os Management Hub service.

    Returns a list of updatable packages for a managed instance.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_managed_instance_updatable_packages = oci.OsManagementHub.get_managed_instance_updatable_packages(managed_instance_id=test_managed_instance["id"],
        advisory_names=managed_instance_updatable_package_advisory_name,
        classification_types=managed_instance_updatable_package_classification_type,
        compartment_id=compartment_id,
        display_names=managed_instance_updatable_package_display_name,
        display_name_contains=managed_instance_updatable_package_display_name_contains)
    ```


    :param Sequence[_builtins.str] advisory_names: The assigned erratum name. It's unique and not changeable.  Example: `ELSA-2020-5804`
    :param Sequence[_builtins.str] classification_types: A filter to return only packages that match the given update classification type.
    :param _builtins.str compartment_id: The OCID of the compartment that contains the resources to list. This filter returns only resources contained within the specified compartment.
    :param _builtins.str display_name_contains: A filter to return resources that may partially match the given display name.
    :param Sequence[_builtins.str] display_names: A filter to return resources that match the given display names.
    :param _builtins.str managed_instance_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
    """
    __args__ = dict()
    __args__['advisoryNames'] = advisory_names
    __args__['classificationTypes'] = classification_types
    __args__['compartmentId'] = compartment_id
    __args__['displayNameContains'] = display_name_contains
    __args__['displayNames'] = display_names
    __args__['filters'] = filters
    __args__['managedInstanceId'] = managed_instance_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:OsManagementHub/getManagedInstanceUpdatablePackages:getManagedInstanceUpdatablePackages', __args__, opts=opts, typ=GetManagedInstanceUpdatablePackagesResult)
    return __ret__.apply(lambda __response__: GetManagedInstanceUpdatablePackagesResult(
        advisory_names=pulumi.get(__response__, 'advisory_names'),
        classification_types=pulumi.get(__response__, 'classification_types'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        display_name_contains=pulumi.get(__response__, 'display_name_contains'),
        display_names=pulumi.get(__response__, 'display_names'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        managed_instance_id=pulumi.get(__response__, 'managed_instance_id'),
        updatable_package_collections=pulumi.get(__response__, 'updatable_package_collections')))
