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
    'GetSoftwarePackageSoftwareSourceResult',
    'AwaitableGetSoftwarePackageSoftwareSourceResult',
    'get_software_package_software_source',
    'get_software_package_software_source_output',
]

@pulumi.output_type
class GetSoftwarePackageSoftwareSourceResult:
    """
    A collection of values returned by getSoftwarePackageSoftwareSource.
    """
    def __init__(__self__, arch_types=None, availabilities=None, availability_anywheres=None, availability_at_ocis=None, compartment_id=None, display_name=None, display_name_contains=None, filters=None, id=None, os_families=None, software_package_name=None, software_source_collections=None, software_source_types=None, states=None):
        if arch_types and not isinstance(arch_types, list):
            raise TypeError("Expected argument 'arch_types' to be a list")
        pulumi.set(__self__, "arch_types", arch_types)
        if availabilities and not isinstance(availabilities, list):
            raise TypeError("Expected argument 'availabilities' to be a list")
        pulumi.set(__self__, "availabilities", availabilities)
        if availability_anywheres and not isinstance(availability_anywheres, list):
            raise TypeError("Expected argument 'availability_anywheres' to be a list")
        pulumi.set(__self__, "availability_anywheres", availability_anywheres)
        if availability_at_ocis and not isinstance(availability_at_ocis, list):
            raise TypeError("Expected argument 'availability_at_ocis' to be a list")
        pulumi.set(__self__, "availability_at_ocis", availability_at_ocis)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if display_name_contains and not isinstance(display_name_contains, str):
            raise TypeError("Expected argument 'display_name_contains' to be a str")
        pulumi.set(__self__, "display_name_contains", display_name_contains)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if os_families and not isinstance(os_families, list):
            raise TypeError("Expected argument 'os_families' to be a list")
        pulumi.set(__self__, "os_families", os_families)
        if software_package_name and not isinstance(software_package_name, str):
            raise TypeError("Expected argument 'software_package_name' to be a str")
        pulumi.set(__self__, "software_package_name", software_package_name)
        if software_source_collections and not isinstance(software_source_collections, list):
            raise TypeError("Expected argument 'software_source_collections' to be a list")
        pulumi.set(__self__, "software_source_collections", software_source_collections)
        if software_source_types and not isinstance(software_source_types, list):
            raise TypeError("Expected argument 'software_source_types' to be a list")
        pulumi.set(__self__, "software_source_types", software_source_types)
        if states and not isinstance(states, list):
            raise TypeError("Expected argument 'states' to be a list")
        pulumi.set(__self__, "states", states)

    @_builtins.property
    @pulumi.getter(name="archTypes")
    def arch_types(self) -> Optional[Sequence[_builtins.str]]:
        """
        The architecture type supported by the software source.
        """
        return pulumi.get(self, "arch_types")

    @_builtins.property
    @pulumi.getter
    def availabilities(self) -> Optional[Sequence[_builtins.str]]:
        """
        Availability of the software source (for non-OCI environments).
        """
        return pulumi.get(self, "availabilities")

    @_builtins.property
    @pulumi.getter(name="availabilityAnywheres")
    def availability_anywheres(self) -> Optional[Sequence[_builtins.str]]:
        return pulumi.get(self, "availability_anywheres")

    @_builtins.property
    @pulumi.getter(name="availabilityAtOcis")
    def availability_at_ocis(self) -> Optional[Sequence[_builtins.str]]:
        """
        Availability of the software source (for Oracle Cloud Infrastructure environments).
        """
        return pulumi.get(self, "availability_at_ocis")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the software source.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[_builtins.str]:
        """
        User-friendly name.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="displayNameContains")
    def display_name_contains(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "display_name_contains")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetSoftwarePackageSoftwareSourceFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="osFamilies")
    def os_families(self) -> Optional[Sequence[_builtins.str]]:
        """
        The OS family of the software source.
        """
        return pulumi.get(self, "os_families")

    @_builtins.property
    @pulumi.getter(name="softwarePackageName")
    def software_package_name(self) -> _builtins.str:
        return pulumi.get(self, "software_package_name")

    @_builtins.property
    @pulumi.getter(name="softwareSourceCollections")
    def software_source_collections(self) -> Sequence['outputs.GetSoftwarePackageSoftwareSourceSoftwareSourceCollectionResult']:
        """
        The list of software_source_collection.
        """
        return pulumi.get(self, "software_source_collections")

    @_builtins.property
    @pulumi.getter(name="softwareSourceTypes")
    def software_source_types(self) -> Optional[Sequence[_builtins.str]]:
        """
        Type of software source.
        """
        return pulumi.get(self, "software_source_types")

    @_builtins.property
    @pulumi.getter
    def states(self) -> Optional[Sequence[_builtins.str]]:
        """
        The current state of the software source.
        """
        return pulumi.get(self, "states")


class AwaitableGetSoftwarePackageSoftwareSourceResult(GetSoftwarePackageSoftwareSourceResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetSoftwarePackageSoftwareSourceResult(
            arch_types=self.arch_types,
            availabilities=self.availabilities,
            availability_anywheres=self.availability_anywheres,
            availability_at_ocis=self.availability_at_ocis,
            compartment_id=self.compartment_id,
            display_name=self.display_name,
            display_name_contains=self.display_name_contains,
            filters=self.filters,
            id=self.id,
            os_families=self.os_families,
            software_package_name=self.software_package_name,
            software_source_collections=self.software_source_collections,
            software_source_types=self.software_source_types,
            states=self.states)


def get_software_package_software_source(arch_types: Optional[Sequence[_builtins.str]] = None,
                                         availabilities: Optional[Sequence[_builtins.str]] = None,
                                         availability_anywheres: Optional[Sequence[_builtins.str]] = None,
                                         availability_at_ocis: Optional[Sequence[_builtins.str]] = None,
                                         compartment_id: Optional[_builtins.str] = None,
                                         display_name: Optional[_builtins.str] = None,
                                         display_name_contains: Optional[_builtins.str] = None,
                                         filters: Optional[Sequence[Union['GetSoftwarePackageSoftwareSourceFilterArgs', 'GetSoftwarePackageSoftwareSourceFilterArgsDict']]] = None,
                                         os_families: Optional[Sequence[_builtins.str]] = None,
                                         software_package_name: Optional[_builtins.str] = None,
                                         software_source_types: Optional[Sequence[_builtins.str]] = None,
                                         states: Optional[Sequence[_builtins.str]] = None,
                                         opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetSoftwarePackageSoftwareSourceResult:
    """
    This data source provides the list of Software Package Software Source in Oracle Cloud Infrastructure Os Management Hub service.

    Lists the software sources in the tenancy that contain the software package. Filter the list against a
    variety of criteria including but not limited to its name, type, architecture, and OS family.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_software_package_software_source = oci.OsManagementHub.get_software_package_software_source(compartment_id=compartment_id,
        software_package_name=test_software_package["name"],
        arch_types=software_package_software_source_arch_type,
        availabilities=software_package_software_source_availability,
        availability_anywheres=software_package_software_source_availability_anywhere,
        availability_at_ocis=software_package_software_source_availability_at_oci,
        display_name=software_package_software_source_display_name,
        display_name_contains=software_package_software_source_display_name_contains,
        os_families=software_package_software_source_os_family,
        software_source_types=software_package_software_source_software_source_type,
        states=software_package_software_source_state)
    ```


    :param Sequence[_builtins.str] arch_types: A filter to return only instances whose architecture type matches the given architecture.
    :param Sequence[_builtins.str] availabilities: The availability of the software source in a non-OCI environment for a tenancy.
    :param Sequence[_builtins.str] availability_anywheres: The availability of the software source. Use this query parameter to filter across availabilities in different environments.
    :param Sequence[_builtins.str] availability_at_ocis: The availability of the software source in an Oracle Cloud Infrastructure environment for a tenancy.
    :param _builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment. This parameter is required and returns only resources contained within the specified compartment.
    :param _builtins.str display_name: A filter to return resources that match the given user-friendly name.
    :param _builtins.str display_name_contains: A filter to return resources that may partially match the given display name.
    :param Sequence[_builtins.str] os_families: A filter to return only resources that match the given operating system family.
    :param _builtins.str software_package_name: The name of the software package.
    :param Sequence[_builtins.str] software_source_types: The type of the software source.
    :param Sequence[_builtins.str] states: A filter to return only software sources whose state matches the given state.
    """
    __args__ = dict()
    __args__['archTypes'] = arch_types
    __args__['availabilities'] = availabilities
    __args__['availabilityAnywheres'] = availability_anywheres
    __args__['availabilityAtOcis'] = availability_at_ocis
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['displayNameContains'] = display_name_contains
    __args__['filters'] = filters
    __args__['osFamilies'] = os_families
    __args__['softwarePackageName'] = software_package_name
    __args__['softwareSourceTypes'] = software_source_types
    __args__['states'] = states
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:OsManagementHub/getSoftwarePackageSoftwareSource:getSoftwarePackageSoftwareSource', __args__, opts=opts, typ=GetSoftwarePackageSoftwareSourceResult).value

    return AwaitableGetSoftwarePackageSoftwareSourceResult(
        arch_types=pulumi.get(__ret__, 'arch_types'),
        availabilities=pulumi.get(__ret__, 'availabilities'),
        availability_anywheres=pulumi.get(__ret__, 'availability_anywheres'),
        availability_at_ocis=pulumi.get(__ret__, 'availability_at_ocis'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        display_name=pulumi.get(__ret__, 'display_name'),
        display_name_contains=pulumi.get(__ret__, 'display_name_contains'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        os_families=pulumi.get(__ret__, 'os_families'),
        software_package_name=pulumi.get(__ret__, 'software_package_name'),
        software_source_collections=pulumi.get(__ret__, 'software_source_collections'),
        software_source_types=pulumi.get(__ret__, 'software_source_types'),
        states=pulumi.get(__ret__, 'states'))
def get_software_package_software_source_output(arch_types: Optional[pulumi.Input[Optional[Sequence[_builtins.str]]]] = None,
                                                availabilities: Optional[pulumi.Input[Optional[Sequence[_builtins.str]]]] = None,
                                                availability_anywheres: Optional[pulumi.Input[Optional[Sequence[_builtins.str]]]] = None,
                                                availability_at_ocis: Optional[pulumi.Input[Optional[Sequence[_builtins.str]]]] = None,
                                                compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                                                display_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                display_name_contains: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                filters: Optional[pulumi.Input[Optional[Sequence[Union['GetSoftwarePackageSoftwareSourceFilterArgs', 'GetSoftwarePackageSoftwareSourceFilterArgsDict']]]]] = None,
                                                os_families: Optional[pulumi.Input[Optional[Sequence[_builtins.str]]]] = None,
                                                software_package_name: Optional[pulumi.Input[_builtins.str]] = None,
                                                software_source_types: Optional[pulumi.Input[Optional[Sequence[_builtins.str]]]] = None,
                                                states: Optional[pulumi.Input[Optional[Sequence[_builtins.str]]]] = None,
                                                opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetSoftwarePackageSoftwareSourceResult]:
    """
    This data source provides the list of Software Package Software Source in Oracle Cloud Infrastructure Os Management Hub service.

    Lists the software sources in the tenancy that contain the software package. Filter the list against a
    variety of criteria including but not limited to its name, type, architecture, and OS family.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_software_package_software_source = oci.OsManagementHub.get_software_package_software_source(compartment_id=compartment_id,
        software_package_name=test_software_package["name"],
        arch_types=software_package_software_source_arch_type,
        availabilities=software_package_software_source_availability,
        availability_anywheres=software_package_software_source_availability_anywhere,
        availability_at_ocis=software_package_software_source_availability_at_oci,
        display_name=software_package_software_source_display_name,
        display_name_contains=software_package_software_source_display_name_contains,
        os_families=software_package_software_source_os_family,
        software_source_types=software_package_software_source_software_source_type,
        states=software_package_software_source_state)
    ```


    :param Sequence[_builtins.str] arch_types: A filter to return only instances whose architecture type matches the given architecture.
    :param Sequence[_builtins.str] availabilities: The availability of the software source in a non-OCI environment for a tenancy.
    :param Sequence[_builtins.str] availability_anywheres: The availability of the software source. Use this query parameter to filter across availabilities in different environments.
    :param Sequence[_builtins.str] availability_at_ocis: The availability of the software source in an Oracle Cloud Infrastructure environment for a tenancy.
    :param _builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment. This parameter is required and returns only resources contained within the specified compartment.
    :param _builtins.str display_name: A filter to return resources that match the given user-friendly name.
    :param _builtins.str display_name_contains: A filter to return resources that may partially match the given display name.
    :param Sequence[_builtins.str] os_families: A filter to return only resources that match the given operating system family.
    :param _builtins.str software_package_name: The name of the software package.
    :param Sequence[_builtins.str] software_source_types: The type of the software source.
    :param Sequence[_builtins.str] states: A filter to return only software sources whose state matches the given state.
    """
    __args__ = dict()
    __args__['archTypes'] = arch_types
    __args__['availabilities'] = availabilities
    __args__['availabilityAnywheres'] = availability_anywheres
    __args__['availabilityAtOcis'] = availability_at_ocis
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['displayNameContains'] = display_name_contains
    __args__['filters'] = filters
    __args__['osFamilies'] = os_families
    __args__['softwarePackageName'] = software_package_name
    __args__['softwareSourceTypes'] = software_source_types
    __args__['states'] = states
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:OsManagementHub/getSoftwarePackageSoftwareSource:getSoftwarePackageSoftwareSource', __args__, opts=opts, typ=GetSoftwarePackageSoftwareSourceResult)
    return __ret__.apply(lambda __response__: GetSoftwarePackageSoftwareSourceResult(
        arch_types=pulumi.get(__response__, 'arch_types'),
        availabilities=pulumi.get(__response__, 'availabilities'),
        availability_anywheres=pulumi.get(__response__, 'availability_anywheres'),
        availability_at_ocis=pulumi.get(__response__, 'availability_at_ocis'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        display_name=pulumi.get(__response__, 'display_name'),
        display_name_contains=pulumi.get(__response__, 'display_name_contains'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        os_families=pulumi.get(__response__, 'os_families'),
        software_package_name=pulumi.get(__response__, 'software_package_name'),
        software_source_collections=pulumi.get(__response__, 'software_source_collections'),
        software_source_types=pulumi.get(__response__, 'software_source_types'),
        states=pulumi.get(__response__, 'states')))
