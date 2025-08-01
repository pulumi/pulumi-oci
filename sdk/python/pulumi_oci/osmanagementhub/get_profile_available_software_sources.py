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
    'GetProfileAvailableSoftwareSourcesResult',
    'AwaitableGetProfileAvailableSoftwareSourcesResult',
    'get_profile_available_software_sources',
    'get_profile_available_software_sources_output',
]

@pulumi.output_type
class GetProfileAvailableSoftwareSourcesResult:
    """
    A collection of values returned by getProfileAvailableSoftwareSources.
    """
    def __init__(__self__, available_software_source_collections=None, compartment_id=None, display_name_contains=None, display_names=None, filters=None, id=None, profile_id=None):
        if available_software_source_collections and not isinstance(available_software_source_collections, list):
            raise TypeError("Expected argument 'available_software_source_collections' to be a list")
        pulumi.set(__self__, "available_software_source_collections", available_software_source_collections)
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
        if profile_id and not isinstance(profile_id, str):
            raise TypeError("Expected argument 'profile_id' to be a str")
        pulumi.set(__self__, "profile_id", profile_id)

    @_builtins.property
    @pulumi.getter(name="availableSoftwareSourceCollections")
    def available_software_source_collections(self) -> Sequence['outputs.GetProfileAvailableSoftwareSourcesAvailableSoftwareSourceCollectionResult']:
        """
        The list of available_software_source_collection.
        """
        return pulumi.get(self, "available_software_source_collections")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the software source.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="displayNameContains")
    def display_name_contains(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "display_name_contains")

    @_builtins.property
    @pulumi.getter(name="displayNames")
    def display_names(self) -> Optional[Sequence[_builtins.str]]:
        """
        User-friendly name for the software source.
        """
        return pulumi.get(self, "display_names")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetProfileAvailableSoftwareSourcesFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="profileId")
    def profile_id(self) -> _builtins.str:
        return pulumi.get(self, "profile_id")


class AwaitableGetProfileAvailableSoftwareSourcesResult(GetProfileAvailableSoftwareSourcesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetProfileAvailableSoftwareSourcesResult(
            available_software_source_collections=self.available_software_source_collections,
            compartment_id=self.compartment_id,
            display_name_contains=self.display_name_contains,
            display_names=self.display_names,
            filters=self.filters,
            id=self.id,
            profile_id=self.profile_id)


def get_profile_available_software_sources(compartment_id: Optional[_builtins.str] = None,
                                           display_name_contains: Optional[_builtins.str] = None,
                                           display_names: Optional[Sequence[_builtins.str]] = None,
                                           filters: Optional[Sequence[Union['GetProfileAvailableSoftwareSourcesFilterArgs', 'GetProfileAvailableSoftwareSourcesFilterArgsDict']]] = None,
                                           profile_id: Optional[_builtins.str] = None,
                                           opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetProfileAvailableSoftwareSourcesResult:
    """
    This data source provides the list of Profile Available Software Sources in Oracle Cloud Infrastructure Os Management Hub service.

    Lists available software sources for a specified profile. Filter the list against a variety of criteria including but not limited to the software source name. The results list only software sources that have not already been added to the profile.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_profile_available_software_sources = oci.OsManagementHub.get_profile_available_software_sources(profile_id=test_profile["id"],
        compartment_id=compartment_id,
        display_names=profile_available_software_source_display_name,
        display_name_contains=profile_available_software_source_display_name_contains)
    ```


    :param _builtins.str compartment_id: The OCID of the compartment that contains the resources to list. This filter returns only resources contained within the specified compartment.
    :param _builtins.str display_name_contains: A filter to return resources that may partially match the given display name.
    :param Sequence[_builtins.str] display_names: A filter to return resources that match the given display names.
    :param _builtins.str profile_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the registration profile.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayNameContains'] = display_name_contains
    __args__['displayNames'] = display_names
    __args__['filters'] = filters
    __args__['profileId'] = profile_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:OsManagementHub/getProfileAvailableSoftwareSources:getProfileAvailableSoftwareSources', __args__, opts=opts, typ=GetProfileAvailableSoftwareSourcesResult).value

    return AwaitableGetProfileAvailableSoftwareSourcesResult(
        available_software_source_collections=pulumi.get(__ret__, 'available_software_source_collections'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        display_name_contains=pulumi.get(__ret__, 'display_name_contains'),
        display_names=pulumi.get(__ret__, 'display_names'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        profile_id=pulumi.get(__ret__, 'profile_id'))
def get_profile_available_software_sources_output(compartment_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                  display_name_contains: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                  display_names: Optional[pulumi.Input[Optional[Sequence[_builtins.str]]]] = None,
                                                  filters: Optional[pulumi.Input[Optional[Sequence[Union['GetProfileAvailableSoftwareSourcesFilterArgs', 'GetProfileAvailableSoftwareSourcesFilterArgsDict']]]]] = None,
                                                  profile_id: Optional[pulumi.Input[_builtins.str]] = None,
                                                  opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetProfileAvailableSoftwareSourcesResult]:
    """
    This data source provides the list of Profile Available Software Sources in Oracle Cloud Infrastructure Os Management Hub service.

    Lists available software sources for a specified profile. Filter the list against a variety of criteria including but not limited to the software source name. The results list only software sources that have not already been added to the profile.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_profile_available_software_sources = oci.OsManagementHub.get_profile_available_software_sources(profile_id=test_profile["id"],
        compartment_id=compartment_id,
        display_names=profile_available_software_source_display_name,
        display_name_contains=profile_available_software_source_display_name_contains)
    ```


    :param _builtins.str compartment_id: The OCID of the compartment that contains the resources to list. This filter returns only resources contained within the specified compartment.
    :param _builtins.str display_name_contains: A filter to return resources that may partially match the given display name.
    :param Sequence[_builtins.str] display_names: A filter to return resources that match the given display names.
    :param _builtins.str profile_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the registration profile.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayNameContains'] = display_name_contains
    __args__['displayNames'] = display_names
    __args__['filters'] = filters
    __args__['profileId'] = profile_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:OsManagementHub/getProfileAvailableSoftwareSources:getProfileAvailableSoftwareSources', __args__, opts=opts, typ=GetProfileAvailableSoftwareSourcesResult)
    return __ret__.apply(lambda __response__: GetProfileAvailableSoftwareSourcesResult(
        available_software_source_collections=pulumi.get(__response__, 'available_software_source_collections'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        display_name_contains=pulumi.get(__response__, 'display_name_contains'),
        display_names=pulumi.get(__response__, 'display_names'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        profile_id=pulumi.get(__response__, 'profile_id')))
