# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities
from . import outputs
from ._inputs import *

__all__ = [
    'GetSoftwareSourceModuleStreamProfilesResult',
    'AwaitableGetSoftwareSourceModuleStreamProfilesResult',
    'get_software_source_module_stream_profiles',
    'get_software_source_module_stream_profiles_output',
]

@pulumi.output_type
class GetSoftwareSourceModuleStreamProfilesResult:
    """
    A collection of values returned by getSoftwareSourceModuleStreamProfiles.
    """
    def __init__(__self__, filters=None, id=None, module_name=None, module_stream_profile_collections=None, name=None, software_source_id=None, stream_name=None):
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if module_name and not isinstance(module_name, str):
            raise TypeError("Expected argument 'module_name' to be a str")
        pulumi.set(__self__, "module_name", module_name)
        if module_stream_profile_collections and not isinstance(module_stream_profile_collections, list):
            raise TypeError("Expected argument 'module_stream_profile_collections' to be a list")
        pulumi.set(__self__, "module_stream_profile_collections", module_stream_profile_collections)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if software_source_id and not isinstance(software_source_id, str):
            raise TypeError("Expected argument 'software_source_id' to be a str")
        pulumi.set(__self__, "software_source_id", software_source_id)
        if stream_name and not isinstance(stream_name, str):
            raise TypeError("Expected argument 'stream_name' to be a str")
        pulumi.set(__self__, "stream_name", stream_name)

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetSoftwareSourceModuleStreamProfilesFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="moduleName")
    def module_name(self) -> Optional[str]:
        """
        The name of the module that contains the stream profile.
        """
        return pulumi.get(self, "module_name")

    @property
    @pulumi.getter(name="moduleStreamProfileCollections")
    def module_stream_profile_collections(self) -> Sequence['outputs.GetSoftwareSourceModuleStreamProfilesModuleStreamProfileCollectionResult']:
        """
        The list of module_stream_profile_collection.
        """
        return pulumi.get(self, "module_stream_profile_collections")

    @property
    @pulumi.getter
    def name(self) -> Optional[str]:
        """
        The name of the profile.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter(name="softwareSourceId")
    def software_source_id(self) -> str:
        return pulumi.get(self, "software_source_id")

    @property
    @pulumi.getter(name="streamName")
    def stream_name(self) -> Optional[str]:
        """
        The name of the stream that contains the profile.
        """
        return pulumi.get(self, "stream_name")


class AwaitableGetSoftwareSourceModuleStreamProfilesResult(GetSoftwareSourceModuleStreamProfilesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetSoftwareSourceModuleStreamProfilesResult(
            filters=self.filters,
            id=self.id,
            module_name=self.module_name,
            module_stream_profile_collections=self.module_stream_profile_collections,
            name=self.name,
            software_source_id=self.software_source_id,
            stream_name=self.stream_name)


def get_software_source_module_stream_profiles(filters: Optional[Sequence[pulumi.InputType['GetSoftwareSourceModuleStreamProfilesFilterArgs']]] = None,
                                               module_name: Optional[str] = None,
                                               name: Optional[str] = None,
                                               software_source_id: Optional[str] = None,
                                               stream_name: Optional[str] = None,
                                               opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetSoftwareSourceModuleStreamProfilesResult:
    """
    This data source provides the list of Software Source Module Stream Profiles in Oracle Cloud Infrastructure Os Management Hub service.

    Lists module stream profiles from the specified software source OCID. Filter the list against a variety of
    criteria including but not limited to its module name, stream name, and (profile) name.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_software_source_module_stream_profiles = oci.OsManagementHub.get_software_source_module_stream_profiles(software_source_id=oci_os_management_hub_software_source["test_software_source"]["id"],
        module_name=var["software_source_module_stream_profile_module_name"],
        name=var["software_source_module_stream_profile_name"],
        stream_name=oci_streaming_stream["test_stream"]["name"])
    ```


    :param str module_name: The name of a module. This parameter is required if a streamName is specified.
    :param str name: The name of the entity to be queried.
    :param str software_source_id: The software source OCID.
    :param str stream_name: The name of the stream of the containing module.  This parameter is required if a profileName is specified.
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['moduleName'] = module_name
    __args__['name'] = name
    __args__['softwareSourceId'] = software_source_id
    __args__['streamName'] = stream_name
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:OsManagementHub/getSoftwareSourceModuleStreamProfiles:getSoftwareSourceModuleStreamProfiles', __args__, opts=opts, typ=GetSoftwareSourceModuleStreamProfilesResult).value

    return AwaitableGetSoftwareSourceModuleStreamProfilesResult(
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        module_name=pulumi.get(__ret__, 'module_name'),
        module_stream_profile_collections=pulumi.get(__ret__, 'module_stream_profile_collections'),
        name=pulumi.get(__ret__, 'name'),
        software_source_id=pulumi.get(__ret__, 'software_source_id'),
        stream_name=pulumi.get(__ret__, 'stream_name'))


@_utilities.lift_output_func(get_software_source_module_stream_profiles)
def get_software_source_module_stream_profiles_output(filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetSoftwareSourceModuleStreamProfilesFilterArgs']]]]] = None,
                                                      module_name: Optional[pulumi.Input[Optional[str]]] = None,
                                                      name: Optional[pulumi.Input[Optional[str]]] = None,
                                                      software_source_id: Optional[pulumi.Input[str]] = None,
                                                      stream_name: Optional[pulumi.Input[Optional[str]]] = None,
                                                      opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetSoftwareSourceModuleStreamProfilesResult]:
    """
    This data source provides the list of Software Source Module Stream Profiles in Oracle Cloud Infrastructure Os Management Hub service.

    Lists module stream profiles from the specified software source OCID. Filter the list against a variety of
    criteria including but not limited to its module name, stream name, and (profile) name.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_software_source_module_stream_profiles = oci.OsManagementHub.get_software_source_module_stream_profiles(software_source_id=oci_os_management_hub_software_source["test_software_source"]["id"],
        module_name=var["software_source_module_stream_profile_module_name"],
        name=var["software_source_module_stream_profile_name"],
        stream_name=oci_streaming_stream["test_stream"]["name"])
    ```


    :param str module_name: The name of a module. This parameter is required if a streamName is specified.
    :param str name: The name of the entity to be queried.
    :param str software_source_id: The software source OCID.
    :param str stream_name: The name of the stream of the containing module.  This parameter is required if a profileName is specified.
    """
    ...