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

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetSoftwareSourceModuleStreamProfilesFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="moduleName")
    def module_name(self) -> Optional[_builtins.str]:
        """
        The name of the module that contains the stream profile.
        """
        return pulumi.get(self, "module_name")

    @_builtins.property
    @pulumi.getter(name="moduleStreamProfileCollections")
    def module_stream_profile_collections(self) -> Sequence['outputs.GetSoftwareSourceModuleStreamProfilesModuleStreamProfileCollectionResult']:
        """
        The list of module_stream_profile_collection.
        """
        return pulumi.get(self, "module_stream_profile_collections")

    @_builtins.property
    @pulumi.getter
    def name(self) -> Optional[_builtins.str]:
        """
        The name of the profile.
        """
        return pulumi.get(self, "name")

    @_builtins.property
    @pulumi.getter(name="softwareSourceId")
    def software_source_id(self) -> _builtins.str:
        return pulumi.get(self, "software_source_id")

    @_builtins.property
    @pulumi.getter(name="streamName")
    def stream_name(self) -> Optional[_builtins.str]:
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


def get_software_source_module_stream_profiles(filters: Optional[Sequence[Union['GetSoftwareSourceModuleStreamProfilesFilterArgs', 'GetSoftwareSourceModuleStreamProfilesFilterArgsDict']]] = None,
                                               module_name: Optional[_builtins.str] = None,
                                               name: Optional[_builtins.str] = None,
                                               software_source_id: Optional[_builtins.str] = None,
                                               stream_name: Optional[_builtins.str] = None,
                                               opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetSoftwareSourceModuleStreamProfilesResult:
    """
    This data source provides the list of Software Source Module Stream Profiles in Oracle Cloud Infrastructure Os Management Hub service.

    Lists module stream profiles from the specified software source [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Filter the list against a variety of
    criteria including but not limited to its module name, stream name, and profile name.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_software_source_module_stream_profiles = oci.OsManagementHub.get_software_source_module_stream_profiles(software_source_id=test_software_source["id"],
        module_name=software_source_module_stream_profile_module_name,
        name=software_source_module_stream_profile_name,
        stream_name=test_stream["name"])
    ```


    :param _builtins.str module_name: The name of a module. This parameter is required if a streamName is specified.
    :param _builtins.str name: The name of the entity to be queried.
    :param _builtins.str software_source_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
    :param _builtins.str stream_name: The name of the module stream. This parameter is required if a profile name is specified.
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
def get_software_source_module_stream_profiles_output(filters: Optional[pulumi.Input[Optional[Sequence[Union['GetSoftwareSourceModuleStreamProfilesFilterArgs', 'GetSoftwareSourceModuleStreamProfilesFilterArgsDict']]]]] = None,
                                                      module_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                      name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                      software_source_id: Optional[pulumi.Input[_builtins.str]] = None,
                                                      stream_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                      opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetSoftwareSourceModuleStreamProfilesResult]:
    """
    This data source provides the list of Software Source Module Stream Profiles in Oracle Cloud Infrastructure Os Management Hub service.

    Lists module stream profiles from the specified software source [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Filter the list against a variety of
    criteria including but not limited to its module name, stream name, and profile name.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_software_source_module_stream_profiles = oci.OsManagementHub.get_software_source_module_stream_profiles(software_source_id=test_software_source["id"],
        module_name=software_source_module_stream_profile_module_name,
        name=software_source_module_stream_profile_name,
        stream_name=test_stream["name"])
    ```


    :param _builtins.str module_name: The name of a module. This parameter is required if a streamName is specified.
    :param _builtins.str name: The name of the entity to be queried.
    :param _builtins.str software_source_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
    :param _builtins.str stream_name: The name of the module stream. This parameter is required if a profile name is specified.
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['moduleName'] = module_name
    __args__['name'] = name
    __args__['softwareSourceId'] = software_source_id
    __args__['streamName'] = stream_name
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:OsManagementHub/getSoftwareSourceModuleStreamProfiles:getSoftwareSourceModuleStreamProfiles', __args__, opts=opts, typ=GetSoftwareSourceModuleStreamProfilesResult)
    return __ret__.apply(lambda __response__: GetSoftwareSourceModuleStreamProfilesResult(
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        module_name=pulumi.get(__response__, 'module_name'),
        module_stream_profile_collections=pulumi.get(__response__, 'module_stream_profile_collections'),
        name=pulumi.get(__response__, 'name'),
        software_source_id=pulumi.get(__response__, 'software_source_id'),
        stream_name=pulumi.get(__response__, 'stream_name')))
