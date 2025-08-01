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
    'GetManagementStationMirrorsResult',
    'AwaitableGetManagementStationMirrorsResult',
    'get_management_station_mirrors',
    'get_management_station_mirrors_output',
]

@pulumi.output_type
class GetManagementStationMirrorsResult:
    """
    A collection of values returned by getManagementStationMirrors.
    """
    def __init__(__self__, display_name=None, display_name_contains=None, filters=None, id=None, management_station_id=None, mirror_states=None, mirrors_collections=None):
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
        if management_station_id and not isinstance(management_station_id, str):
            raise TypeError("Expected argument 'management_station_id' to be a str")
        pulumi.set(__self__, "management_station_id", management_station_id)
        if mirror_states and not isinstance(mirror_states, list):
            raise TypeError("Expected argument 'mirror_states' to be a list")
        pulumi.set(__self__, "mirror_states", mirror_states)
        if mirrors_collections and not isinstance(mirrors_collections, list):
            raise TypeError("Expected argument 'mirrors_collections' to be a list")
        pulumi.set(__self__, "mirrors_collections", mirrors_collections)

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[_builtins.str]:
        """
        Display name of the mirror.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="displayNameContains")
    def display_name_contains(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "display_name_contains")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetManagementStationMirrorsFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="managementStationId")
    def management_station_id(self) -> _builtins.str:
        return pulumi.get(self, "management_station_id")

    @_builtins.property
    @pulumi.getter(name="mirrorStates")
    def mirror_states(self) -> Optional[Sequence[_builtins.str]]:
        return pulumi.get(self, "mirror_states")

    @_builtins.property
    @pulumi.getter(name="mirrorsCollections")
    def mirrors_collections(self) -> Sequence['outputs.GetManagementStationMirrorsMirrorsCollectionResult']:
        """
        The list of mirrors_collection.
        """
        return pulumi.get(self, "mirrors_collections")


class AwaitableGetManagementStationMirrorsResult(GetManagementStationMirrorsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetManagementStationMirrorsResult(
            display_name=self.display_name,
            display_name_contains=self.display_name_contains,
            filters=self.filters,
            id=self.id,
            management_station_id=self.management_station_id,
            mirror_states=self.mirror_states,
            mirrors_collections=self.mirrors_collections)


def get_management_station_mirrors(display_name: Optional[_builtins.str] = None,
                                   display_name_contains: Optional[_builtins.str] = None,
                                   filters: Optional[Sequence[Union['GetManagementStationMirrorsFilterArgs', 'GetManagementStationMirrorsFilterArgsDict']]] = None,
                                   management_station_id: Optional[_builtins.str] = None,
                                   mirror_states: Optional[Sequence[_builtins.str]] = None,
                                   opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetManagementStationMirrorsResult:
    """
    This data source provides the list of Management Station Mirrors in Oracle Cloud Infrastructure Os Management Hub service.

    Lists all software source mirrors associated with a specified management station.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_management_station_mirrors = oci.OsManagementHub.get_management_station_mirrors(management_station_id=test_management_station["id"],
        display_name=management_station_mirror_display_name,
        display_name_contains=management_station_mirror_display_name_contains,
        mirror_states=management_station_mirror_mirror_states)
    ```


    :param _builtins.str display_name: A filter to return resources that match the given user-friendly name.
    :param _builtins.str display_name_contains: A filter to return resources that may partially match the given display name.
    :param _builtins.str management_station_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station.
    :param Sequence[_builtins.str] mirror_states: List of Mirror state to filter by
    """
    __args__ = dict()
    __args__['displayName'] = display_name
    __args__['displayNameContains'] = display_name_contains
    __args__['filters'] = filters
    __args__['managementStationId'] = management_station_id
    __args__['mirrorStates'] = mirror_states
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:OsManagementHub/getManagementStationMirrors:getManagementStationMirrors', __args__, opts=opts, typ=GetManagementStationMirrorsResult).value

    return AwaitableGetManagementStationMirrorsResult(
        display_name=pulumi.get(__ret__, 'display_name'),
        display_name_contains=pulumi.get(__ret__, 'display_name_contains'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        management_station_id=pulumi.get(__ret__, 'management_station_id'),
        mirror_states=pulumi.get(__ret__, 'mirror_states'),
        mirrors_collections=pulumi.get(__ret__, 'mirrors_collections'))
def get_management_station_mirrors_output(display_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                          display_name_contains: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                          filters: Optional[pulumi.Input[Optional[Sequence[Union['GetManagementStationMirrorsFilterArgs', 'GetManagementStationMirrorsFilterArgsDict']]]]] = None,
                                          management_station_id: Optional[pulumi.Input[_builtins.str]] = None,
                                          mirror_states: Optional[pulumi.Input[Optional[Sequence[_builtins.str]]]] = None,
                                          opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetManagementStationMirrorsResult]:
    """
    This data source provides the list of Management Station Mirrors in Oracle Cloud Infrastructure Os Management Hub service.

    Lists all software source mirrors associated with a specified management station.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_management_station_mirrors = oci.OsManagementHub.get_management_station_mirrors(management_station_id=test_management_station["id"],
        display_name=management_station_mirror_display_name,
        display_name_contains=management_station_mirror_display_name_contains,
        mirror_states=management_station_mirror_mirror_states)
    ```


    :param _builtins.str display_name: A filter to return resources that match the given user-friendly name.
    :param _builtins.str display_name_contains: A filter to return resources that may partially match the given display name.
    :param _builtins.str management_station_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station.
    :param Sequence[_builtins.str] mirror_states: List of Mirror state to filter by
    """
    __args__ = dict()
    __args__['displayName'] = display_name
    __args__['displayNameContains'] = display_name_contains
    __args__['filters'] = filters
    __args__['managementStationId'] = management_station_id
    __args__['mirrorStates'] = mirror_states
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:OsManagementHub/getManagementStationMirrors:getManagementStationMirrors', __args__, opts=opts, typ=GetManagementStationMirrorsResult)
    return __ret__.apply(lambda __response__: GetManagementStationMirrorsResult(
        display_name=pulumi.get(__response__, 'display_name'),
        display_name_contains=pulumi.get(__response__, 'display_name_contains'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        management_station_id=pulumi.get(__response__, 'management_station_id'),
        mirror_states=pulumi.get(__response__, 'mirror_states'),
        mirrors_collections=pulumi.get(__response__, 'mirrors_collections')))
