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
    'GetCrossConnectLocationsResult',
    'AwaitableGetCrossConnectLocationsResult',
    'get_cross_connect_locations',
    'get_cross_connect_locations_output',
]

@pulumi.output_type
class GetCrossConnectLocationsResult:
    """
    A collection of values returned by getCrossConnectLocations.
    """
    def __init__(__self__, compartment_id=None, cross_connect_locations=None, filters=None, id=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if cross_connect_locations and not isinstance(cross_connect_locations, list):
            raise TypeError("Expected argument 'cross_connect_locations' to be a list")
        pulumi.set(__self__, "cross_connect_locations", cross_connect_locations)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="crossConnectLocations")
    def cross_connect_locations(self) -> Sequence['outputs.GetCrossConnectLocationsCrossConnectLocationResult']:
        """
        The list of cross_connect_locations.
        """
        return pulumi.get(self, "cross_connect_locations")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetCrossConnectLocationsFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")


class AwaitableGetCrossConnectLocationsResult(GetCrossConnectLocationsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetCrossConnectLocationsResult(
            compartment_id=self.compartment_id,
            cross_connect_locations=self.cross_connect_locations,
            filters=self.filters,
            id=self.id)


def get_cross_connect_locations(compartment_id: Optional[_builtins.str] = None,
                                filters: Optional[Sequence[Union['GetCrossConnectLocationsFilterArgs', 'GetCrossConnectLocationsFilterArgsDict']]] = None,
                                opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetCrossConnectLocationsResult:
    """
    This data source provides the list of Cross Connect Locations in Oracle Cloud Infrastructure Core service.

    Lists the available FastConnect locations for cross-connect installation. You need
    this information so you can specify your desired location when you create a cross-connect.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_cross_connect_locations = oci.Core.get_cross_connect_locations(compartment_id=compartment_id)
    ```


    :param _builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Core/getCrossConnectLocations:getCrossConnectLocations', __args__, opts=opts, typ=GetCrossConnectLocationsResult).value

    return AwaitableGetCrossConnectLocationsResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        cross_connect_locations=pulumi.get(__ret__, 'cross_connect_locations'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'))
def get_cross_connect_locations_output(compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                                       filters: Optional[pulumi.Input[Optional[Sequence[Union['GetCrossConnectLocationsFilterArgs', 'GetCrossConnectLocationsFilterArgsDict']]]]] = None,
                                       opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetCrossConnectLocationsResult]:
    """
    This data source provides the list of Cross Connect Locations in Oracle Cloud Infrastructure Core service.

    Lists the available FastConnect locations for cross-connect installation. You need
    this information so you can specify your desired location when you create a cross-connect.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_cross_connect_locations = oci.Core.get_cross_connect_locations(compartment_id=compartment_id)
    ```


    :param _builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Core/getCrossConnectLocations:getCrossConnectLocations', __args__, opts=opts, typ=GetCrossConnectLocationsResult)
    return __ret__.apply(lambda __response__: GetCrossConnectLocationsResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        cross_connect_locations=pulumi.get(__response__, 'cross_connect_locations'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id')))
