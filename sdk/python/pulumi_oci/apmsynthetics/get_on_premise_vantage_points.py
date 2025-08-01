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
    'GetOnPremiseVantagePointsResult',
    'AwaitableGetOnPremiseVantagePointsResult',
    'get_on_premise_vantage_points',
    'get_on_premise_vantage_points_output',
]

@pulumi.output_type
class GetOnPremiseVantagePointsResult:
    """
    A collection of values returned by getOnPremiseVantagePoints.
    """
    def __init__(__self__, apm_domain_id=None, display_name=None, filters=None, id=None, name=None, on_premise_vantage_point_collections=None):
        if apm_domain_id and not isinstance(apm_domain_id, str):
            raise TypeError("Expected argument 'apm_domain_id' to be a str")
        pulumi.set(__self__, "apm_domain_id", apm_domain_id)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if on_premise_vantage_point_collections and not isinstance(on_premise_vantage_point_collections, list):
            raise TypeError("Expected argument 'on_premise_vantage_point_collections' to be a list")
        pulumi.set(__self__, "on_premise_vantage_point_collections", on_premise_vantage_point_collections)

    @_builtins.property
    @pulumi.getter(name="apmDomainId")
    def apm_domain_id(self) -> _builtins.str:
        return pulumi.get(self, "apm_domain_id")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[_builtins.str]:
        """
        Unique permanent name of the On-premise vantage point.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetOnPremiseVantagePointsFilterResult']]:
        return pulumi.get(self, "filters")

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
        Unique On-premise vantage point name that cannot be edited. The name should not contain any confidential information.
        """
        return pulumi.get(self, "name")

    @_builtins.property
    @pulumi.getter(name="onPremiseVantagePointCollections")
    def on_premise_vantage_point_collections(self) -> Sequence['outputs.GetOnPremiseVantagePointsOnPremiseVantagePointCollectionResult']:
        """
        The list of on_premise_vantage_point_collection.
        """
        return pulumi.get(self, "on_premise_vantage_point_collections")


class AwaitableGetOnPremiseVantagePointsResult(GetOnPremiseVantagePointsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetOnPremiseVantagePointsResult(
            apm_domain_id=self.apm_domain_id,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            name=self.name,
            on_premise_vantage_point_collections=self.on_premise_vantage_point_collections)


def get_on_premise_vantage_points(apm_domain_id: Optional[_builtins.str] = None,
                                  display_name: Optional[_builtins.str] = None,
                                  filters: Optional[Sequence[Union['GetOnPremiseVantagePointsFilterArgs', 'GetOnPremiseVantagePointsFilterArgsDict']]] = None,
                                  name: Optional[_builtins.str] = None,
                                  opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetOnPremiseVantagePointsResult:
    """
    This data source provides the list of On Premise Vantage Points in Oracle Cloud Infrastructure APM Availability Monitoring service (aka APM Synthetics Service).

    Returns a list of On-premise vantage points.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_on_premise_vantage_points = oci.ApmSynthetics.get_on_premise_vantage_points(apm_domain_id=test_apm_domain["id"],
        display_name=on_premise_vantage_point_display_name,
        name=on_premise_vantage_point_name)
    ```


    :param _builtins.str apm_domain_id: The APM domain ID the request is intended for.
    :param _builtins.str display_name: A filter to return only the resources that match the entire display name.
    :param _builtins.str name: A filter to return only the resources that match the entire name.
    """
    __args__ = dict()
    __args__['apmDomainId'] = apm_domain_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['name'] = name
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:ApmSynthetics/getOnPremiseVantagePoints:getOnPremiseVantagePoints', __args__, opts=opts, typ=GetOnPremiseVantagePointsResult).value

    return AwaitableGetOnPremiseVantagePointsResult(
        apm_domain_id=pulumi.get(__ret__, 'apm_domain_id'),
        display_name=pulumi.get(__ret__, 'display_name'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        name=pulumi.get(__ret__, 'name'),
        on_premise_vantage_point_collections=pulumi.get(__ret__, 'on_premise_vantage_point_collections'))
def get_on_premise_vantage_points_output(apm_domain_id: Optional[pulumi.Input[_builtins.str]] = None,
                                         display_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                         filters: Optional[pulumi.Input[Optional[Sequence[Union['GetOnPremiseVantagePointsFilterArgs', 'GetOnPremiseVantagePointsFilterArgsDict']]]]] = None,
                                         name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                         opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetOnPremiseVantagePointsResult]:
    """
    This data source provides the list of On Premise Vantage Points in Oracle Cloud Infrastructure APM Availability Monitoring service (aka APM Synthetics Service).

    Returns a list of On-premise vantage points.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_on_premise_vantage_points = oci.ApmSynthetics.get_on_premise_vantage_points(apm_domain_id=test_apm_domain["id"],
        display_name=on_premise_vantage_point_display_name,
        name=on_premise_vantage_point_name)
    ```


    :param _builtins.str apm_domain_id: The APM domain ID the request is intended for.
    :param _builtins.str display_name: A filter to return only the resources that match the entire display name.
    :param _builtins.str name: A filter to return only the resources that match the entire name.
    """
    __args__ = dict()
    __args__['apmDomainId'] = apm_domain_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['name'] = name
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:ApmSynthetics/getOnPremiseVantagePoints:getOnPremiseVantagePoints', __args__, opts=opts, typ=GetOnPremiseVantagePointsResult)
    return __ret__.apply(lambda __response__: GetOnPremiseVantagePointsResult(
        apm_domain_id=pulumi.get(__response__, 'apm_domain_id'),
        display_name=pulumi.get(__response__, 'display_name'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        name=pulumi.get(__response__, 'name'),
        on_premise_vantage_point_collections=pulumi.get(__response__, 'on_premise_vantage_point_collections')))
