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
    'GetDedicatedVantagePointsResult',
    'AwaitableGetDedicatedVantagePointsResult',
    'get_dedicated_vantage_points',
    'get_dedicated_vantage_points_output',
]

@pulumi.output_type
class GetDedicatedVantagePointsResult:
    """
    A collection of values returned by getDedicatedVantagePoints.
    """
    def __init__(__self__, apm_domain_id=None, dedicated_vantage_point_collections=None, display_name=None, filters=None, id=None, name=None, status=None):
        if apm_domain_id and not isinstance(apm_domain_id, str):
            raise TypeError("Expected argument 'apm_domain_id' to be a str")
        pulumi.set(__self__, "apm_domain_id", apm_domain_id)
        if dedicated_vantage_point_collections and not isinstance(dedicated_vantage_point_collections, list):
            raise TypeError("Expected argument 'dedicated_vantage_point_collections' to be a list")
        pulumi.set(__self__, "dedicated_vantage_point_collections", dedicated_vantage_point_collections)
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
        if status and not isinstance(status, str):
            raise TypeError("Expected argument 'status' to be a str")
        pulumi.set(__self__, "status", status)

    @property
    @pulumi.getter(name="apmDomainId")
    def apm_domain_id(self) -> str:
        return pulumi.get(self, "apm_domain_id")

    @property
    @pulumi.getter(name="dedicatedVantagePointCollections")
    def dedicated_vantage_point_collections(self) -> Sequence['outputs.GetDedicatedVantagePointsDedicatedVantagePointCollectionResult']:
        """
        The list of dedicated_vantage_point_collection.
        """
        return pulumi.get(self, "dedicated_vantage_point_collections")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[str]:
        """
        Unique dedicated vantage point name that cannot be edited. The name should not contain any confidential information.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetDedicatedVantagePointsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def name(self) -> Optional[str]:
        """
        Unique permanent name of the dedicated vantage point. This is the same as the displayName.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter
    def status(self) -> Optional[str]:
        """
        Status of the dedicated vantage point.
        """
        return pulumi.get(self, "status")


class AwaitableGetDedicatedVantagePointsResult(GetDedicatedVantagePointsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDedicatedVantagePointsResult(
            apm_domain_id=self.apm_domain_id,
            dedicated_vantage_point_collections=self.dedicated_vantage_point_collections,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            name=self.name,
            status=self.status)


def get_dedicated_vantage_points(apm_domain_id: Optional[str] = None,
                                 display_name: Optional[str] = None,
                                 filters: Optional[Sequence[pulumi.InputType['GetDedicatedVantagePointsFilterArgs']]] = None,
                                 name: Optional[str] = None,
                                 status: Optional[str] = None,
                                 opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDedicatedVantagePointsResult:
    """
    This data source provides the list of Dedicated Vantage Points in Oracle Cloud Infrastructure Apm Synthetics service.

    Returns a list of dedicated vantage points.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_dedicated_vantage_points = oci.ApmSynthetics.get_dedicated_vantage_points(apm_domain_id=oci_apm_apm_domain["test_apm_domain"]["id"],
        display_name=var["dedicated_vantage_point_display_name"],
        name=var["dedicated_vantage_point_name"],
        status=var["dedicated_vantage_point_status"])
    ```


    :param str apm_domain_id: The APM domain ID the request is intended for.
    :param str display_name: A filter to return only the resources that match the entire display name.
    :param str name: A filter to return only the resources that match the entire name.
    :param str status: A filter to return only the dedicated vantage points that match a given status.
    """
    __args__ = dict()
    __args__['apmDomainId'] = apm_domain_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['name'] = name
    __args__['status'] = status
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:ApmSynthetics/getDedicatedVantagePoints:getDedicatedVantagePoints', __args__, opts=opts, typ=GetDedicatedVantagePointsResult).value

    return AwaitableGetDedicatedVantagePointsResult(
        apm_domain_id=__ret__.apm_domain_id,
        dedicated_vantage_point_collections=__ret__.dedicated_vantage_point_collections,
        display_name=__ret__.display_name,
        filters=__ret__.filters,
        id=__ret__.id,
        name=__ret__.name,
        status=__ret__.status)


@_utilities.lift_output_func(get_dedicated_vantage_points)
def get_dedicated_vantage_points_output(apm_domain_id: Optional[pulumi.Input[str]] = None,
                                        display_name: Optional[pulumi.Input[Optional[str]]] = None,
                                        filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetDedicatedVantagePointsFilterArgs']]]]] = None,
                                        name: Optional[pulumi.Input[Optional[str]]] = None,
                                        status: Optional[pulumi.Input[Optional[str]]] = None,
                                        opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetDedicatedVantagePointsResult]:
    """
    This data source provides the list of Dedicated Vantage Points in Oracle Cloud Infrastructure Apm Synthetics service.

    Returns a list of dedicated vantage points.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_dedicated_vantage_points = oci.ApmSynthetics.get_dedicated_vantage_points(apm_domain_id=oci_apm_apm_domain["test_apm_domain"]["id"],
        display_name=var["dedicated_vantage_point_display_name"],
        name=var["dedicated_vantage_point_name"],
        status=var["dedicated_vantage_point_status"])
    ```


    :param str apm_domain_id: The APM domain ID the request is intended for.
    :param str display_name: A filter to return only the resources that match the entire display name.
    :param str name: A filter to return only the resources that match the entire name.
    :param str status: A filter to return only the dedicated vantage points that match a given status.
    """
    ...