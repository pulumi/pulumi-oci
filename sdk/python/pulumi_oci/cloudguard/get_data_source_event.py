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

__all__ = [
    'GetDataSourceEventResult',
    'AwaitableGetDataSourceEventResult',
    'get_data_source_event',
    'get_data_source_event_output',
]

@pulumi.output_type
class GetDataSourceEventResult:
    """
    A collection of values returned by getDataSourceEvent.
    """
    def __init__(__self__, data_source_id=None, id=None, items=None, region=None):
        if data_source_id and not isinstance(data_source_id, str):
            raise TypeError("Expected argument 'data_source_id' to be a str")
        pulumi.set(__self__, "data_source_id", data_source_id)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if items and not isinstance(items, list):
            raise TypeError("Expected argument 'items' to be a list")
        pulumi.set(__self__, "items", items)
        if region and not isinstance(region, str):
            raise TypeError("Expected argument 'region' to be a str")
        pulumi.set(__self__, "region", region)

    @property
    @pulumi.getter(name="dataSourceId")
    def data_source_id(self) -> str:
        """
        Attached data Source
        """
        return pulumi.get(self, "data_source_id")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def items(self) -> Sequence['outputs.GetDataSourceEventItemResult']:
        """
        List of event related to a DataSource
        """
        return pulumi.get(self, "items")

    @property
    @pulumi.getter
    def region(self) -> Optional[str]:
        """
        Data source event region
        """
        return pulumi.get(self, "region")


class AwaitableGetDataSourceEventResult(GetDataSourceEventResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDataSourceEventResult(
            data_source_id=self.data_source_id,
            id=self.id,
            items=self.items,
            region=self.region)


def get_data_source_event(data_source_id: Optional[str] = None,
                          region: Optional[str] = None,
                          opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDataSourceEventResult:
    """
    This data source provides details about a specific Data Source Event resource in Oracle Cloud Infrastructure Cloud Guard service.

    Returns a list of events from CloudGuard DataSource

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_data_source_event = oci.CloudGuard.get_data_source_event(data_source_id=oci_cloud_guard_data_source["test_data_source"]["id"],
        region=var["data_source_event_region"])
    ```


    :param str data_source_id: DataSource OCID
    :param str region: A filter to return only resource their region matches the given region.
    """
    __args__ = dict()
    __args__['dataSourceId'] = data_source_id
    __args__['region'] = region
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:CloudGuard/getDataSourceEvent:getDataSourceEvent', __args__, opts=opts, typ=GetDataSourceEventResult).value

    return AwaitableGetDataSourceEventResult(
        data_source_id=__ret__.data_source_id,
        id=__ret__.id,
        items=__ret__.items,
        region=__ret__.region)


@_utilities.lift_output_func(get_data_source_event)
def get_data_source_event_output(data_source_id: Optional[pulumi.Input[str]] = None,
                                 region: Optional[pulumi.Input[Optional[str]]] = None,
                                 opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetDataSourceEventResult]:
    """
    This data source provides details about a specific Data Source Event resource in Oracle Cloud Infrastructure Cloud Guard service.

    Returns a list of events from CloudGuard DataSource

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_data_source_event = oci.CloudGuard.get_data_source_event(data_source_id=oci_cloud_guard_data_source["test_data_source"]["id"],
        region=var["data_source_event_region"])
    ```


    :param str data_source_id: DataSource OCID
    :param str region: A filter to return only resource their region matches the given region.
    """
    ...