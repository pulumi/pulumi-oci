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
    'GetOperationsInsightsWarehousesResult',
    'AwaitableGetOperationsInsightsWarehousesResult',
    'get_operations_insights_warehouses',
    'get_operations_insights_warehouses_output',
]

@pulumi.output_type
class GetOperationsInsightsWarehousesResult:
    """
    A collection of values returned by getOperationsInsightsWarehouses.
    """
    def __init__(__self__, compartment_id=None, display_name=None, filters=None, id=None, operations_insights_warehouse_summary_collections=None, states=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if operations_insights_warehouse_summary_collections and not isinstance(operations_insights_warehouse_summary_collections, list):
            raise TypeError("Expected argument 'operations_insights_warehouse_summary_collections' to be a list")
        pulumi.set(__self__, "operations_insights_warehouse_summary_collections", operations_insights_warehouse_summary_collections)
        if states and not isinstance(states, list):
            raise TypeError("Expected argument 'states' to be a list")
        pulumi.set(__self__, "states", states)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[str]:
        """
        User-friedly name of Operations Insights Warehouse that does not have to be unique.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetOperationsInsightsWarehousesFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> Optional[str]:
        """
        OPSI Warehouse OCID
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="operationsInsightsWarehouseSummaryCollections")
    def operations_insights_warehouse_summary_collections(self) -> Sequence['outputs.GetOperationsInsightsWarehousesOperationsInsightsWarehouseSummaryCollectionResult']:
        """
        The list of operations_insights_warehouse_summary_collection.
        """
        return pulumi.get(self, "operations_insights_warehouse_summary_collections")

    @property
    @pulumi.getter
    def states(self) -> Optional[Sequence[str]]:
        """
        Possible lifecycle states
        """
        return pulumi.get(self, "states")


class AwaitableGetOperationsInsightsWarehousesResult(GetOperationsInsightsWarehousesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetOperationsInsightsWarehousesResult(
            compartment_id=self.compartment_id,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            operations_insights_warehouse_summary_collections=self.operations_insights_warehouse_summary_collections,
            states=self.states)


def get_operations_insights_warehouses(compartment_id: Optional[str] = None,
                                       display_name: Optional[str] = None,
                                       filters: Optional[Sequence[pulumi.InputType['GetOperationsInsightsWarehousesFilterArgs']]] = None,
                                       id: Optional[str] = None,
                                       states: Optional[Sequence[str]] = None,
                                       opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetOperationsInsightsWarehousesResult:
    """
    This data source provides the list of Operations Insights Warehouses in Oracle Cloud Infrastructure Opsi service.

    Gets a list of Operations Insights warehouses. Either compartmentId or id must be specified.
    There is only expected to be 1 warehouse per tenant. The warehouse is expected to be in the root compartment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_operations_insights_warehouses = oci.Opsi.get_operations_insights_warehouses(compartment_id=var["compartment_id"],
        display_name=var["operations_insights_warehouse_display_name"],
        id=var["operations_insights_warehouse_id"],
        states=var["operations_insights_warehouse_state"])
    ```


    :param str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param str display_name: A filter to return only resources that match the entire display name.
    :param str id: Unique Operations Insights Warehouse identifier
    :param Sequence[str] states: Lifecycle states
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['id'] = id
    __args__['states'] = states
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Opsi/getOperationsInsightsWarehouses:getOperationsInsightsWarehouses', __args__, opts=opts, typ=GetOperationsInsightsWarehousesResult).value

    return AwaitableGetOperationsInsightsWarehousesResult(
        compartment_id=__ret__.compartment_id,
        display_name=__ret__.display_name,
        filters=__ret__.filters,
        id=__ret__.id,
        operations_insights_warehouse_summary_collections=__ret__.operations_insights_warehouse_summary_collections,
        states=__ret__.states)


@_utilities.lift_output_func(get_operations_insights_warehouses)
def get_operations_insights_warehouses_output(compartment_id: Optional[pulumi.Input[Optional[str]]] = None,
                                              display_name: Optional[pulumi.Input[Optional[str]]] = None,
                                              filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetOperationsInsightsWarehousesFilterArgs']]]]] = None,
                                              id: Optional[pulumi.Input[Optional[str]]] = None,
                                              states: Optional[pulumi.Input[Optional[Sequence[str]]]] = None,
                                              opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetOperationsInsightsWarehousesResult]:
    """
    This data source provides the list of Operations Insights Warehouses in Oracle Cloud Infrastructure Opsi service.

    Gets a list of Operations Insights warehouses. Either compartmentId or id must be specified.
    There is only expected to be 1 warehouse per tenant. The warehouse is expected to be in the root compartment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_operations_insights_warehouses = oci.Opsi.get_operations_insights_warehouses(compartment_id=var["compartment_id"],
        display_name=var["operations_insights_warehouse_display_name"],
        id=var["operations_insights_warehouse_id"],
        states=var["operations_insights_warehouse_state"])
    ```


    :param str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param str display_name: A filter to return only resources that match the entire display name.
    :param str id: Unique Operations Insights Warehouse identifier
    :param Sequence[str] states: Lifecycle states
    """
    ...