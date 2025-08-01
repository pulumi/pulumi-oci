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
    'GetFleetProductsResult',
    'AwaitableGetFleetProductsResult',
    'get_fleet_products',
    'get_fleet_products_output',
]

@pulumi.output_type
class GetFleetProductsResult:
    """
    A collection of values returned by getFleetProducts.
    """
    def __init__(__self__, compartment_id=None, display_name=None, filters=None, fleet_id=None, fleet_product_collections=None, id=None, resource_display_name=None, resource_id=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if fleet_id and not isinstance(fleet_id, str):
            raise TypeError("Expected argument 'fleet_id' to be a str")
        pulumi.set(__self__, "fleet_id", fleet_id)
        if fleet_product_collections and not isinstance(fleet_product_collections, list):
            raise TypeError("Expected argument 'fleet_product_collections' to be a list")
        pulumi.set(__self__, "fleet_product_collections", fleet_product_collections)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if resource_display_name and not isinstance(resource_display_name, str):
            raise TypeError("Expected argument 'resource_display_name' to be a str")
        pulumi.set(__self__, "resource_display_name", resource_display_name)
        if resource_id and not isinstance(resource_id, str):
            raise TypeError("Expected argument 'resource_id' to be a str")
        pulumi.set(__self__, "resource_id", resource_id)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[_builtins.str]:
        """
        Root Compartment Id.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[_builtins.str]:
        """
        A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetFleetProductsFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter(name="fleetId")
    def fleet_id(self) -> _builtins.str:
        return pulumi.get(self, "fleet_id")

    @_builtins.property
    @pulumi.getter(name="fleetProductCollections")
    def fleet_product_collections(self) -> Sequence['outputs.GetFleetProductsFleetProductCollectionResult']:
        """
        The list of fleet_product_collection.
        """
        return pulumi.get(self, "fleet_product_collections")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="resourceDisplayName")
    def resource_display_name(self) -> Optional[_builtins.str]:
        """
        A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
        """
        return pulumi.get(self, "resource_display_name")

    @_builtins.property
    @pulumi.getter(name="resourceId")
    def resource_id(self) -> Optional[_builtins.str]:
        """
        The OCID of the resource.
        """
        return pulumi.get(self, "resource_id")


class AwaitableGetFleetProductsResult(GetFleetProductsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetFleetProductsResult(
            compartment_id=self.compartment_id,
            display_name=self.display_name,
            filters=self.filters,
            fleet_id=self.fleet_id,
            fleet_product_collections=self.fleet_product_collections,
            id=self.id,
            resource_display_name=self.resource_display_name,
            resource_id=self.resource_id)


def get_fleet_products(compartment_id: Optional[_builtins.str] = None,
                       display_name: Optional[_builtins.str] = None,
                       filters: Optional[Sequence[Union['GetFleetProductsFilterArgs', 'GetFleetProductsFilterArgsDict']]] = None,
                       fleet_id: Optional[_builtins.str] = None,
                       resource_display_name: Optional[_builtins.str] = None,
                       resource_id: Optional[_builtins.str] = None,
                       opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetFleetProductsResult:
    """
    This data source provides the list of Fleet Products in Oracle Cloud Infrastructure Fleet Apps Management service.

    Returns a list of products associated with the confirmed targets.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_fleet_products = oci.FleetAppsManagement.get_fleet_products(fleet_id=test_fleet["id"],
        compartment_id=compartment_id,
        display_name=fleet_product_display_name,
        resource_display_name=fleet_product_resource_display_name,
        resource_id=test_resource["id"])
    ```


    :param _builtins.str compartment_id: The ID of the compartment in which to list resources. Empty only if the resource OCID query param is not specified.
    :param _builtins.str display_name: A filter to return only resources that match the entire display name given.
    :param _builtins.str fleet_id: Unique Fleet identifier.
    :param _builtins.str resource_display_name: Resource Display Name.
    :param _builtins.str resource_id: Resource Identifier
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['fleetId'] = fleet_id
    __args__['resourceDisplayName'] = resource_display_name
    __args__['resourceId'] = resource_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:FleetAppsManagement/getFleetProducts:getFleetProducts', __args__, opts=opts, typ=GetFleetProductsResult).value

    return AwaitableGetFleetProductsResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        display_name=pulumi.get(__ret__, 'display_name'),
        filters=pulumi.get(__ret__, 'filters'),
        fleet_id=pulumi.get(__ret__, 'fleet_id'),
        fleet_product_collections=pulumi.get(__ret__, 'fleet_product_collections'),
        id=pulumi.get(__ret__, 'id'),
        resource_display_name=pulumi.get(__ret__, 'resource_display_name'),
        resource_id=pulumi.get(__ret__, 'resource_id'))
def get_fleet_products_output(compartment_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                              display_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                              filters: Optional[pulumi.Input[Optional[Sequence[Union['GetFleetProductsFilterArgs', 'GetFleetProductsFilterArgsDict']]]]] = None,
                              fleet_id: Optional[pulumi.Input[_builtins.str]] = None,
                              resource_display_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                              resource_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                              opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetFleetProductsResult]:
    """
    This data source provides the list of Fleet Products in Oracle Cloud Infrastructure Fleet Apps Management service.

    Returns a list of products associated with the confirmed targets.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_fleet_products = oci.FleetAppsManagement.get_fleet_products(fleet_id=test_fleet["id"],
        compartment_id=compartment_id,
        display_name=fleet_product_display_name,
        resource_display_name=fleet_product_resource_display_name,
        resource_id=test_resource["id"])
    ```


    :param _builtins.str compartment_id: The ID of the compartment in which to list resources. Empty only if the resource OCID query param is not specified.
    :param _builtins.str display_name: A filter to return only resources that match the entire display name given.
    :param _builtins.str fleet_id: Unique Fleet identifier.
    :param _builtins.str resource_display_name: Resource Display Name.
    :param _builtins.str resource_id: Resource Identifier
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['fleetId'] = fleet_id
    __args__['resourceDisplayName'] = resource_display_name
    __args__['resourceId'] = resource_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:FleetAppsManagement/getFleetProducts:getFleetProducts', __args__, opts=opts, typ=GetFleetProductsResult)
    return __ret__.apply(lambda __response__: GetFleetProductsResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        display_name=pulumi.get(__response__, 'display_name'),
        filters=pulumi.get(__response__, 'filters'),
        fleet_id=pulumi.get(__response__, 'fleet_id'),
        fleet_product_collections=pulumi.get(__response__, 'fleet_product_collections'),
        id=pulumi.get(__response__, 'id'),
        resource_display_name=pulumi.get(__response__, 'resource_display_name'),
        resource_id=pulumi.get(__response__, 'resource_id')))
