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
    'GetCatalogPrivateEndpointsResult',
    'AwaitableGetCatalogPrivateEndpointsResult',
    'get_catalog_private_endpoints',
    'get_catalog_private_endpoints_output',
]

@pulumi.output_type
class GetCatalogPrivateEndpointsResult:
    """
    A collection of values returned by getCatalogPrivateEndpoints.
    """
    def __init__(__self__, catalog_private_endpoints=None, compartment_id=None, display_name=None, filters=None, id=None, state=None):
        if catalog_private_endpoints and not isinstance(catalog_private_endpoints, list):
            raise TypeError("Expected argument 'catalog_private_endpoints' to be a list")
        pulumi.set(__self__, "catalog_private_endpoints", catalog_private_endpoints)
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
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @_builtins.property
    @pulumi.getter(name="catalogPrivateEndpoints")
    def catalog_private_endpoints(self) -> Sequence['outputs.GetCatalogPrivateEndpointsCatalogPrivateEndpointResult']:
        """
        The list of catalog_private_endpoints.
        """
        return pulumi.get(self, "catalog_private_endpoints")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        Identifier of the compartment this private endpoint belongs to
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[_builtins.str]:
        """
        Mutable name of the Private Reverse Connection Endpoint
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetCatalogPrivateEndpointsFilterResult']]:
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
    def state(self) -> Optional[_builtins.str]:
        """
        The current state of the private endpoint resource.
        """
        return pulumi.get(self, "state")


class AwaitableGetCatalogPrivateEndpointsResult(GetCatalogPrivateEndpointsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetCatalogPrivateEndpointsResult(
            catalog_private_endpoints=self.catalog_private_endpoints,
            compartment_id=self.compartment_id,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            state=self.state)


def get_catalog_private_endpoints(compartment_id: Optional[_builtins.str] = None,
                                  display_name: Optional[_builtins.str] = None,
                                  filters: Optional[Sequence[Union['GetCatalogPrivateEndpointsFilterArgs', 'GetCatalogPrivateEndpointsFilterArgsDict']]] = None,
                                  state: Optional[_builtins.str] = None,
                                  opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetCatalogPrivateEndpointsResult:
    """
    This data source provides the list of Catalog Private Endpoints in Oracle Cloud Infrastructure Data Catalog service.

    Returns a list of all the catalog private endpoints in the specified compartment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_catalog_private_endpoints = oci.DataCatalog.get_catalog_private_endpoints(compartment_id=compartment_id,
        display_name=catalog_private_endpoint_display_name,
        state=catalog_private_endpoint_state)
    ```


    :param _builtins.str compartment_id: The OCID of the compartment where you want to list resources.
    :param _builtins.str display_name: A filter to return only resources that match the entire display name given. The match is not case sensitive.
    :param _builtins.str state: A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['state'] = state
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DataCatalog/getCatalogPrivateEndpoints:getCatalogPrivateEndpoints', __args__, opts=opts, typ=GetCatalogPrivateEndpointsResult).value

    return AwaitableGetCatalogPrivateEndpointsResult(
        catalog_private_endpoints=pulumi.get(__ret__, 'catalog_private_endpoints'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        display_name=pulumi.get(__ret__, 'display_name'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        state=pulumi.get(__ret__, 'state'))
def get_catalog_private_endpoints_output(compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                                         display_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                         filters: Optional[pulumi.Input[Optional[Sequence[Union['GetCatalogPrivateEndpointsFilterArgs', 'GetCatalogPrivateEndpointsFilterArgsDict']]]]] = None,
                                         state: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                         opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetCatalogPrivateEndpointsResult]:
    """
    This data source provides the list of Catalog Private Endpoints in Oracle Cloud Infrastructure Data Catalog service.

    Returns a list of all the catalog private endpoints in the specified compartment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_catalog_private_endpoints = oci.DataCatalog.get_catalog_private_endpoints(compartment_id=compartment_id,
        display_name=catalog_private_endpoint_display_name,
        state=catalog_private_endpoint_state)
    ```


    :param _builtins.str compartment_id: The OCID of the compartment where you want to list resources.
    :param _builtins.str display_name: A filter to return only resources that match the entire display name given. The match is not case sensitive.
    :param _builtins.str state: A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['state'] = state
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:DataCatalog/getCatalogPrivateEndpoints:getCatalogPrivateEndpoints', __args__, opts=opts, typ=GetCatalogPrivateEndpointsResult)
    return __ret__.apply(lambda __response__: GetCatalogPrivateEndpointsResult(
        catalog_private_endpoints=pulumi.get(__response__, 'catalog_private_endpoints'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        display_name=pulumi.get(__response__, 'display_name'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        state=pulumi.get(__response__, 'state')))
