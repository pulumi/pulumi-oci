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
    'GetVirtualCircuitBandwidthShapesResult',
    'AwaitableGetVirtualCircuitBandwidthShapesResult',
    'get_virtual_circuit_bandwidth_shapes',
    'get_virtual_circuit_bandwidth_shapes_output',
]

@pulumi.output_type
class GetVirtualCircuitBandwidthShapesResult:
    """
    A collection of values returned by getVirtualCircuitBandwidthShapes.
    """
    def __init__(__self__, filters=None, id=None, provider_service_id=None, virtual_circuit_bandwidth_shapes=None):
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if provider_service_id and not isinstance(provider_service_id, str):
            raise TypeError("Expected argument 'provider_service_id' to be a str")
        pulumi.set(__self__, "provider_service_id", provider_service_id)
        if virtual_circuit_bandwidth_shapes and not isinstance(virtual_circuit_bandwidth_shapes, list):
            raise TypeError("Expected argument 'virtual_circuit_bandwidth_shapes' to be a list")
        pulumi.set(__self__, "virtual_circuit_bandwidth_shapes", virtual_circuit_bandwidth_shapes)

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetVirtualCircuitBandwidthShapesFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="providerServiceId")
    def provider_service_id(self) -> _builtins.str:
        return pulumi.get(self, "provider_service_id")

    @_builtins.property
    @pulumi.getter(name="virtualCircuitBandwidthShapes")
    def virtual_circuit_bandwidth_shapes(self) -> Sequence['outputs.GetVirtualCircuitBandwidthShapesVirtualCircuitBandwidthShapeResult']:
        """
        The list of virtual_circuit_bandwidth_shapes.
        """
        return pulumi.get(self, "virtual_circuit_bandwidth_shapes")


class AwaitableGetVirtualCircuitBandwidthShapesResult(GetVirtualCircuitBandwidthShapesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetVirtualCircuitBandwidthShapesResult(
            filters=self.filters,
            id=self.id,
            provider_service_id=self.provider_service_id,
            virtual_circuit_bandwidth_shapes=self.virtual_circuit_bandwidth_shapes)


def get_virtual_circuit_bandwidth_shapes(filters: Optional[Sequence[Union['GetVirtualCircuitBandwidthShapesFilterArgs', 'GetVirtualCircuitBandwidthShapesFilterArgsDict']]] = None,
                                         provider_service_id: Optional[_builtins.str] = None,
                                         opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetVirtualCircuitBandwidthShapesResult:
    """
    This data source provides the list of Virtual Circuit Bandwidth Shapes in Oracle Cloud Infrastructure Core service.

    Gets the list of available virtual circuit bandwidth levels for a provider.
    You need this information so you can specify your desired bandwidth level (shape) when you create a virtual circuit.

    For more information about virtual circuits, see [FastConnect Overview](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/fastconnect.htm).

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_virtual_circuit_bandwidth_shapes = oci.Core.get_virtual_circuit_bandwidth_shapes(provider_service_id=test_fast_connect_provider_services["fastConnectProviderServices"][0]["id"])
    ```


    :param _builtins.str provider_service_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the provider service.
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['providerServiceId'] = provider_service_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Core/getVirtualCircuitBandwidthShapes:getVirtualCircuitBandwidthShapes', __args__, opts=opts, typ=GetVirtualCircuitBandwidthShapesResult).value

    return AwaitableGetVirtualCircuitBandwidthShapesResult(
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        provider_service_id=pulumi.get(__ret__, 'provider_service_id'),
        virtual_circuit_bandwidth_shapes=pulumi.get(__ret__, 'virtual_circuit_bandwidth_shapes'))
def get_virtual_circuit_bandwidth_shapes_output(filters: Optional[pulumi.Input[Optional[Sequence[Union['GetVirtualCircuitBandwidthShapesFilterArgs', 'GetVirtualCircuitBandwidthShapesFilterArgsDict']]]]] = None,
                                                provider_service_id: Optional[pulumi.Input[_builtins.str]] = None,
                                                opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetVirtualCircuitBandwidthShapesResult]:
    """
    This data source provides the list of Virtual Circuit Bandwidth Shapes in Oracle Cloud Infrastructure Core service.

    Gets the list of available virtual circuit bandwidth levels for a provider.
    You need this information so you can specify your desired bandwidth level (shape) when you create a virtual circuit.

    For more information about virtual circuits, see [FastConnect Overview](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/fastconnect.htm).

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_virtual_circuit_bandwidth_shapes = oci.Core.get_virtual_circuit_bandwidth_shapes(provider_service_id=test_fast_connect_provider_services["fastConnectProviderServices"][0]["id"])
    ```


    :param _builtins.str provider_service_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the provider service.
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['providerServiceId'] = provider_service_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Core/getVirtualCircuitBandwidthShapes:getVirtualCircuitBandwidthShapes', __args__, opts=opts, typ=GetVirtualCircuitBandwidthShapesResult)
    return __ret__.apply(lambda __response__: GetVirtualCircuitBandwidthShapesResult(
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        provider_service_id=pulumi.get(__response__, 'provider_service_id'),
        virtual_circuit_bandwidth_shapes=pulumi.get(__response__, 'virtual_circuit_bandwidth_shapes')))
