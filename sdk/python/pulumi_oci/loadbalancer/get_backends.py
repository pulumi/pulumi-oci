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
    'GetBackendsResult',
    'AwaitableGetBackendsResult',
    'get_backends',
    'get_backends_output',
]

@pulumi.output_type
class GetBackendsResult:
    """
    A collection of values returned by getBackends.
    """
    def __init__(__self__, backends=None, backendset_name=None, filters=None, id=None, load_balancer_id=None):
        if backends and not isinstance(backends, list):
            raise TypeError("Expected argument 'backends' to be a list")
        pulumi.set(__self__, "backends", backends)
        if backendset_name and not isinstance(backendset_name, str):
            raise TypeError("Expected argument 'backendset_name' to be a str")
        pulumi.set(__self__, "backendset_name", backendset_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if load_balancer_id and not isinstance(load_balancer_id, str):
            raise TypeError("Expected argument 'load_balancer_id' to be a str")
        pulumi.set(__self__, "load_balancer_id", load_balancer_id)

    @_builtins.property
    @pulumi.getter
    def backends(self) -> Sequence['outputs.GetBackendsBackendResult']:
        """
        The list of backends.
        """
        return pulumi.get(self, "backends")

    @_builtins.property
    @pulumi.getter(name="backendsetName")
    def backendset_name(self) -> _builtins.str:
        return pulumi.get(self, "backendset_name")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetBackendsFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="loadBalancerId")
    def load_balancer_id(self) -> _builtins.str:
        return pulumi.get(self, "load_balancer_id")


class AwaitableGetBackendsResult(GetBackendsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetBackendsResult(
            backends=self.backends,
            backendset_name=self.backendset_name,
            filters=self.filters,
            id=self.id,
            load_balancer_id=self.load_balancer_id)


def get_backends(backendset_name: Optional[_builtins.str] = None,
                 filters: Optional[Sequence[Union['GetBackendsFilterArgs', 'GetBackendsFilterArgsDict']]] = None,
                 load_balancer_id: Optional[_builtins.str] = None,
                 opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetBackendsResult:
    """
    This data source provides the list of Backends in Oracle Cloud Infrastructure Load Balancer service.

    Lists the backend servers for a given load balancer and backend set.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_backends = oci.LoadBalancer.get_backends(backendset_name=test_backend_set["name"],
        load_balancer_id=test_load_balancer["id"])
    ```


    :param _builtins.str backendset_name: The name of the backend set associated with the backend servers.  Example: `example_backend_set`
    :param _builtins.str load_balancer_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the backend set and servers.
    """
    __args__ = dict()
    __args__['backendsetName'] = backendset_name
    __args__['filters'] = filters
    __args__['loadBalancerId'] = load_balancer_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:LoadBalancer/getBackends:getBackends', __args__, opts=opts, typ=GetBackendsResult).value

    return AwaitableGetBackendsResult(
        backends=pulumi.get(__ret__, 'backends'),
        backendset_name=pulumi.get(__ret__, 'backendset_name'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        load_balancer_id=pulumi.get(__ret__, 'load_balancer_id'))
def get_backends_output(backendset_name: Optional[pulumi.Input[_builtins.str]] = None,
                        filters: Optional[pulumi.Input[Optional[Sequence[Union['GetBackendsFilterArgs', 'GetBackendsFilterArgsDict']]]]] = None,
                        load_balancer_id: Optional[pulumi.Input[_builtins.str]] = None,
                        opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetBackendsResult]:
    """
    This data source provides the list of Backends in Oracle Cloud Infrastructure Load Balancer service.

    Lists the backend servers for a given load balancer and backend set.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_backends = oci.LoadBalancer.get_backends(backendset_name=test_backend_set["name"],
        load_balancer_id=test_load_balancer["id"])
    ```


    :param _builtins.str backendset_name: The name of the backend set associated with the backend servers.  Example: `example_backend_set`
    :param _builtins.str load_balancer_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the backend set and servers.
    """
    __args__ = dict()
    __args__['backendsetName'] = backendset_name
    __args__['filters'] = filters
    __args__['loadBalancerId'] = load_balancer_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:LoadBalancer/getBackends:getBackends', __args__, opts=opts, typ=GetBackendsResult)
    return __ret__.apply(lambda __response__: GetBackendsResult(
        backends=pulumi.get(__response__, 'backends'),
        backendset_name=pulumi.get(__response__, 'backendset_name'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        load_balancer_id=pulumi.get(__response__, 'load_balancer_id')))
