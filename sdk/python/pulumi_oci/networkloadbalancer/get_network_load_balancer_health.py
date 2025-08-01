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

__all__ = [
    'GetNetworkLoadBalancerHealthResult',
    'AwaitableGetNetworkLoadBalancerHealthResult',
    'get_network_load_balancer_health',
    'get_network_load_balancer_health_output',
]

@pulumi.output_type
class GetNetworkLoadBalancerHealthResult:
    """
    A collection of values returned by getNetworkLoadBalancerHealth.
    """
    def __init__(__self__, critical_state_backend_set_names=None, id=None, network_load_balancer_id=None, status=None, total_backend_set_count=None, unknown_state_backend_set_names=None, warning_state_backend_set_names=None):
        if critical_state_backend_set_names and not isinstance(critical_state_backend_set_names, list):
            raise TypeError("Expected argument 'critical_state_backend_set_names' to be a list")
        pulumi.set(__self__, "critical_state_backend_set_names", critical_state_backend_set_names)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if network_load_balancer_id and not isinstance(network_load_balancer_id, str):
            raise TypeError("Expected argument 'network_load_balancer_id' to be a str")
        pulumi.set(__self__, "network_load_balancer_id", network_load_balancer_id)
        if status and not isinstance(status, str):
            raise TypeError("Expected argument 'status' to be a str")
        pulumi.set(__self__, "status", status)
        if total_backend_set_count and not isinstance(total_backend_set_count, int):
            raise TypeError("Expected argument 'total_backend_set_count' to be a int")
        pulumi.set(__self__, "total_backend_set_count", total_backend_set_count)
        if unknown_state_backend_set_names and not isinstance(unknown_state_backend_set_names, list):
            raise TypeError("Expected argument 'unknown_state_backend_set_names' to be a list")
        pulumi.set(__self__, "unknown_state_backend_set_names", unknown_state_backend_set_names)
        if warning_state_backend_set_names and not isinstance(warning_state_backend_set_names, list):
            raise TypeError("Expected argument 'warning_state_backend_set_names' to be a list")
        pulumi.set(__self__, "warning_state_backend_set_names", warning_state_backend_set_names)

    @_builtins.property
    @pulumi.getter(name="criticalStateBackendSetNames")
    def critical_state_backend_set_names(self) -> Sequence[_builtins.str]:
        """
        A list of backend sets that are currently in the `CRITICAL` health state. The list identifies each backend set by the user-friendly name you assigned when you created the backend set.  Example: `example_backend_set`
        """
        return pulumi.get(self, "critical_state_backend_set_names")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="networkLoadBalancerId")
    def network_load_balancer_id(self) -> _builtins.str:
        return pulumi.get(self, "network_load_balancer_id")

    @_builtins.property
    @pulumi.getter
    def status(self) -> _builtins.str:
        """
        The overall health status of the network load balancer.
        *  **OK:** All backend sets associated with the network load balancer return a status of `OK`.
        *  **WARNING:** At least one of the backend sets associated with the network load balancer returns a status of `WARNING`, no backend sets return a status of `CRITICAL`, and the network load balancer life cycle state is `ACTIVE`.
        *  **CRITICAL:** One or more of the backend sets associated with the network load balancer return a status of `CRITICAL`.
        *  **UNKNOWN:** If any one of the following conditions is true:
        *  The network load balancer life cycle state is not `ACTIVE`.
        *  No backend sets are defined for the network load balancer.
        *  More than half of the backend sets associated with the network load balancer return a status of `UNKNOWN`, none of the backend sets return a status of `WARNING` or `CRITICAL`, and the network load balancer life cycle state is `ACTIVE`.
        *  The system could not retrieve metrics for any reason.
        """
        return pulumi.get(self, "status")

    @_builtins.property
    @pulumi.getter(name="totalBackendSetCount")
    def total_backend_set_count(self) -> _builtins.int:
        """
        The total number of backend sets associated with this network load balancer.  Example: `4`
        """
        return pulumi.get(self, "total_backend_set_count")

    @_builtins.property
    @pulumi.getter(name="unknownStateBackendSetNames")
    def unknown_state_backend_set_names(self) -> Sequence[_builtins.str]:
        """
        A list of backend sets that are currently in the `UNKNOWN` health state. The list identifies each backend set by the user-friendly name you assigned when you created the backend set.  Example: `example_backend_set2`
        """
        return pulumi.get(self, "unknown_state_backend_set_names")

    @_builtins.property
    @pulumi.getter(name="warningStateBackendSetNames")
    def warning_state_backend_set_names(self) -> Sequence[_builtins.str]:
        """
        A list of backend sets that are currently in the `WARNING` health state. The list identifies each backend set by the user-friendly name you assigned when you created the backend set.  Example: `example_backend_set3`
        """
        return pulumi.get(self, "warning_state_backend_set_names")


class AwaitableGetNetworkLoadBalancerHealthResult(GetNetworkLoadBalancerHealthResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetNetworkLoadBalancerHealthResult(
            critical_state_backend_set_names=self.critical_state_backend_set_names,
            id=self.id,
            network_load_balancer_id=self.network_load_balancer_id,
            status=self.status,
            total_backend_set_count=self.total_backend_set_count,
            unknown_state_backend_set_names=self.unknown_state_backend_set_names,
            warning_state_backend_set_names=self.warning_state_backend_set_names)


def get_network_load_balancer_health(network_load_balancer_id: Optional[_builtins.str] = None,
                                     opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetNetworkLoadBalancerHealthResult:
    """
    This data source provides details about a specific Network Load Balancer Health resource in Oracle Cloud Infrastructure Network Load Balancer service.

    Retrieves the health status for the specified network load balancer.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_network_load_balancer_health = oci.NetworkLoadBalancer.get_network_load_balancer_health(network_load_balancer_id=test_network_load_balancer["id"])
    ```


    :param _builtins.str network_load_balancer_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
    """
    __args__ = dict()
    __args__['networkLoadBalancerId'] = network_load_balancer_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:NetworkLoadBalancer/getNetworkLoadBalancerHealth:getNetworkLoadBalancerHealth', __args__, opts=opts, typ=GetNetworkLoadBalancerHealthResult).value

    return AwaitableGetNetworkLoadBalancerHealthResult(
        critical_state_backend_set_names=pulumi.get(__ret__, 'critical_state_backend_set_names'),
        id=pulumi.get(__ret__, 'id'),
        network_load_balancer_id=pulumi.get(__ret__, 'network_load_balancer_id'),
        status=pulumi.get(__ret__, 'status'),
        total_backend_set_count=pulumi.get(__ret__, 'total_backend_set_count'),
        unknown_state_backend_set_names=pulumi.get(__ret__, 'unknown_state_backend_set_names'),
        warning_state_backend_set_names=pulumi.get(__ret__, 'warning_state_backend_set_names'))
def get_network_load_balancer_health_output(network_load_balancer_id: Optional[pulumi.Input[_builtins.str]] = None,
                                            opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetNetworkLoadBalancerHealthResult]:
    """
    This data source provides details about a specific Network Load Balancer Health resource in Oracle Cloud Infrastructure Network Load Balancer service.

    Retrieves the health status for the specified network load balancer.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_network_load_balancer_health = oci.NetworkLoadBalancer.get_network_load_balancer_health(network_load_balancer_id=test_network_load_balancer["id"])
    ```


    :param _builtins.str network_load_balancer_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
    """
    __args__ = dict()
    __args__['networkLoadBalancerId'] = network_load_balancer_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:NetworkLoadBalancer/getNetworkLoadBalancerHealth:getNetworkLoadBalancerHealth', __args__, opts=opts, typ=GetNetworkLoadBalancerHealthResult)
    return __ret__.apply(lambda __response__: GetNetworkLoadBalancerHealthResult(
        critical_state_backend_set_names=pulumi.get(__response__, 'critical_state_backend_set_names'),
        id=pulumi.get(__response__, 'id'),
        network_load_balancer_id=pulumi.get(__response__, 'network_load_balancer_id'),
        status=pulumi.get(__response__, 'status'),
        total_backend_set_count=pulumi.get(__response__, 'total_backend_set_count'),
        unknown_state_backend_set_names=pulumi.get(__response__, 'unknown_state_backend_set_names'),
        warning_state_backend_set_names=pulumi.get(__response__, 'warning_state_backend_set_names')))
