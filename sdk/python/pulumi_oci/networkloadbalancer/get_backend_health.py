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

__all__ = [
    'GetBackendHealthResult',
    'AwaitableGetBackendHealthResult',
    'get_backend_health',
    'get_backend_health_output',
]

@pulumi.output_type
class GetBackendHealthResult:
    """
    A collection of values returned by getBackendHealth.
    """
    def __init__(__self__, backend_name=None, backend_set_name=None, health_check_results=None, id=None, network_load_balancer_id=None, status=None):
        if backend_name and not isinstance(backend_name, str):
            raise TypeError("Expected argument 'backend_name' to be a str")
        pulumi.set(__self__, "backend_name", backend_name)
        if backend_set_name and not isinstance(backend_set_name, str):
            raise TypeError("Expected argument 'backend_set_name' to be a str")
        pulumi.set(__self__, "backend_set_name", backend_set_name)
        if health_check_results and not isinstance(health_check_results, list):
            raise TypeError("Expected argument 'health_check_results' to be a list")
        pulumi.set(__self__, "health_check_results", health_check_results)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if network_load_balancer_id and not isinstance(network_load_balancer_id, str):
            raise TypeError("Expected argument 'network_load_balancer_id' to be a str")
        pulumi.set(__self__, "network_load_balancer_id", network_load_balancer_id)
        if status and not isinstance(status, str):
            raise TypeError("Expected argument 'status' to be a str")
        pulumi.set(__self__, "status", status)

    @_builtins.property
    @pulumi.getter(name="backendName")
    def backend_name(self) -> _builtins.str:
        return pulumi.get(self, "backend_name")

    @_builtins.property
    @pulumi.getter(name="backendSetName")
    def backend_set_name(self) -> _builtins.str:
        return pulumi.get(self, "backend_set_name")

    @_builtins.property
    @pulumi.getter(name="healthCheckResults")
    def health_check_results(self) -> Sequence['outputs.GetBackendHealthHealthCheckResultResult']:
        """
        A list of the most recent health check results returned for the specified backend server.
        """
        return pulumi.get(self, "health_check_results")

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
        The general health status of the specified backend server.
        *   **OK:**  All health check probes return `OK`
        *   **WARNING:** At least one of the health check probes does not return `OK`
        *   **CRITICAL:** None of the health check probes return `OK`. *
        *   **UNKNOWN:** One of the health checks probes return `UNKNOWN`,
        *   or the system is unable to retrieve metrics at this time.
        """
        return pulumi.get(self, "status")


class AwaitableGetBackendHealthResult(GetBackendHealthResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetBackendHealthResult(
            backend_name=self.backend_name,
            backend_set_name=self.backend_set_name,
            health_check_results=self.health_check_results,
            id=self.id,
            network_load_balancer_id=self.network_load_balancer_id,
            status=self.status)


def get_backend_health(backend_name: Optional[_builtins.str] = None,
                       backend_set_name: Optional[_builtins.str] = None,
                       network_load_balancer_id: Optional[_builtins.str] = None,
                       opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetBackendHealthResult:
    """
    This data source provides details about a specific Backend Health resource in Oracle Cloud Infrastructure Network Load Balancer service.

    Retrieves the current health status of the specified backend server.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_backend_health = oci.NetworkLoadBalancer.get_backend_health(backend_name=test_backend["name"],
        backend_set_name=test_backend_set["name"],
        network_load_balancer_id=test_network_load_balancer["id"])
    ```


    :param _builtins.str backend_name: The name of the backend server to retrieve health status for. If the backend was created with an explicitly specified name, that name should be used here. If the backend was created without explicitly specifying the name, but was created using ipAddress, this is specified as <ipAddress>:<port>. If the backend was created without explicitly specifying the name, but was created using targetId, this is specified as <targetId>:<port>.  Example: `10.0.0.3:8080` or `ocid1.privateip..oc1.<var>&lt;unique_ID&gt;</var>:8080`
    :param _builtins.str backend_set_name: The name of the backend set associated with the backend server for which to retrieve the health status.  Example: `example_backend_set`
    :param _builtins.str network_load_balancer_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
    """
    __args__ = dict()
    __args__['backendName'] = backend_name
    __args__['backendSetName'] = backend_set_name
    __args__['networkLoadBalancerId'] = network_load_balancer_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:NetworkLoadBalancer/getBackendHealth:getBackendHealth', __args__, opts=opts, typ=GetBackendHealthResult).value

    return AwaitableGetBackendHealthResult(
        backend_name=pulumi.get(__ret__, 'backend_name'),
        backend_set_name=pulumi.get(__ret__, 'backend_set_name'),
        health_check_results=pulumi.get(__ret__, 'health_check_results'),
        id=pulumi.get(__ret__, 'id'),
        network_load_balancer_id=pulumi.get(__ret__, 'network_load_balancer_id'),
        status=pulumi.get(__ret__, 'status'))
def get_backend_health_output(backend_name: Optional[pulumi.Input[_builtins.str]] = None,
                              backend_set_name: Optional[pulumi.Input[_builtins.str]] = None,
                              network_load_balancer_id: Optional[pulumi.Input[_builtins.str]] = None,
                              opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetBackendHealthResult]:
    """
    This data source provides details about a specific Backend Health resource in Oracle Cloud Infrastructure Network Load Balancer service.

    Retrieves the current health status of the specified backend server.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_backend_health = oci.NetworkLoadBalancer.get_backend_health(backend_name=test_backend["name"],
        backend_set_name=test_backend_set["name"],
        network_load_balancer_id=test_network_load_balancer["id"])
    ```


    :param _builtins.str backend_name: The name of the backend server to retrieve health status for. If the backend was created with an explicitly specified name, that name should be used here. If the backend was created without explicitly specifying the name, but was created using ipAddress, this is specified as <ipAddress>:<port>. If the backend was created without explicitly specifying the name, but was created using targetId, this is specified as <targetId>:<port>.  Example: `10.0.0.3:8080` or `ocid1.privateip..oc1.<var>&lt;unique_ID&gt;</var>:8080`
    :param _builtins.str backend_set_name: The name of the backend set associated with the backend server for which to retrieve the health status.  Example: `example_backend_set`
    :param _builtins.str network_load_balancer_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
    """
    __args__ = dict()
    __args__['backendName'] = backend_name
    __args__['backendSetName'] = backend_set_name
    __args__['networkLoadBalancerId'] = network_load_balancer_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:NetworkLoadBalancer/getBackendHealth:getBackendHealth', __args__, opts=opts, typ=GetBackendHealthResult)
    return __ret__.apply(lambda __response__: GetBackendHealthResult(
        backend_name=pulumi.get(__response__, 'backend_name'),
        backend_set_name=pulumi.get(__response__, 'backend_set_name'),
        health_check_results=pulumi.get(__response__, 'health_check_results'),
        id=pulumi.get(__response__, 'id'),
        network_load_balancer_id=pulumi.get(__response__, 'network_load_balancer_id'),
        status=pulumi.get(__response__, 'status')))
