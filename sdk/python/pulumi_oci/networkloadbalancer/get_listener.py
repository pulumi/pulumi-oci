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
    'GetListenerResult',
    'AwaitableGetListenerResult',
    'get_listener',
    'get_listener_output',
]

@pulumi.output_type
class GetListenerResult:
    """
    A collection of values returned by getListener.
    """
    def __init__(__self__, default_backend_set_name=None, id=None, ip_version=None, is_ppv2enabled=None, l3ip_idle_timeout=None, listener_name=None, name=None, network_load_balancer_id=None, port=None, protocol=None, tcp_idle_timeout=None, udp_idle_timeout=None):
        if default_backend_set_name and not isinstance(default_backend_set_name, str):
            raise TypeError("Expected argument 'default_backend_set_name' to be a str")
        pulumi.set(__self__, "default_backend_set_name", default_backend_set_name)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if ip_version and not isinstance(ip_version, str):
            raise TypeError("Expected argument 'ip_version' to be a str")
        pulumi.set(__self__, "ip_version", ip_version)
        if is_ppv2enabled and not isinstance(is_ppv2enabled, bool):
            raise TypeError("Expected argument 'is_ppv2enabled' to be a bool")
        pulumi.set(__self__, "is_ppv2enabled", is_ppv2enabled)
        if l3ip_idle_timeout and not isinstance(l3ip_idle_timeout, int):
            raise TypeError("Expected argument 'l3ip_idle_timeout' to be a int")
        pulumi.set(__self__, "l3ip_idle_timeout", l3ip_idle_timeout)
        if listener_name and not isinstance(listener_name, str):
            raise TypeError("Expected argument 'listener_name' to be a str")
        pulumi.set(__self__, "listener_name", listener_name)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if network_load_balancer_id and not isinstance(network_load_balancer_id, str):
            raise TypeError("Expected argument 'network_load_balancer_id' to be a str")
        pulumi.set(__self__, "network_load_balancer_id", network_load_balancer_id)
        if port and not isinstance(port, int):
            raise TypeError("Expected argument 'port' to be a int")
        pulumi.set(__self__, "port", port)
        if protocol and not isinstance(protocol, str):
            raise TypeError("Expected argument 'protocol' to be a str")
        pulumi.set(__self__, "protocol", protocol)
        if tcp_idle_timeout and not isinstance(tcp_idle_timeout, int):
            raise TypeError("Expected argument 'tcp_idle_timeout' to be a int")
        pulumi.set(__self__, "tcp_idle_timeout", tcp_idle_timeout)
        if udp_idle_timeout and not isinstance(udp_idle_timeout, int):
            raise TypeError("Expected argument 'udp_idle_timeout' to be a int")
        pulumi.set(__self__, "udp_idle_timeout", udp_idle_timeout)

    @_builtins.property
    @pulumi.getter(name="defaultBackendSetName")
    def default_backend_set_name(self) -> _builtins.str:
        """
        The name of the associated backend set.  Example: `example_backend_set`
        """
        return pulumi.get(self, "default_backend_set_name")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="ipVersion")
    def ip_version(self) -> _builtins.str:
        """
        IP version associated with the listener.
        """
        return pulumi.get(self, "ip_version")

    @_builtins.property
    @pulumi.getter(name="isPpv2enabled")
    def is_ppv2enabled(self) -> _builtins.bool:
        """
        Property to enable/disable PPv2 feature for this listener.
        """
        return pulumi.get(self, "is_ppv2enabled")

    @_builtins.property
    @pulumi.getter(name="l3ipIdleTimeout")
    def l3ip_idle_timeout(self) -> _builtins.int:
        """
        The duration for L3IP idle timeout in seconds. Example: `200`
        """
        return pulumi.get(self, "l3ip_idle_timeout")

    @_builtins.property
    @pulumi.getter(name="listenerName")
    def listener_name(self) -> _builtins.str:
        return pulumi.get(self, "listener_name")

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        """
        A friendly name for the listener. It must be unique and it cannot be changed.  Example: `example_listener`
        """
        return pulumi.get(self, "name")

    @_builtins.property
    @pulumi.getter(name="networkLoadBalancerId")
    def network_load_balancer_id(self) -> _builtins.str:
        return pulumi.get(self, "network_load_balancer_id")

    @_builtins.property
    @pulumi.getter
    def port(self) -> _builtins.int:
        """
        The communication port for the listener.  Example: `80`
        """
        return pulumi.get(self, "port")

    @_builtins.property
    @pulumi.getter
    def protocol(self) -> _builtins.str:
        """
        The protocol on which the listener accepts connection requests. For public network load balancers, ANY protocol refers to TCP/UDP with the wildcard port. For private network load balancers, ANY protocol refers to TCP/UDP/ICMP (note that ICMP requires isPreserveSourceDestination to be set to true). "ListNetworkLoadBalancersProtocols" API is deprecated and it will not return the updated values. Use the allowed values for the protocol instead.  Example: `TCP`
        """
        return pulumi.get(self, "protocol")

    @_builtins.property
    @pulumi.getter(name="tcpIdleTimeout")
    def tcp_idle_timeout(self) -> _builtins.int:
        """
        The duration for TCP idle timeout in seconds. Example: `300`
        """
        return pulumi.get(self, "tcp_idle_timeout")

    @_builtins.property
    @pulumi.getter(name="udpIdleTimeout")
    def udp_idle_timeout(self) -> _builtins.int:
        """
        The duration for UDP idle timeout in seconds. Example: `120`
        """
        return pulumi.get(self, "udp_idle_timeout")


class AwaitableGetListenerResult(GetListenerResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetListenerResult(
            default_backend_set_name=self.default_backend_set_name,
            id=self.id,
            ip_version=self.ip_version,
            is_ppv2enabled=self.is_ppv2enabled,
            l3ip_idle_timeout=self.l3ip_idle_timeout,
            listener_name=self.listener_name,
            name=self.name,
            network_load_balancer_id=self.network_load_balancer_id,
            port=self.port,
            protocol=self.protocol,
            tcp_idle_timeout=self.tcp_idle_timeout,
            udp_idle_timeout=self.udp_idle_timeout)


def get_listener(listener_name: Optional[_builtins.str] = None,
                 network_load_balancer_id: Optional[_builtins.str] = None,
                 opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetListenerResult:
    """
    This data source provides details about a specific Listener resource in Oracle Cloud Infrastructure Network Load Balancer service.

    Retrieves listener properties associated with a given network load balancer and listener name.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_listener = oci.NetworkLoadBalancer.get_listener(listener_name=test_listener_oci_network_load_balancer_listener["name"],
        network_load_balancer_id=test_network_load_balancer["id"])
    ```


    :param _builtins.str listener_name: The name of the listener to get.  Example: `example_listener`
    :param _builtins.str network_load_balancer_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
    """
    __args__ = dict()
    __args__['listenerName'] = listener_name
    __args__['networkLoadBalancerId'] = network_load_balancer_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:NetworkLoadBalancer/getListener:getListener', __args__, opts=opts, typ=GetListenerResult).value

    return AwaitableGetListenerResult(
        default_backend_set_name=pulumi.get(__ret__, 'default_backend_set_name'),
        id=pulumi.get(__ret__, 'id'),
        ip_version=pulumi.get(__ret__, 'ip_version'),
        is_ppv2enabled=pulumi.get(__ret__, 'is_ppv2enabled'),
        l3ip_idle_timeout=pulumi.get(__ret__, 'l3ip_idle_timeout'),
        listener_name=pulumi.get(__ret__, 'listener_name'),
        name=pulumi.get(__ret__, 'name'),
        network_load_balancer_id=pulumi.get(__ret__, 'network_load_balancer_id'),
        port=pulumi.get(__ret__, 'port'),
        protocol=pulumi.get(__ret__, 'protocol'),
        tcp_idle_timeout=pulumi.get(__ret__, 'tcp_idle_timeout'),
        udp_idle_timeout=pulumi.get(__ret__, 'udp_idle_timeout'))
def get_listener_output(listener_name: Optional[pulumi.Input[_builtins.str]] = None,
                        network_load_balancer_id: Optional[pulumi.Input[_builtins.str]] = None,
                        opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetListenerResult]:
    """
    This data source provides details about a specific Listener resource in Oracle Cloud Infrastructure Network Load Balancer service.

    Retrieves listener properties associated with a given network load balancer and listener name.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_listener = oci.NetworkLoadBalancer.get_listener(listener_name=test_listener_oci_network_load_balancer_listener["name"],
        network_load_balancer_id=test_network_load_balancer["id"])
    ```


    :param _builtins.str listener_name: The name of the listener to get.  Example: `example_listener`
    :param _builtins.str network_load_balancer_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
    """
    __args__ = dict()
    __args__['listenerName'] = listener_name
    __args__['networkLoadBalancerId'] = network_load_balancer_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:NetworkLoadBalancer/getListener:getListener', __args__, opts=opts, typ=GetListenerResult)
    return __ret__.apply(lambda __response__: GetListenerResult(
        default_backend_set_name=pulumi.get(__response__, 'default_backend_set_name'),
        id=pulumi.get(__response__, 'id'),
        ip_version=pulumi.get(__response__, 'ip_version'),
        is_ppv2enabled=pulumi.get(__response__, 'is_ppv2enabled'),
        l3ip_idle_timeout=pulumi.get(__response__, 'l3ip_idle_timeout'),
        listener_name=pulumi.get(__response__, 'listener_name'),
        name=pulumi.get(__response__, 'name'),
        network_load_balancer_id=pulumi.get(__response__, 'network_load_balancer_id'),
        port=pulumi.get(__response__, 'port'),
        protocol=pulumi.get(__response__, 'protocol'),
        tcp_idle_timeout=pulumi.get(__response__, 'tcp_idle_timeout'),
        udp_idle_timeout=pulumi.get(__response__, 'udp_idle_timeout')))
