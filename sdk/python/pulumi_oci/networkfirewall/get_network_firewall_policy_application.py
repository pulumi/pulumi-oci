# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'GetNetworkFirewallPolicyApplicationResult',
    'AwaitableGetNetworkFirewallPolicyApplicationResult',
    'get_network_firewall_policy_application',
    'get_network_firewall_policy_application_output',
]

@pulumi.output_type
class GetNetworkFirewallPolicyApplicationResult:
    """
    A collection of values returned by getNetworkFirewallPolicyApplication.
    """
    def __init__(__self__, icmp_code=None, icmp_type=None, id=None, name=None, network_firewall_policy_id=None, parent_resource_id=None, type=None):
        if icmp_code and not isinstance(icmp_code, int):
            raise TypeError("Expected argument 'icmp_code' to be a int")
        pulumi.set(__self__, "icmp_code", icmp_code)
        if icmp_type and not isinstance(icmp_type, int):
            raise TypeError("Expected argument 'icmp_type' to be a int")
        pulumi.set(__self__, "icmp_type", icmp_type)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if network_firewall_policy_id and not isinstance(network_firewall_policy_id, str):
            raise TypeError("Expected argument 'network_firewall_policy_id' to be a str")
        pulumi.set(__self__, "network_firewall_policy_id", network_firewall_policy_id)
        if parent_resource_id and not isinstance(parent_resource_id, str):
            raise TypeError("Expected argument 'parent_resource_id' to be a str")
        pulumi.set(__self__, "parent_resource_id", parent_resource_id)
        if type and not isinstance(type, str):
            raise TypeError("Expected argument 'type' to be a str")
        pulumi.set(__self__, "type", type)

    @property
    @pulumi.getter(name="icmpCode")
    def icmp_code(self) -> int:
        """
        The value of the ICMP/ICMP_V6 message Code (subtype) field as defined by [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.1).
        """
        return pulumi.get(self, "icmp_code")

    @property
    @pulumi.getter(name="icmpType")
    def icmp_type(self) -> int:
        """
        The value of the ICMP/ICMP_V6 message Type field as defined by [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.1).
        """
        return pulumi.get(self, "icmp_type")

    @property
    @pulumi.getter
    def id(self) -> str:
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        Name of the application.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter(name="networkFirewallPolicyId")
    def network_firewall_policy_id(self) -> str:
        return pulumi.get(self, "network_firewall_policy_id")

    @property
    @pulumi.getter(name="parentResourceId")
    def parent_resource_id(self) -> str:
        """
        OCID of the Network Firewall Policy this application belongs to.
        """
        return pulumi.get(self, "parent_resource_id")

    @property
    @pulumi.getter
    def type(self) -> str:
        """
        Describes the type of application.
        """
        return pulumi.get(self, "type")


class AwaitableGetNetworkFirewallPolicyApplicationResult(GetNetworkFirewallPolicyApplicationResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetNetworkFirewallPolicyApplicationResult(
            icmp_code=self.icmp_code,
            icmp_type=self.icmp_type,
            id=self.id,
            name=self.name,
            network_firewall_policy_id=self.network_firewall_policy_id,
            parent_resource_id=self.parent_resource_id,
            type=self.type)


def get_network_firewall_policy_application(name: Optional[str] = None,
                                            network_firewall_policy_id: Optional[str] = None,
                                            opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetNetworkFirewallPolicyApplicationResult:
    """
    This data source provides details about a specific Network Firewall Policy Application resource in Oracle Cloud Infrastructure Network Firewall service.

    Get Application by the given name in the context of network firewall policy.


    :param str name: Name of the application.
    :param str network_firewall_policy_id: Unique Network Firewall Policy identifier
    """
    __args__ = dict()
    __args__['name'] = name
    __args__['networkFirewallPolicyId'] = network_firewall_policy_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:NetworkFirewall/getNetworkFirewallPolicyApplication:getNetworkFirewallPolicyApplication', __args__, opts=opts, typ=GetNetworkFirewallPolicyApplicationResult).value

    return AwaitableGetNetworkFirewallPolicyApplicationResult(
        icmp_code=pulumi.get(__ret__, 'icmp_code'),
        icmp_type=pulumi.get(__ret__, 'icmp_type'),
        id=pulumi.get(__ret__, 'id'),
        name=pulumi.get(__ret__, 'name'),
        network_firewall_policy_id=pulumi.get(__ret__, 'network_firewall_policy_id'),
        parent_resource_id=pulumi.get(__ret__, 'parent_resource_id'),
        type=pulumi.get(__ret__, 'type'))


@_utilities.lift_output_func(get_network_firewall_policy_application)
def get_network_firewall_policy_application_output(name: Optional[pulumi.Input[str]] = None,
                                                   network_firewall_policy_id: Optional[pulumi.Input[str]] = None,
                                                   opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetNetworkFirewallPolicyApplicationResult]:
    """
    This data source provides details about a specific Network Firewall Policy Application resource in Oracle Cloud Infrastructure Network Firewall service.

    Get Application by the given name in the context of network firewall policy.


    :param str name: Name of the application.
    :param str network_firewall_policy_id: Unique Network Firewall Policy identifier
    """
    ...