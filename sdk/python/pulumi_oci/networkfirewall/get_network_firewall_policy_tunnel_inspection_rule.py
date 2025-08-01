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
    'GetNetworkFirewallPolicyTunnelInspectionRuleResult',
    'AwaitableGetNetworkFirewallPolicyTunnelInspectionRuleResult',
    'get_network_firewall_policy_tunnel_inspection_rule',
    'get_network_firewall_policy_tunnel_inspection_rule_output',
]

@pulumi.output_type
class GetNetworkFirewallPolicyTunnelInspectionRuleResult:
    """
    A collection of values returned by getNetworkFirewallPolicyTunnelInspectionRule.
    """
    def __init__(__self__, action=None, conditions=None, id=None, name=None, network_firewall_policy_id=None, parent_resource_id=None, positions=None, priority_order=None, profiles=None, protocol=None, tunnel_inspection_rule_name=None):
        if action and not isinstance(action, str):
            raise TypeError("Expected argument 'action' to be a str")
        pulumi.set(__self__, "action", action)
        if conditions and not isinstance(conditions, list):
            raise TypeError("Expected argument 'conditions' to be a list")
        pulumi.set(__self__, "conditions", conditions)
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
        if positions and not isinstance(positions, list):
            raise TypeError("Expected argument 'positions' to be a list")
        pulumi.set(__self__, "positions", positions)
        if priority_order and not isinstance(priority_order, str):
            raise TypeError("Expected argument 'priority_order' to be a str")
        pulumi.set(__self__, "priority_order", priority_order)
        if profiles and not isinstance(profiles, list):
            raise TypeError("Expected argument 'profiles' to be a list")
        pulumi.set(__self__, "profiles", profiles)
        if protocol and not isinstance(protocol, str):
            raise TypeError("Expected argument 'protocol' to be a str")
        pulumi.set(__self__, "protocol", protocol)
        if tunnel_inspection_rule_name and not isinstance(tunnel_inspection_rule_name, str):
            raise TypeError("Expected argument 'tunnel_inspection_rule_name' to be a str")
        pulumi.set(__self__, "tunnel_inspection_rule_name", tunnel_inspection_rule_name)

    @_builtins.property
    @pulumi.getter
    def action(self) -> _builtins.str:
        """
        Types of Inspect Action on the Traffic flow.
        * INSPECT - Inspect the traffic.
        * INSPECT_AND_CAPTURE_LOG - Inspect and capture logs for the traffic.
        """
        return pulumi.get(self, "action")

    @_builtins.property
    @pulumi.getter
    def conditions(self) -> Sequence['outputs.GetNetworkFirewallPolicyTunnelInspectionRuleConditionResult']:
        """
        Criteria to evaluate against incoming network traffic. A match occurs when at least one item in the array associated with each specified property corresponds with the relevant aspect of the traffic.
        """
        return pulumi.get(self, "conditions")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        """
        Name for the Tunnel Inspection Rule, must be unique within the policy.
        """
        return pulumi.get(self, "name")

    @_builtins.property
    @pulumi.getter(name="networkFirewallPolicyId")
    def network_firewall_policy_id(self) -> _builtins.str:
        return pulumi.get(self, "network_firewall_policy_id")

    @_builtins.property
    @pulumi.getter(name="parentResourceId")
    def parent_resource_id(self) -> _builtins.str:
        """
        OCID of the Network Firewall Policy this Tunnel Inspection Rule belongs to.
        """
        return pulumi.get(self, "parent_resource_id")

    @_builtins.property
    @pulumi.getter
    def positions(self) -> Sequence['outputs.GetNetworkFirewallPolicyTunnelInspectionRulePositionResult']:
        """
        An object which defines the position of the rule.
        """
        return pulumi.get(self, "positions")

    @_builtins.property
    @pulumi.getter(name="priorityOrder")
    def priority_order(self) -> _builtins.str:
        """
        The priority order in which this rule should be evaluated
        """
        return pulumi.get(self, "priority_order")

    @_builtins.property
    @pulumi.getter
    def profiles(self) -> Sequence['outputs.GetNetworkFirewallPolicyTunnelInspectionRuleProfileResult']:
        """
        Vxlan Inspect profile used in Vxlan Tunnel Inspection Rules.
        """
        return pulumi.get(self, "profiles")

    @_builtins.property
    @pulumi.getter
    def protocol(self) -> _builtins.str:
        """
        Types of Tunnel Inspection Protocol to be applied on the traffic.
        * VXLAN - VXLAN Tunnel Inspection Protocol will be applied on the traffic.
        """
        return pulumi.get(self, "protocol")

    @_builtins.property
    @pulumi.getter(name="tunnelInspectionRuleName")
    def tunnel_inspection_rule_name(self) -> _builtins.str:
        return pulumi.get(self, "tunnel_inspection_rule_name")


class AwaitableGetNetworkFirewallPolicyTunnelInspectionRuleResult(GetNetworkFirewallPolicyTunnelInspectionRuleResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetNetworkFirewallPolicyTunnelInspectionRuleResult(
            action=self.action,
            conditions=self.conditions,
            id=self.id,
            name=self.name,
            network_firewall_policy_id=self.network_firewall_policy_id,
            parent_resource_id=self.parent_resource_id,
            positions=self.positions,
            priority_order=self.priority_order,
            profiles=self.profiles,
            protocol=self.protocol,
            tunnel_inspection_rule_name=self.tunnel_inspection_rule_name)


def get_network_firewall_policy_tunnel_inspection_rule(network_firewall_policy_id: Optional[_builtins.str] = None,
                                                       tunnel_inspection_rule_name: Optional[_builtins.str] = None,
                                                       opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetNetworkFirewallPolicyTunnelInspectionRuleResult:
    """
    This data source provides details about a specific Network Firewall Policy Tunnel Inspection Rule resource in Oracle Cloud Infrastructure Network Firewall service.

    Get tunnel inspection rule by the given name in the context of network firewall policy.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_network_firewall_policy_tunnel_inspection_rule = oci.NetworkFirewall.get_network_firewall_policy_tunnel_inspection_rule(network_firewall_policy_id=test_network_firewall_policy["id"],
        tunnel_inspection_rule_name=test_rule["name"])
    ```


    :param _builtins.str network_firewall_policy_id: Unique Network Firewall Policy identifier
    :param _builtins.str tunnel_inspection_rule_name: Unique identifier for Tunnel Inspection Rules in the network firewall policy.
    """
    __args__ = dict()
    __args__['networkFirewallPolicyId'] = network_firewall_policy_id
    __args__['tunnelInspectionRuleName'] = tunnel_inspection_rule_name
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:NetworkFirewall/getNetworkFirewallPolicyTunnelInspectionRule:getNetworkFirewallPolicyTunnelInspectionRule', __args__, opts=opts, typ=GetNetworkFirewallPolicyTunnelInspectionRuleResult).value

    return AwaitableGetNetworkFirewallPolicyTunnelInspectionRuleResult(
        action=pulumi.get(__ret__, 'action'),
        conditions=pulumi.get(__ret__, 'conditions'),
        id=pulumi.get(__ret__, 'id'),
        name=pulumi.get(__ret__, 'name'),
        network_firewall_policy_id=pulumi.get(__ret__, 'network_firewall_policy_id'),
        parent_resource_id=pulumi.get(__ret__, 'parent_resource_id'),
        positions=pulumi.get(__ret__, 'positions'),
        priority_order=pulumi.get(__ret__, 'priority_order'),
        profiles=pulumi.get(__ret__, 'profiles'),
        protocol=pulumi.get(__ret__, 'protocol'),
        tunnel_inspection_rule_name=pulumi.get(__ret__, 'tunnel_inspection_rule_name'))
def get_network_firewall_policy_tunnel_inspection_rule_output(network_firewall_policy_id: Optional[pulumi.Input[_builtins.str]] = None,
                                                              tunnel_inspection_rule_name: Optional[pulumi.Input[_builtins.str]] = None,
                                                              opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetNetworkFirewallPolicyTunnelInspectionRuleResult]:
    """
    This data source provides details about a specific Network Firewall Policy Tunnel Inspection Rule resource in Oracle Cloud Infrastructure Network Firewall service.

    Get tunnel inspection rule by the given name in the context of network firewall policy.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_network_firewall_policy_tunnel_inspection_rule = oci.NetworkFirewall.get_network_firewall_policy_tunnel_inspection_rule(network_firewall_policy_id=test_network_firewall_policy["id"],
        tunnel_inspection_rule_name=test_rule["name"])
    ```


    :param _builtins.str network_firewall_policy_id: Unique Network Firewall Policy identifier
    :param _builtins.str tunnel_inspection_rule_name: Unique identifier for Tunnel Inspection Rules in the network firewall policy.
    """
    __args__ = dict()
    __args__['networkFirewallPolicyId'] = network_firewall_policy_id
    __args__['tunnelInspectionRuleName'] = tunnel_inspection_rule_name
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:NetworkFirewall/getNetworkFirewallPolicyTunnelInspectionRule:getNetworkFirewallPolicyTunnelInspectionRule', __args__, opts=opts, typ=GetNetworkFirewallPolicyTunnelInspectionRuleResult)
    return __ret__.apply(lambda __response__: GetNetworkFirewallPolicyTunnelInspectionRuleResult(
        action=pulumi.get(__response__, 'action'),
        conditions=pulumi.get(__response__, 'conditions'),
        id=pulumi.get(__response__, 'id'),
        name=pulumi.get(__response__, 'name'),
        network_firewall_policy_id=pulumi.get(__response__, 'network_firewall_policy_id'),
        parent_resource_id=pulumi.get(__response__, 'parent_resource_id'),
        positions=pulumi.get(__response__, 'positions'),
        priority_order=pulumi.get(__response__, 'priority_order'),
        profiles=pulumi.get(__response__, 'profiles'),
        protocol=pulumi.get(__response__, 'protocol'),
        tunnel_inspection_rule_name=pulumi.get(__response__, 'tunnel_inspection_rule_name')))
