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
    'GetNetworkFirewallPolicyTunnelInspectionRulesResult',
    'AwaitableGetNetworkFirewallPolicyTunnelInspectionRulesResult',
    'get_network_firewall_policy_tunnel_inspection_rules',
    'get_network_firewall_policy_tunnel_inspection_rules_output',
]

@pulumi.output_type
class GetNetworkFirewallPolicyTunnelInspectionRulesResult:
    """
    A collection of values returned by getNetworkFirewallPolicyTunnelInspectionRules.
    """
    def __init__(__self__, display_name=None, filters=None, id=None, network_firewall_policy_id=None, tunnel_inspection_rule_priority_order=None, tunnel_inspection_rule_summary_collections=None):
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if network_firewall_policy_id and not isinstance(network_firewall_policy_id, str):
            raise TypeError("Expected argument 'network_firewall_policy_id' to be a str")
        pulumi.set(__self__, "network_firewall_policy_id", network_firewall_policy_id)
        if tunnel_inspection_rule_priority_order and not isinstance(tunnel_inspection_rule_priority_order, int):
            raise TypeError("Expected argument 'tunnel_inspection_rule_priority_order' to be a int")
        pulumi.set(__self__, "tunnel_inspection_rule_priority_order", tunnel_inspection_rule_priority_order)
        if tunnel_inspection_rule_summary_collections and not isinstance(tunnel_inspection_rule_summary_collections, list):
            raise TypeError("Expected argument 'tunnel_inspection_rule_summary_collections' to be a list")
        pulumi.set(__self__, "tunnel_inspection_rule_summary_collections", tunnel_inspection_rule_summary_collections)

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetNetworkFirewallPolicyTunnelInspectionRulesFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="networkFirewallPolicyId")
    def network_firewall_policy_id(self) -> _builtins.str:
        return pulumi.get(self, "network_firewall_policy_id")

    @_builtins.property
    @pulumi.getter(name="tunnelInspectionRulePriorityOrder")
    def tunnel_inspection_rule_priority_order(self) -> Optional[_builtins.int]:
        return pulumi.get(self, "tunnel_inspection_rule_priority_order")

    @_builtins.property
    @pulumi.getter(name="tunnelInspectionRuleSummaryCollections")
    def tunnel_inspection_rule_summary_collections(self) -> Sequence['outputs.GetNetworkFirewallPolicyTunnelInspectionRulesTunnelInspectionRuleSummaryCollectionResult']:
        """
        The list of tunnel_inspection_rule_summary_collection.
        """
        return pulumi.get(self, "tunnel_inspection_rule_summary_collections")


class AwaitableGetNetworkFirewallPolicyTunnelInspectionRulesResult(GetNetworkFirewallPolicyTunnelInspectionRulesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetNetworkFirewallPolicyTunnelInspectionRulesResult(
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            network_firewall_policy_id=self.network_firewall_policy_id,
            tunnel_inspection_rule_priority_order=self.tunnel_inspection_rule_priority_order,
            tunnel_inspection_rule_summary_collections=self.tunnel_inspection_rule_summary_collections)


def get_network_firewall_policy_tunnel_inspection_rules(display_name: Optional[_builtins.str] = None,
                                                        filters: Optional[Sequence[Union['GetNetworkFirewallPolicyTunnelInspectionRulesFilterArgs', 'GetNetworkFirewallPolicyTunnelInspectionRulesFilterArgsDict']]] = None,
                                                        network_firewall_policy_id: Optional[_builtins.str] = None,
                                                        tunnel_inspection_rule_priority_order: Optional[_builtins.int] = None,
                                                        opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetNetworkFirewallPolicyTunnelInspectionRulesResult:
    """
    This data source provides the list of Network Firewall Policy Tunnel Inspection Rules in Oracle Cloud Infrastructure Network Firewall service.

    Returns a list of tunnel inspection rules for the network firewall policy.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_network_firewall_policy_tunnel_inspection_rules = oci.NetworkFirewall.get_network_firewall_policy_tunnel_inspection_rules(network_firewall_policy_id=test_network_firewall_policy["id"],
        display_name=network_firewall_policy_tunnel_inspection_rule_display_name,
        tunnel_inspection_rule_priority_order=network_firewall_policy_tunnel_inspection_rule_tunnel_inspection_rule_priority_order)
    ```


    :param _builtins.str display_name: A filter to return only resources that match the entire display name given.
    :param _builtins.str network_firewall_policy_id: Unique Network Firewall Policy identifier
    :param _builtins.int tunnel_inspection_rule_priority_order: Unique priority order for Tunnel Inspection rules in the network firewall policy.
    """
    __args__ = dict()
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['networkFirewallPolicyId'] = network_firewall_policy_id
    __args__['tunnelInspectionRulePriorityOrder'] = tunnel_inspection_rule_priority_order
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:NetworkFirewall/getNetworkFirewallPolicyTunnelInspectionRules:getNetworkFirewallPolicyTunnelInspectionRules', __args__, opts=opts, typ=GetNetworkFirewallPolicyTunnelInspectionRulesResult).value

    return AwaitableGetNetworkFirewallPolicyTunnelInspectionRulesResult(
        display_name=pulumi.get(__ret__, 'display_name'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        network_firewall_policy_id=pulumi.get(__ret__, 'network_firewall_policy_id'),
        tunnel_inspection_rule_priority_order=pulumi.get(__ret__, 'tunnel_inspection_rule_priority_order'),
        tunnel_inspection_rule_summary_collections=pulumi.get(__ret__, 'tunnel_inspection_rule_summary_collections'))
def get_network_firewall_policy_tunnel_inspection_rules_output(display_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                               filters: Optional[pulumi.Input[Optional[Sequence[Union['GetNetworkFirewallPolicyTunnelInspectionRulesFilterArgs', 'GetNetworkFirewallPolicyTunnelInspectionRulesFilterArgsDict']]]]] = None,
                                                               network_firewall_policy_id: Optional[pulumi.Input[_builtins.str]] = None,
                                                               tunnel_inspection_rule_priority_order: Optional[pulumi.Input[Optional[_builtins.int]]] = None,
                                                               opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetNetworkFirewallPolicyTunnelInspectionRulesResult]:
    """
    This data source provides the list of Network Firewall Policy Tunnel Inspection Rules in Oracle Cloud Infrastructure Network Firewall service.

    Returns a list of tunnel inspection rules for the network firewall policy.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_network_firewall_policy_tunnel_inspection_rules = oci.NetworkFirewall.get_network_firewall_policy_tunnel_inspection_rules(network_firewall_policy_id=test_network_firewall_policy["id"],
        display_name=network_firewall_policy_tunnel_inspection_rule_display_name,
        tunnel_inspection_rule_priority_order=network_firewall_policy_tunnel_inspection_rule_tunnel_inspection_rule_priority_order)
    ```


    :param _builtins.str display_name: A filter to return only resources that match the entire display name given.
    :param _builtins.str network_firewall_policy_id: Unique Network Firewall Policy identifier
    :param _builtins.int tunnel_inspection_rule_priority_order: Unique priority order for Tunnel Inspection rules in the network firewall policy.
    """
    __args__ = dict()
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['networkFirewallPolicyId'] = network_firewall_policy_id
    __args__['tunnelInspectionRulePriorityOrder'] = tunnel_inspection_rule_priority_order
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:NetworkFirewall/getNetworkFirewallPolicyTunnelInspectionRules:getNetworkFirewallPolicyTunnelInspectionRules', __args__, opts=opts, typ=GetNetworkFirewallPolicyTunnelInspectionRulesResult)
    return __ret__.apply(lambda __response__: GetNetworkFirewallPolicyTunnelInspectionRulesResult(
        display_name=pulumi.get(__response__, 'display_name'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        network_firewall_policy_id=pulumi.get(__response__, 'network_firewall_policy_id'),
        tunnel_inspection_rule_priority_order=pulumi.get(__response__, 'tunnel_inspection_rule_priority_order'),
        tunnel_inspection_rule_summary_collections=pulumi.get(__response__, 'tunnel_inspection_rule_summary_collections')))
