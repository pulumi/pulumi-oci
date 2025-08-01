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

__all__ = ['NetworkFirewallPolicyTunnelInspectionRuleArgs', 'NetworkFirewallPolicyTunnelInspectionRule']

@pulumi.input_type
class NetworkFirewallPolicyTunnelInspectionRuleArgs:
    def __init__(__self__, *,
                 condition: pulumi.Input['NetworkFirewallPolicyTunnelInspectionRuleConditionArgs'],
                 network_firewall_policy_id: pulumi.Input[_builtins.str],
                 protocol: pulumi.Input[_builtins.str],
                 action: Optional[pulumi.Input[_builtins.str]] = None,
                 name: Optional[pulumi.Input[_builtins.str]] = None,
                 position: Optional[pulumi.Input['NetworkFirewallPolicyTunnelInspectionRulePositionArgs']] = None,
                 profile: Optional[pulumi.Input['NetworkFirewallPolicyTunnelInspectionRuleProfileArgs']] = None):
        """
        The set of arguments for constructing a NetworkFirewallPolicyTunnelInspectionRule resource.
        :param pulumi.Input['NetworkFirewallPolicyTunnelInspectionRuleConditionArgs'] condition: (Updatable) Criteria to evaluate against incoming network traffic. A match occurs when at least one item in the array associated with each specified property corresponds with the relevant aspect of the traffic.
        :param pulumi.Input[_builtins.str] network_firewall_policy_id: Unique Network Firewall Policy identifier
        :param pulumi.Input[_builtins.str] protocol: (Updatable) Types of Tunnel Inspection Protocol to be applied on the traffic.
               * VXLAN - VXLAN Tunnel Inspection Protocol will be applied on the traffic.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[_builtins.str] action: (Updatable) Types of Inspect Action on the traffic flow.
               * INSPECT - Inspect the traffic.
               * INSPECT_AND_CAPTURE_LOG - Inspect and capture logs for the traffic.
        :param pulumi.Input[_builtins.str] name: Name for the Tunnel Inspection Rule, must be unique within the policy.
        :param pulumi.Input['NetworkFirewallPolicyTunnelInspectionRulePositionArgs'] position: (Updatable) An object which defines the position of the rule.
        :param pulumi.Input['NetworkFirewallPolicyTunnelInspectionRuleProfileArgs'] profile: (Updatable) Vxlan Inspect profile used in Vxlan Tunnel Inspection Rules.
        """
        pulumi.set(__self__, "condition", condition)
        pulumi.set(__self__, "network_firewall_policy_id", network_firewall_policy_id)
        pulumi.set(__self__, "protocol", protocol)
        if action is not None:
            pulumi.set(__self__, "action", action)
        if name is not None:
            pulumi.set(__self__, "name", name)
        if position is not None:
            pulumi.set(__self__, "position", position)
        if profile is not None:
            pulumi.set(__self__, "profile", profile)

    @_builtins.property
    @pulumi.getter
    def condition(self) -> pulumi.Input['NetworkFirewallPolicyTunnelInspectionRuleConditionArgs']:
        """
        (Updatable) Criteria to evaluate against incoming network traffic. A match occurs when at least one item in the array associated with each specified property corresponds with the relevant aspect of the traffic.
        """
        return pulumi.get(self, "condition")

    @condition.setter
    def condition(self, value: pulumi.Input['NetworkFirewallPolicyTunnelInspectionRuleConditionArgs']):
        pulumi.set(self, "condition", value)

    @_builtins.property
    @pulumi.getter(name="networkFirewallPolicyId")
    def network_firewall_policy_id(self) -> pulumi.Input[_builtins.str]:
        """
        Unique Network Firewall Policy identifier
        """
        return pulumi.get(self, "network_firewall_policy_id")

    @network_firewall_policy_id.setter
    def network_firewall_policy_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "network_firewall_policy_id", value)

    @_builtins.property
    @pulumi.getter
    def protocol(self) -> pulumi.Input[_builtins.str]:
        """
        (Updatable) Types of Tunnel Inspection Protocol to be applied on the traffic.
        * VXLAN - VXLAN Tunnel Inspection Protocol will be applied on the traffic.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "protocol")

    @protocol.setter
    def protocol(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "protocol", value)

    @_builtins.property
    @pulumi.getter
    def action(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) Types of Inspect Action on the traffic flow.
        * INSPECT - Inspect the traffic.
        * INSPECT_AND_CAPTURE_LOG - Inspect and capture logs for the traffic.
        """
        return pulumi.get(self, "action")

    @action.setter
    def action(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "action", value)

    @_builtins.property
    @pulumi.getter
    def name(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        Name for the Tunnel Inspection Rule, must be unique within the policy.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "name", value)

    @_builtins.property
    @pulumi.getter
    def position(self) -> Optional[pulumi.Input['NetworkFirewallPolicyTunnelInspectionRulePositionArgs']]:
        """
        (Updatable) An object which defines the position of the rule.
        """
        return pulumi.get(self, "position")

    @position.setter
    def position(self, value: Optional[pulumi.Input['NetworkFirewallPolicyTunnelInspectionRulePositionArgs']]):
        pulumi.set(self, "position", value)

    @_builtins.property
    @pulumi.getter
    def profile(self) -> Optional[pulumi.Input['NetworkFirewallPolicyTunnelInspectionRuleProfileArgs']]:
        """
        (Updatable) Vxlan Inspect profile used in Vxlan Tunnel Inspection Rules.
        """
        return pulumi.get(self, "profile")

    @profile.setter
    def profile(self, value: Optional[pulumi.Input['NetworkFirewallPolicyTunnelInspectionRuleProfileArgs']]):
        pulumi.set(self, "profile", value)


@pulumi.input_type
class _NetworkFirewallPolicyTunnelInspectionRuleState:
    def __init__(__self__, *,
                 action: Optional[pulumi.Input[_builtins.str]] = None,
                 condition: Optional[pulumi.Input['NetworkFirewallPolicyTunnelInspectionRuleConditionArgs']] = None,
                 name: Optional[pulumi.Input[_builtins.str]] = None,
                 network_firewall_policy_id: Optional[pulumi.Input[_builtins.str]] = None,
                 parent_resource_id: Optional[pulumi.Input[_builtins.str]] = None,
                 position: Optional[pulumi.Input['NetworkFirewallPolicyTunnelInspectionRulePositionArgs']] = None,
                 priority_order: Optional[pulumi.Input[_builtins.str]] = None,
                 profile: Optional[pulumi.Input['NetworkFirewallPolicyTunnelInspectionRuleProfileArgs']] = None,
                 protocol: Optional[pulumi.Input[_builtins.str]] = None):
        """
        Input properties used for looking up and filtering NetworkFirewallPolicyTunnelInspectionRule resources.
        :param pulumi.Input[_builtins.str] action: (Updatable) Types of Inspect Action on the traffic flow.
               * INSPECT - Inspect the traffic.
               * INSPECT_AND_CAPTURE_LOG - Inspect and capture logs for the traffic.
        :param pulumi.Input['NetworkFirewallPolicyTunnelInspectionRuleConditionArgs'] condition: (Updatable) Criteria to evaluate against incoming network traffic. A match occurs when at least one item in the array associated with each specified property corresponds with the relevant aspect of the traffic.
        :param pulumi.Input[_builtins.str] name: Name for the Tunnel Inspection Rule, must be unique within the policy.
        :param pulumi.Input[_builtins.str] network_firewall_policy_id: Unique Network Firewall Policy identifier
        :param pulumi.Input[_builtins.str] parent_resource_id: OCID of the Network Firewall Policy this Tunnel Inspection Rule belongs to.
        :param pulumi.Input['NetworkFirewallPolicyTunnelInspectionRulePositionArgs'] position: (Updatable) An object which defines the position of the rule.
        :param pulumi.Input[_builtins.str] priority_order: The priority order in which this rule should be evaluated
        :param pulumi.Input['NetworkFirewallPolicyTunnelInspectionRuleProfileArgs'] profile: (Updatable) Vxlan Inspect profile used in Vxlan Tunnel Inspection Rules.
        :param pulumi.Input[_builtins.str] protocol: (Updatable) Types of Tunnel Inspection Protocol to be applied on the traffic.
               * VXLAN - VXLAN Tunnel Inspection Protocol will be applied on the traffic.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        if action is not None:
            pulumi.set(__self__, "action", action)
        if condition is not None:
            pulumi.set(__self__, "condition", condition)
        if name is not None:
            pulumi.set(__self__, "name", name)
        if network_firewall_policy_id is not None:
            pulumi.set(__self__, "network_firewall_policy_id", network_firewall_policy_id)
        if parent_resource_id is not None:
            pulumi.set(__self__, "parent_resource_id", parent_resource_id)
        if position is not None:
            pulumi.set(__self__, "position", position)
        if priority_order is not None:
            pulumi.set(__self__, "priority_order", priority_order)
        if profile is not None:
            pulumi.set(__self__, "profile", profile)
        if protocol is not None:
            pulumi.set(__self__, "protocol", protocol)

    @_builtins.property
    @pulumi.getter
    def action(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) Types of Inspect Action on the traffic flow.
        * INSPECT - Inspect the traffic.
        * INSPECT_AND_CAPTURE_LOG - Inspect and capture logs for the traffic.
        """
        return pulumi.get(self, "action")

    @action.setter
    def action(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "action", value)

    @_builtins.property
    @pulumi.getter
    def condition(self) -> Optional[pulumi.Input['NetworkFirewallPolicyTunnelInspectionRuleConditionArgs']]:
        """
        (Updatable) Criteria to evaluate against incoming network traffic. A match occurs when at least one item in the array associated with each specified property corresponds with the relevant aspect of the traffic.
        """
        return pulumi.get(self, "condition")

    @condition.setter
    def condition(self, value: Optional[pulumi.Input['NetworkFirewallPolicyTunnelInspectionRuleConditionArgs']]):
        pulumi.set(self, "condition", value)

    @_builtins.property
    @pulumi.getter
    def name(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        Name for the Tunnel Inspection Rule, must be unique within the policy.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "name", value)

    @_builtins.property
    @pulumi.getter(name="networkFirewallPolicyId")
    def network_firewall_policy_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        Unique Network Firewall Policy identifier
        """
        return pulumi.get(self, "network_firewall_policy_id")

    @network_firewall_policy_id.setter
    def network_firewall_policy_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "network_firewall_policy_id", value)

    @_builtins.property
    @pulumi.getter(name="parentResourceId")
    def parent_resource_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        OCID of the Network Firewall Policy this Tunnel Inspection Rule belongs to.
        """
        return pulumi.get(self, "parent_resource_id")

    @parent_resource_id.setter
    def parent_resource_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "parent_resource_id", value)

    @_builtins.property
    @pulumi.getter
    def position(self) -> Optional[pulumi.Input['NetworkFirewallPolicyTunnelInspectionRulePositionArgs']]:
        """
        (Updatable) An object which defines the position of the rule.
        """
        return pulumi.get(self, "position")

    @position.setter
    def position(self, value: Optional[pulumi.Input['NetworkFirewallPolicyTunnelInspectionRulePositionArgs']]):
        pulumi.set(self, "position", value)

    @_builtins.property
    @pulumi.getter(name="priorityOrder")
    def priority_order(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The priority order in which this rule should be evaluated
        """
        return pulumi.get(self, "priority_order")

    @priority_order.setter
    def priority_order(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "priority_order", value)

    @_builtins.property
    @pulumi.getter
    def profile(self) -> Optional[pulumi.Input['NetworkFirewallPolicyTunnelInspectionRuleProfileArgs']]:
        """
        (Updatable) Vxlan Inspect profile used in Vxlan Tunnel Inspection Rules.
        """
        return pulumi.get(self, "profile")

    @profile.setter
    def profile(self, value: Optional[pulumi.Input['NetworkFirewallPolicyTunnelInspectionRuleProfileArgs']]):
        pulumi.set(self, "profile", value)

    @_builtins.property
    @pulumi.getter
    def protocol(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) Types of Tunnel Inspection Protocol to be applied on the traffic.
        * VXLAN - VXLAN Tunnel Inspection Protocol will be applied on the traffic.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "protocol")

    @protocol.setter
    def protocol(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "protocol", value)


@pulumi.type_token("oci:NetworkFirewall/networkFirewallPolicyTunnelInspectionRule:NetworkFirewallPolicyTunnelInspectionRule")
class NetworkFirewallPolicyTunnelInspectionRule(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 action: Optional[pulumi.Input[_builtins.str]] = None,
                 condition: Optional[pulumi.Input[Union['NetworkFirewallPolicyTunnelInspectionRuleConditionArgs', 'NetworkFirewallPolicyTunnelInspectionRuleConditionArgsDict']]] = None,
                 name: Optional[pulumi.Input[_builtins.str]] = None,
                 network_firewall_policy_id: Optional[pulumi.Input[_builtins.str]] = None,
                 position: Optional[pulumi.Input[Union['NetworkFirewallPolicyTunnelInspectionRulePositionArgs', 'NetworkFirewallPolicyTunnelInspectionRulePositionArgsDict']]] = None,
                 profile: Optional[pulumi.Input[Union['NetworkFirewallPolicyTunnelInspectionRuleProfileArgs', 'NetworkFirewallPolicyTunnelInspectionRuleProfileArgsDict']]] = None,
                 protocol: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        """
        This resource provides the Network Firewall Policy Tunnel Inspection Rule resource in Oracle Cloud Infrastructure Network Firewall service.

        Creates a new tunnel inspection rule for the network firewall policy.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_network_firewall_policy_tunnel_inspection_rule = oci.networkfirewall.NetworkFirewallPolicyTunnelInspectionRule("test_network_firewall_policy_tunnel_inspection_rule",
            condition={
                "destination_addresses": network_firewall_policy_tunnel_inspection_rule_condition_destination_address,
                "source_addresses": network_firewall_policy_tunnel_inspection_rule_condition_source_address,
            },
            name=network_firewall_policy_tunnel_inspection_rule_name,
            network_firewall_policy_id=test_network_firewall_policy["id"],
            protocol=network_firewall_policy_tunnel_inspection_rule_protocol,
            action=network_firewall_policy_tunnel_inspection_rule_action,
            position={
                "after_rule": network_firewall_policy_tunnel_inspection_rule_position_after_rule,
                "before_rule": network_firewall_policy_tunnel_inspection_rule_position_before_rule,
            },
            profile={
                "must_return_traffic_to_source": network_firewall_policy_tunnel_inspection_rule_profile_must_return_traffic_to_source,
            })
        ```

        ## Import

        NetworkFirewallPolicyTunnelInspectionRules can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:NetworkFirewall/networkFirewallPolicyTunnelInspectionRule:NetworkFirewallPolicyTunnelInspectionRule test_network_firewall_policy_tunnel_inspection_rule "networkFirewallPolicies/{networkFirewallPolicyId}/tunnelInspectionRules/{tunnelInspectionRuleName}"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] action: (Updatable) Types of Inspect Action on the traffic flow.
               * INSPECT - Inspect the traffic.
               * INSPECT_AND_CAPTURE_LOG - Inspect and capture logs for the traffic.
        :param pulumi.Input[Union['NetworkFirewallPolicyTunnelInspectionRuleConditionArgs', 'NetworkFirewallPolicyTunnelInspectionRuleConditionArgsDict']] condition: (Updatable) Criteria to evaluate against incoming network traffic. A match occurs when at least one item in the array associated with each specified property corresponds with the relevant aspect of the traffic.
        :param pulumi.Input[_builtins.str] name: Name for the Tunnel Inspection Rule, must be unique within the policy.
        :param pulumi.Input[_builtins.str] network_firewall_policy_id: Unique Network Firewall Policy identifier
        :param pulumi.Input[Union['NetworkFirewallPolicyTunnelInspectionRulePositionArgs', 'NetworkFirewallPolicyTunnelInspectionRulePositionArgsDict']] position: (Updatable) An object which defines the position of the rule.
        :param pulumi.Input[Union['NetworkFirewallPolicyTunnelInspectionRuleProfileArgs', 'NetworkFirewallPolicyTunnelInspectionRuleProfileArgsDict']] profile: (Updatable) Vxlan Inspect profile used in Vxlan Tunnel Inspection Rules.
        :param pulumi.Input[_builtins.str] protocol: (Updatable) Types of Tunnel Inspection Protocol to be applied on the traffic.
               * VXLAN - VXLAN Tunnel Inspection Protocol will be applied on the traffic.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: NetworkFirewallPolicyTunnelInspectionRuleArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Network Firewall Policy Tunnel Inspection Rule resource in Oracle Cloud Infrastructure Network Firewall service.

        Creates a new tunnel inspection rule for the network firewall policy.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_network_firewall_policy_tunnel_inspection_rule = oci.networkfirewall.NetworkFirewallPolicyTunnelInspectionRule("test_network_firewall_policy_tunnel_inspection_rule",
            condition={
                "destination_addresses": network_firewall_policy_tunnel_inspection_rule_condition_destination_address,
                "source_addresses": network_firewall_policy_tunnel_inspection_rule_condition_source_address,
            },
            name=network_firewall_policy_tunnel_inspection_rule_name,
            network_firewall_policy_id=test_network_firewall_policy["id"],
            protocol=network_firewall_policy_tunnel_inspection_rule_protocol,
            action=network_firewall_policy_tunnel_inspection_rule_action,
            position={
                "after_rule": network_firewall_policy_tunnel_inspection_rule_position_after_rule,
                "before_rule": network_firewall_policy_tunnel_inspection_rule_position_before_rule,
            },
            profile={
                "must_return_traffic_to_source": network_firewall_policy_tunnel_inspection_rule_profile_must_return_traffic_to_source,
            })
        ```

        ## Import

        NetworkFirewallPolicyTunnelInspectionRules can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:NetworkFirewall/networkFirewallPolicyTunnelInspectionRule:NetworkFirewallPolicyTunnelInspectionRule test_network_firewall_policy_tunnel_inspection_rule "networkFirewallPolicies/{networkFirewallPolicyId}/tunnelInspectionRules/{tunnelInspectionRuleName}"
        ```

        :param str resource_name: The name of the resource.
        :param NetworkFirewallPolicyTunnelInspectionRuleArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(NetworkFirewallPolicyTunnelInspectionRuleArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 action: Optional[pulumi.Input[_builtins.str]] = None,
                 condition: Optional[pulumi.Input[Union['NetworkFirewallPolicyTunnelInspectionRuleConditionArgs', 'NetworkFirewallPolicyTunnelInspectionRuleConditionArgsDict']]] = None,
                 name: Optional[pulumi.Input[_builtins.str]] = None,
                 network_firewall_policy_id: Optional[pulumi.Input[_builtins.str]] = None,
                 position: Optional[pulumi.Input[Union['NetworkFirewallPolicyTunnelInspectionRulePositionArgs', 'NetworkFirewallPolicyTunnelInspectionRulePositionArgsDict']]] = None,
                 profile: Optional[pulumi.Input[Union['NetworkFirewallPolicyTunnelInspectionRuleProfileArgs', 'NetworkFirewallPolicyTunnelInspectionRuleProfileArgsDict']]] = None,
                 protocol: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = NetworkFirewallPolicyTunnelInspectionRuleArgs.__new__(NetworkFirewallPolicyTunnelInspectionRuleArgs)

            __props__.__dict__["action"] = action
            if condition is None and not opts.urn:
                raise TypeError("Missing required property 'condition'")
            __props__.__dict__["condition"] = condition
            __props__.__dict__["name"] = name
            if network_firewall_policy_id is None and not opts.urn:
                raise TypeError("Missing required property 'network_firewall_policy_id'")
            __props__.__dict__["network_firewall_policy_id"] = network_firewall_policy_id
            __props__.__dict__["position"] = position
            __props__.__dict__["profile"] = profile
            if protocol is None and not opts.urn:
                raise TypeError("Missing required property 'protocol'")
            __props__.__dict__["protocol"] = protocol
            __props__.__dict__["parent_resource_id"] = None
            __props__.__dict__["priority_order"] = None
        super(NetworkFirewallPolicyTunnelInspectionRule, __self__).__init__(
            'oci:NetworkFirewall/networkFirewallPolicyTunnelInspectionRule:NetworkFirewallPolicyTunnelInspectionRule',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            action: Optional[pulumi.Input[_builtins.str]] = None,
            condition: Optional[pulumi.Input[Union['NetworkFirewallPolicyTunnelInspectionRuleConditionArgs', 'NetworkFirewallPolicyTunnelInspectionRuleConditionArgsDict']]] = None,
            name: Optional[pulumi.Input[_builtins.str]] = None,
            network_firewall_policy_id: Optional[pulumi.Input[_builtins.str]] = None,
            parent_resource_id: Optional[pulumi.Input[_builtins.str]] = None,
            position: Optional[pulumi.Input[Union['NetworkFirewallPolicyTunnelInspectionRulePositionArgs', 'NetworkFirewallPolicyTunnelInspectionRulePositionArgsDict']]] = None,
            priority_order: Optional[pulumi.Input[_builtins.str]] = None,
            profile: Optional[pulumi.Input[Union['NetworkFirewallPolicyTunnelInspectionRuleProfileArgs', 'NetworkFirewallPolicyTunnelInspectionRuleProfileArgsDict']]] = None,
            protocol: Optional[pulumi.Input[_builtins.str]] = None) -> 'NetworkFirewallPolicyTunnelInspectionRule':
        """
        Get an existing NetworkFirewallPolicyTunnelInspectionRule resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] action: (Updatable) Types of Inspect Action on the traffic flow.
               * INSPECT - Inspect the traffic.
               * INSPECT_AND_CAPTURE_LOG - Inspect and capture logs for the traffic.
        :param pulumi.Input[Union['NetworkFirewallPolicyTunnelInspectionRuleConditionArgs', 'NetworkFirewallPolicyTunnelInspectionRuleConditionArgsDict']] condition: (Updatable) Criteria to evaluate against incoming network traffic. A match occurs when at least one item in the array associated with each specified property corresponds with the relevant aspect of the traffic.
        :param pulumi.Input[_builtins.str] name: Name for the Tunnel Inspection Rule, must be unique within the policy.
        :param pulumi.Input[_builtins.str] network_firewall_policy_id: Unique Network Firewall Policy identifier
        :param pulumi.Input[_builtins.str] parent_resource_id: OCID of the Network Firewall Policy this Tunnel Inspection Rule belongs to.
        :param pulumi.Input[Union['NetworkFirewallPolicyTunnelInspectionRulePositionArgs', 'NetworkFirewallPolicyTunnelInspectionRulePositionArgsDict']] position: (Updatable) An object which defines the position of the rule.
        :param pulumi.Input[_builtins.str] priority_order: The priority order in which this rule should be evaluated
        :param pulumi.Input[Union['NetworkFirewallPolicyTunnelInspectionRuleProfileArgs', 'NetworkFirewallPolicyTunnelInspectionRuleProfileArgsDict']] profile: (Updatable) Vxlan Inspect profile used in Vxlan Tunnel Inspection Rules.
        :param pulumi.Input[_builtins.str] protocol: (Updatable) Types of Tunnel Inspection Protocol to be applied on the traffic.
               * VXLAN - VXLAN Tunnel Inspection Protocol will be applied on the traffic.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _NetworkFirewallPolicyTunnelInspectionRuleState.__new__(_NetworkFirewallPolicyTunnelInspectionRuleState)

        __props__.__dict__["action"] = action
        __props__.__dict__["condition"] = condition
        __props__.__dict__["name"] = name
        __props__.__dict__["network_firewall_policy_id"] = network_firewall_policy_id
        __props__.__dict__["parent_resource_id"] = parent_resource_id
        __props__.__dict__["position"] = position
        __props__.__dict__["priority_order"] = priority_order
        __props__.__dict__["profile"] = profile
        __props__.__dict__["protocol"] = protocol
        return NetworkFirewallPolicyTunnelInspectionRule(resource_name, opts=opts, __props__=__props__)

    @_builtins.property
    @pulumi.getter
    def action(self) -> pulumi.Output[_builtins.str]:
        """
        (Updatable) Types of Inspect Action on the traffic flow.
        * INSPECT - Inspect the traffic.
        * INSPECT_AND_CAPTURE_LOG - Inspect and capture logs for the traffic.
        """
        return pulumi.get(self, "action")

    @_builtins.property
    @pulumi.getter
    def condition(self) -> pulumi.Output['outputs.NetworkFirewallPolicyTunnelInspectionRuleCondition']:
        """
        (Updatable) Criteria to evaluate against incoming network traffic. A match occurs when at least one item in the array associated with each specified property corresponds with the relevant aspect of the traffic.
        """
        return pulumi.get(self, "condition")

    @_builtins.property
    @pulumi.getter
    def name(self) -> pulumi.Output[_builtins.str]:
        """
        Name for the Tunnel Inspection Rule, must be unique within the policy.
        """
        return pulumi.get(self, "name")

    @_builtins.property
    @pulumi.getter(name="networkFirewallPolicyId")
    def network_firewall_policy_id(self) -> pulumi.Output[_builtins.str]:
        """
        Unique Network Firewall Policy identifier
        """
        return pulumi.get(self, "network_firewall_policy_id")

    @_builtins.property
    @pulumi.getter(name="parentResourceId")
    def parent_resource_id(self) -> pulumi.Output[_builtins.str]:
        """
        OCID of the Network Firewall Policy this Tunnel Inspection Rule belongs to.
        """
        return pulumi.get(self, "parent_resource_id")

    @_builtins.property
    @pulumi.getter
    def position(self) -> pulumi.Output['outputs.NetworkFirewallPolicyTunnelInspectionRulePosition']:
        """
        (Updatable) An object which defines the position of the rule.
        """
        return pulumi.get(self, "position")

    @_builtins.property
    @pulumi.getter(name="priorityOrder")
    def priority_order(self) -> pulumi.Output[_builtins.str]:
        """
        The priority order in which this rule should be evaluated
        """
        return pulumi.get(self, "priority_order")

    @_builtins.property
    @pulumi.getter
    def profile(self) -> pulumi.Output['outputs.NetworkFirewallPolicyTunnelInspectionRuleProfile']:
        """
        (Updatable) Vxlan Inspect profile used in Vxlan Tunnel Inspection Rules.
        """
        return pulumi.get(self, "profile")

    @_builtins.property
    @pulumi.getter
    def protocol(self) -> pulumi.Output[_builtins.str]:
        """
        (Updatable) Types of Tunnel Inspection Protocol to be applied on the traffic.
        * VXLAN - VXLAN Tunnel Inspection Protocol will be applied on the traffic.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "protocol")

