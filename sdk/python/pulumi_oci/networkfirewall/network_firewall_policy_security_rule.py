# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities
from . import outputs
from ._inputs import *

__all__ = ['NetworkFirewallPolicySecurityRuleArgs', 'NetworkFirewallPolicySecurityRule']

@pulumi.input_type
class NetworkFirewallPolicySecurityRuleArgs:
    def __init__(__self__, *,
                 action: pulumi.Input[str],
                 condition: pulumi.Input['NetworkFirewallPolicySecurityRuleConditionArgs'],
                 network_firewall_policy_id: pulumi.Input[str],
                 inspection: Optional[pulumi.Input[str]] = None,
                 name: Optional[pulumi.Input[str]] = None,
                 positions: Optional[pulumi.Input[Sequence[pulumi.Input['NetworkFirewallPolicySecurityRulePositionArgs']]]] = None,
                 priority_order: Optional[pulumi.Input[str]] = None):
        """
        The set of arguments for constructing a NetworkFirewallPolicySecurityRule resource.
        :param pulumi.Input[str] action: (Updatable) Types of Action on the Traffic flow.
               * ALLOW - Allows the traffic.
               * DROP - Silently drops the traffic, e.g. without sending a TCP reset.
               * REJECT - Rejects the traffic, sending a TCP reset to client and/or server as applicable.
               * INSPECT - Inspects traffic for vulnerability as specified in `inspection`, which may result in rejection.
        :param pulumi.Input['NetworkFirewallPolicySecurityRuleConditionArgs'] condition: (Updatable) Criteria to evaluate against network traffic. A match occurs when at least one item in the array associated with each specified property corresponds with the relevant aspect of the traffic. The resources mentioned must already be present in the policy before being referenced in the rule.
        :param pulumi.Input[str] network_firewall_policy_id: Unique Network Firewall Policy identifier
        :param pulumi.Input[str] inspection: (Updatable) Type of inspection to affect the traffic flow. This is only applicable if action is INSPECT.
               * INTRUSION_DETECTION - Intrusion Detection.
               * INTRUSION_PREVENTION - Intrusion Detection and Prevention. Traffic classified as potentially malicious will be rejected as described in `type`.
        :param pulumi.Input[str] name: Name for the Security rule, must be unique within the policy.
        :param pulumi.Input[Sequence[pulumi.Input['NetworkFirewallPolicySecurityRulePositionArgs']]] positions: (Updatable) An object which defines the position of the rule. Only one of the following position references should be provided.
        """
        pulumi.set(__self__, "action", action)
        pulumi.set(__self__, "condition", condition)
        pulumi.set(__self__, "network_firewall_policy_id", network_firewall_policy_id)
        if inspection is not None:
            pulumi.set(__self__, "inspection", inspection)
        if name is not None:
            pulumi.set(__self__, "name", name)
        if positions is not None:
            pulumi.set(__self__, "positions", positions)
        if priority_order is not None:
            pulumi.set(__self__, "priority_order", priority_order)

    @property
    @pulumi.getter
    def action(self) -> pulumi.Input[str]:
        """
        (Updatable) Types of Action on the Traffic flow.
        * ALLOW - Allows the traffic.
        * DROP - Silently drops the traffic, e.g. without sending a TCP reset.
        * REJECT - Rejects the traffic, sending a TCP reset to client and/or server as applicable.
        * INSPECT - Inspects traffic for vulnerability as specified in `inspection`, which may result in rejection.
        """
        return pulumi.get(self, "action")

    @action.setter
    def action(self, value: pulumi.Input[str]):
        pulumi.set(self, "action", value)

    @property
    @pulumi.getter
    def condition(self) -> pulumi.Input['NetworkFirewallPolicySecurityRuleConditionArgs']:
        """
        (Updatable) Criteria to evaluate against network traffic. A match occurs when at least one item in the array associated with each specified property corresponds with the relevant aspect of the traffic. The resources mentioned must already be present in the policy before being referenced in the rule.
        """
        return pulumi.get(self, "condition")

    @condition.setter
    def condition(self, value: pulumi.Input['NetworkFirewallPolicySecurityRuleConditionArgs']):
        pulumi.set(self, "condition", value)

    @property
    @pulumi.getter(name="networkFirewallPolicyId")
    def network_firewall_policy_id(self) -> pulumi.Input[str]:
        """
        Unique Network Firewall Policy identifier
        """
        return pulumi.get(self, "network_firewall_policy_id")

    @network_firewall_policy_id.setter
    def network_firewall_policy_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "network_firewall_policy_id", value)

    @property
    @pulumi.getter
    def inspection(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Type of inspection to affect the traffic flow. This is only applicable if action is INSPECT.
        * INTRUSION_DETECTION - Intrusion Detection.
        * INTRUSION_PREVENTION - Intrusion Detection and Prevention. Traffic classified as potentially malicious will be rejected as described in `type`.
        """
        return pulumi.get(self, "inspection")

    @inspection.setter
    def inspection(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "inspection", value)

    @property
    @pulumi.getter
    def name(self) -> Optional[pulumi.Input[str]]:
        """
        Name for the Security rule, must be unique within the policy.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def positions(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['NetworkFirewallPolicySecurityRulePositionArgs']]]]:
        """
        (Updatable) An object which defines the position of the rule. Only one of the following position references should be provided.
        """
        return pulumi.get(self, "positions")

    @positions.setter
    def positions(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['NetworkFirewallPolicySecurityRulePositionArgs']]]]):
        pulumi.set(self, "positions", value)

    @property
    @pulumi.getter(name="priorityOrder")
    def priority_order(self) -> Optional[pulumi.Input[str]]:
        return pulumi.get(self, "priority_order")

    @priority_order.setter
    def priority_order(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "priority_order", value)


@pulumi.input_type
class _NetworkFirewallPolicySecurityRuleState:
    def __init__(__self__, *,
                 action: Optional[pulumi.Input[str]] = None,
                 condition: Optional[pulumi.Input['NetworkFirewallPolicySecurityRuleConditionArgs']] = None,
                 inspection: Optional[pulumi.Input[str]] = None,
                 name: Optional[pulumi.Input[str]] = None,
                 network_firewall_policy_id: Optional[pulumi.Input[str]] = None,
                 parent_resource_id: Optional[pulumi.Input[str]] = None,
                 positions: Optional[pulumi.Input[Sequence[pulumi.Input['NetworkFirewallPolicySecurityRulePositionArgs']]]] = None,
                 priority_order: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering NetworkFirewallPolicySecurityRule resources.
        :param pulumi.Input[str] action: (Updatable) Types of Action on the Traffic flow.
               * ALLOW - Allows the traffic.
               * DROP - Silently drops the traffic, e.g. without sending a TCP reset.
               * REJECT - Rejects the traffic, sending a TCP reset to client and/or server as applicable.
               * INSPECT - Inspects traffic for vulnerability as specified in `inspection`, which may result in rejection.
        :param pulumi.Input['NetworkFirewallPolicySecurityRuleConditionArgs'] condition: (Updatable) Criteria to evaluate against network traffic. A match occurs when at least one item in the array associated with each specified property corresponds with the relevant aspect of the traffic. The resources mentioned must already be present in the policy before being referenced in the rule.
        :param pulumi.Input[str] inspection: (Updatable) Type of inspection to affect the traffic flow. This is only applicable if action is INSPECT.
               * INTRUSION_DETECTION - Intrusion Detection.
               * INTRUSION_PREVENTION - Intrusion Detection and Prevention. Traffic classified as potentially malicious will be rejected as described in `type`.
        :param pulumi.Input[str] name: Name for the Security rule, must be unique within the policy.
        :param pulumi.Input[str] network_firewall_policy_id: Unique Network Firewall Policy identifier
        :param pulumi.Input[str] parent_resource_id: OCID of the Network Firewall Policy this security rule belongs to.
        :param pulumi.Input[Sequence[pulumi.Input['NetworkFirewallPolicySecurityRulePositionArgs']]] positions: (Updatable) An object which defines the position of the rule. Only one of the following position references should be provided.
        """
        if action is not None:
            pulumi.set(__self__, "action", action)
        if condition is not None:
            pulumi.set(__self__, "condition", condition)
        if inspection is not None:
            pulumi.set(__self__, "inspection", inspection)
        if name is not None:
            pulumi.set(__self__, "name", name)
        if network_firewall_policy_id is not None:
            pulumi.set(__self__, "network_firewall_policy_id", network_firewall_policy_id)
        if parent_resource_id is not None:
            pulumi.set(__self__, "parent_resource_id", parent_resource_id)
        if positions is not None:
            pulumi.set(__self__, "positions", positions)
        if priority_order is not None:
            pulumi.set(__self__, "priority_order", priority_order)

    @property
    @pulumi.getter
    def action(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Types of Action on the Traffic flow.
        * ALLOW - Allows the traffic.
        * DROP - Silently drops the traffic, e.g. without sending a TCP reset.
        * REJECT - Rejects the traffic, sending a TCP reset to client and/or server as applicable.
        * INSPECT - Inspects traffic for vulnerability as specified in `inspection`, which may result in rejection.
        """
        return pulumi.get(self, "action")

    @action.setter
    def action(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "action", value)

    @property
    @pulumi.getter
    def condition(self) -> Optional[pulumi.Input['NetworkFirewallPolicySecurityRuleConditionArgs']]:
        """
        (Updatable) Criteria to evaluate against network traffic. A match occurs when at least one item in the array associated with each specified property corresponds with the relevant aspect of the traffic. The resources mentioned must already be present in the policy before being referenced in the rule.
        """
        return pulumi.get(self, "condition")

    @condition.setter
    def condition(self, value: Optional[pulumi.Input['NetworkFirewallPolicySecurityRuleConditionArgs']]):
        pulumi.set(self, "condition", value)

    @property
    @pulumi.getter
    def inspection(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) Type of inspection to affect the traffic flow. This is only applicable if action is INSPECT.
        * INTRUSION_DETECTION - Intrusion Detection.
        * INTRUSION_PREVENTION - Intrusion Detection and Prevention. Traffic classified as potentially malicious will be rejected as described in `type`.
        """
        return pulumi.get(self, "inspection")

    @inspection.setter
    def inspection(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "inspection", value)

    @property
    @pulumi.getter
    def name(self) -> Optional[pulumi.Input[str]]:
        """
        Name for the Security rule, must be unique within the policy.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter(name="networkFirewallPolicyId")
    def network_firewall_policy_id(self) -> Optional[pulumi.Input[str]]:
        """
        Unique Network Firewall Policy identifier
        """
        return pulumi.get(self, "network_firewall_policy_id")

    @network_firewall_policy_id.setter
    def network_firewall_policy_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "network_firewall_policy_id", value)

    @property
    @pulumi.getter(name="parentResourceId")
    def parent_resource_id(self) -> Optional[pulumi.Input[str]]:
        """
        OCID of the Network Firewall Policy this security rule belongs to.
        """
        return pulumi.get(self, "parent_resource_id")

    @parent_resource_id.setter
    def parent_resource_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "parent_resource_id", value)

    @property
    @pulumi.getter
    def positions(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['NetworkFirewallPolicySecurityRulePositionArgs']]]]:
        """
        (Updatable) An object which defines the position of the rule. Only one of the following position references should be provided.
        """
        return pulumi.get(self, "positions")

    @positions.setter
    def positions(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['NetworkFirewallPolicySecurityRulePositionArgs']]]]):
        pulumi.set(self, "positions", value)

    @property
    @pulumi.getter(name="priorityOrder")
    def priority_order(self) -> Optional[pulumi.Input[str]]:
        return pulumi.get(self, "priority_order")

    @priority_order.setter
    def priority_order(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "priority_order", value)


class NetworkFirewallPolicySecurityRule(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 action: Optional[pulumi.Input[str]] = None,
                 condition: Optional[pulumi.Input[pulumi.InputType['NetworkFirewallPolicySecurityRuleConditionArgs']]] = None,
                 inspection: Optional[pulumi.Input[str]] = None,
                 name: Optional[pulumi.Input[str]] = None,
                 network_firewall_policy_id: Optional[pulumi.Input[str]] = None,
                 positions: Optional[pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['NetworkFirewallPolicySecurityRulePositionArgs']]]]] = None,
                 priority_order: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        """
        This resource provides the Network Firewall Policy Security Rule resource in Oracle Cloud Infrastructure Network Firewall service.

        Creates a new Security Rule for the Network Firewall Policy.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_network_firewall_policy_security_rule = oci.network_firewall.NetworkFirewallPolicySecurityRule("testNetworkFirewallPolicySecurityRule",
            action=var["network_firewall_policy_security_rule_action"],
            condition=oci.network_firewall.NetworkFirewallPolicySecurityRuleConditionArgs(
                applications=var["network_firewall_policy_security_rule_condition_application"],
                destination_addresses=var["network_firewall_policy_security_rule_condition_destination_address"],
                services=var["network_firewall_policy_security_rule_condition_service"],
                source_addresses=var["network_firewall_policy_security_rule_condition_source_address"],
                urls=var["network_firewall_policy_security_rule_condition_url"],
            ),
            network_firewall_policy_id=oci_network_firewall_network_firewall_policy["test_network_firewall_policy"]["id"],
            inspection=var["network_firewall_policy_security_rule_inspection"],
            positions=[oci.network_firewall.NetworkFirewallPolicySecurityRulePositionArgs(
                after_rule=var["network_firewall_policy_security_rule_position_after_rule"],
                before_rule=var["network_firewall_policy_security_rule_position_before_rule"],
            )])
        ```

        ## Import

        NetworkFirewallPolicySecurityRules can be imported using the `name`, e.g.

        ```sh
         $ pulumi import oci:NetworkFirewall/networkFirewallPolicySecurityRule:NetworkFirewallPolicySecurityRule test_network_firewall_policy_security_rule "networkFirewallPolicies/{networkFirewallPolicyId}/securityRules/{securityRuleName}"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] action: (Updatable) Types of Action on the Traffic flow.
               * ALLOW - Allows the traffic.
               * DROP - Silently drops the traffic, e.g. without sending a TCP reset.
               * REJECT - Rejects the traffic, sending a TCP reset to client and/or server as applicable.
               * INSPECT - Inspects traffic for vulnerability as specified in `inspection`, which may result in rejection.
        :param pulumi.Input[pulumi.InputType['NetworkFirewallPolicySecurityRuleConditionArgs']] condition: (Updatable) Criteria to evaluate against network traffic. A match occurs when at least one item in the array associated with each specified property corresponds with the relevant aspect of the traffic. The resources mentioned must already be present in the policy before being referenced in the rule.
        :param pulumi.Input[str] inspection: (Updatable) Type of inspection to affect the traffic flow. This is only applicable if action is INSPECT.
               * INTRUSION_DETECTION - Intrusion Detection.
               * INTRUSION_PREVENTION - Intrusion Detection and Prevention. Traffic classified as potentially malicious will be rejected as described in `type`.
        :param pulumi.Input[str] name: Name for the Security rule, must be unique within the policy.
        :param pulumi.Input[str] network_firewall_policy_id: Unique Network Firewall Policy identifier
        :param pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['NetworkFirewallPolicySecurityRulePositionArgs']]]] positions: (Updatable) An object which defines the position of the rule. Only one of the following position references should be provided.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: NetworkFirewallPolicySecurityRuleArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Network Firewall Policy Security Rule resource in Oracle Cloud Infrastructure Network Firewall service.

        Creates a new Security Rule for the Network Firewall Policy.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_network_firewall_policy_security_rule = oci.network_firewall.NetworkFirewallPolicySecurityRule("testNetworkFirewallPolicySecurityRule",
            action=var["network_firewall_policy_security_rule_action"],
            condition=oci.network_firewall.NetworkFirewallPolicySecurityRuleConditionArgs(
                applications=var["network_firewall_policy_security_rule_condition_application"],
                destination_addresses=var["network_firewall_policy_security_rule_condition_destination_address"],
                services=var["network_firewall_policy_security_rule_condition_service"],
                source_addresses=var["network_firewall_policy_security_rule_condition_source_address"],
                urls=var["network_firewall_policy_security_rule_condition_url"],
            ),
            network_firewall_policy_id=oci_network_firewall_network_firewall_policy["test_network_firewall_policy"]["id"],
            inspection=var["network_firewall_policy_security_rule_inspection"],
            positions=[oci.network_firewall.NetworkFirewallPolicySecurityRulePositionArgs(
                after_rule=var["network_firewall_policy_security_rule_position_after_rule"],
                before_rule=var["network_firewall_policy_security_rule_position_before_rule"],
            )])
        ```

        ## Import

        NetworkFirewallPolicySecurityRules can be imported using the `name`, e.g.

        ```sh
         $ pulumi import oci:NetworkFirewall/networkFirewallPolicySecurityRule:NetworkFirewallPolicySecurityRule test_network_firewall_policy_security_rule "networkFirewallPolicies/{networkFirewallPolicyId}/securityRules/{securityRuleName}"
        ```

        :param str resource_name: The name of the resource.
        :param NetworkFirewallPolicySecurityRuleArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(NetworkFirewallPolicySecurityRuleArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 action: Optional[pulumi.Input[str]] = None,
                 condition: Optional[pulumi.Input[pulumi.InputType['NetworkFirewallPolicySecurityRuleConditionArgs']]] = None,
                 inspection: Optional[pulumi.Input[str]] = None,
                 name: Optional[pulumi.Input[str]] = None,
                 network_firewall_policy_id: Optional[pulumi.Input[str]] = None,
                 positions: Optional[pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['NetworkFirewallPolicySecurityRulePositionArgs']]]]] = None,
                 priority_order: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = NetworkFirewallPolicySecurityRuleArgs.__new__(NetworkFirewallPolicySecurityRuleArgs)

            if action is None and not opts.urn:
                raise TypeError("Missing required property 'action'")
            __props__.__dict__["action"] = action
            if condition is None and not opts.urn:
                raise TypeError("Missing required property 'condition'")
            __props__.__dict__["condition"] = condition
            __props__.__dict__["inspection"] = inspection
            __props__.__dict__["name"] = name
            if network_firewall_policy_id is None and not opts.urn:
                raise TypeError("Missing required property 'network_firewall_policy_id'")
            __props__.__dict__["network_firewall_policy_id"] = network_firewall_policy_id
            __props__.__dict__["positions"] = positions
            __props__.__dict__["priority_order"] = priority_order
            __props__.__dict__["parent_resource_id"] = None
        super(NetworkFirewallPolicySecurityRule, __self__).__init__(
            'oci:NetworkFirewall/networkFirewallPolicySecurityRule:NetworkFirewallPolicySecurityRule',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            action: Optional[pulumi.Input[str]] = None,
            condition: Optional[pulumi.Input[pulumi.InputType['NetworkFirewallPolicySecurityRuleConditionArgs']]] = None,
            inspection: Optional[pulumi.Input[str]] = None,
            name: Optional[pulumi.Input[str]] = None,
            network_firewall_policy_id: Optional[pulumi.Input[str]] = None,
            parent_resource_id: Optional[pulumi.Input[str]] = None,
            positions: Optional[pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['NetworkFirewallPolicySecurityRulePositionArgs']]]]] = None,
            priority_order: Optional[pulumi.Input[str]] = None) -> 'NetworkFirewallPolicySecurityRule':
        """
        Get an existing NetworkFirewallPolicySecurityRule resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] action: (Updatable) Types of Action on the Traffic flow.
               * ALLOW - Allows the traffic.
               * DROP - Silently drops the traffic, e.g. without sending a TCP reset.
               * REJECT - Rejects the traffic, sending a TCP reset to client and/or server as applicable.
               * INSPECT - Inspects traffic for vulnerability as specified in `inspection`, which may result in rejection.
        :param pulumi.Input[pulumi.InputType['NetworkFirewallPolicySecurityRuleConditionArgs']] condition: (Updatable) Criteria to evaluate against network traffic. A match occurs when at least one item in the array associated with each specified property corresponds with the relevant aspect of the traffic. The resources mentioned must already be present in the policy before being referenced in the rule.
        :param pulumi.Input[str] inspection: (Updatable) Type of inspection to affect the traffic flow. This is only applicable if action is INSPECT.
               * INTRUSION_DETECTION - Intrusion Detection.
               * INTRUSION_PREVENTION - Intrusion Detection and Prevention. Traffic classified as potentially malicious will be rejected as described in `type`.
        :param pulumi.Input[str] name: Name for the Security rule, must be unique within the policy.
        :param pulumi.Input[str] network_firewall_policy_id: Unique Network Firewall Policy identifier
        :param pulumi.Input[str] parent_resource_id: OCID of the Network Firewall Policy this security rule belongs to.
        :param pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['NetworkFirewallPolicySecurityRulePositionArgs']]]] positions: (Updatable) An object which defines the position of the rule. Only one of the following position references should be provided.
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _NetworkFirewallPolicySecurityRuleState.__new__(_NetworkFirewallPolicySecurityRuleState)

        __props__.__dict__["action"] = action
        __props__.__dict__["condition"] = condition
        __props__.__dict__["inspection"] = inspection
        __props__.__dict__["name"] = name
        __props__.__dict__["network_firewall_policy_id"] = network_firewall_policy_id
        __props__.__dict__["parent_resource_id"] = parent_resource_id
        __props__.__dict__["positions"] = positions
        __props__.__dict__["priority_order"] = priority_order
        return NetworkFirewallPolicySecurityRule(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter
    def action(self) -> pulumi.Output[str]:
        """
        (Updatable) Types of Action on the Traffic flow.
        * ALLOW - Allows the traffic.
        * DROP - Silently drops the traffic, e.g. without sending a TCP reset.
        * REJECT - Rejects the traffic, sending a TCP reset to client and/or server as applicable.
        * INSPECT - Inspects traffic for vulnerability as specified in `inspection`, which may result in rejection.
        """
        return pulumi.get(self, "action")

    @property
    @pulumi.getter
    def condition(self) -> pulumi.Output['outputs.NetworkFirewallPolicySecurityRuleCondition']:
        """
        (Updatable) Criteria to evaluate against network traffic. A match occurs when at least one item in the array associated with each specified property corresponds with the relevant aspect of the traffic. The resources mentioned must already be present in the policy before being referenced in the rule.
        """
        return pulumi.get(self, "condition")

    @property
    @pulumi.getter
    def inspection(self) -> pulumi.Output[Optional[str]]:
        """
        (Updatable) Type of inspection to affect the traffic flow. This is only applicable if action is INSPECT.
        * INTRUSION_DETECTION - Intrusion Detection.
        * INTRUSION_PREVENTION - Intrusion Detection and Prevention. Traffic classified as potentially malicious will be rejected as described in `type`.
        """
        return pulumi.get(self, "inspection")

    @property
    @pulumi.getter
    def name(self) -> pulumi.Output[str]:
        """
        Name for the Security rule, must be unique within the policy.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter(name="networkFirewallPolicyId")
    def network_firewall_policy_id(self) -> pulumi.Output[str]:
        """
        Unique Network Firewall Policy identifier
        """
        return pulumi.get(self, "network_firewall_policy_id")

    @property
    @pulumi.getter(name="parentResourceId")
    def parent_resource_id(self) -> pulumi.Output[str]:
        """
        OCID of the Network Firewall Policy this security rule belongs to.
        """
        return pulumi.get(self, "parent_resource_id")

    @property
    @pulumi.getter
    def positions(self) -> pulumi.Output[Sequence['outputs.NetworkFirewallPolicySecurityRulePosition']]:
        """
        (Updatable) An object which defines the position of the rule. Only one of the following position references should be provided.
        """
        return pulumi.get(self, "positions")

    @property
    @pulumi.getter(name="priorityOrder")
    def priority_order(self) -> pulumi.Output[Optional[str]]:
        return pulumi.get(self, "priority_order")
