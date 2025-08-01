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
    'GetLoadBalancerRoutingPolicyResult',
    'AwaitableGetLoadBalancerRoutingPolicyResult',
    'get_load_balancer_routing_policy',
    'get_load_balancer_routing_policy_output',
]

@pulumi.output_type
class GetLoadBalancerRoutingPolicyResult:
    """
    A collection of values returned by getLoadBalancerRoutingPolicy.
    """
    def __init__(__self__, condition_language_version=None, id=None, load_balancer_id=None, name=None, routing_policy_name=None, rules=None, state=None):
        if condition_language_version and not isinstance(condition_language_version, str):
            raise TypeError("Expected argument 'condition_language_version' to be a str")
        pulumi.set(__self__, "condition_language_version", condition_language_version)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if load_balancer_id and not isinstance(load_balancer_id, str):
            raise TypeError("Expected argument 'load_balancer_id' to be a str")
        pulumi.set(__self__, "load_balancer_id", load_balancer_id)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if routing_policy_name and not isinstance(routing_policy_name, str):
            raise TypeError("Expected argument 'routing_policy_name' to be a str")
        pulumi.set(__self__, "routing_policy_name", routing_policy_name)
        if rules and not isinstance(rules, list):
            raise TypeError("Expected argument 'rules' to be a list")
        pulumi.set(__self__, "rules", rules)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @_builtins.property
    @pulumi.getter(name="conditionLanguageVersion")
    def condition_language_version(self) -> _builtins.str:
        """
        The version of the language in which `condition` of `rules` are composed.
        """
        return pulumi.get(self, "condition_language_version")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="loadBalancerId")
    def load_balancer_id(self) -> _builtins.str:
        return pulumi.get(self, "load_balancer_id")

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        """
        A unique name for the routing policy rule. Avoid entering confidential information.
        """
        return pulumi.get(self, "name")

    @_builtins.property
    @pulumi.getter(name="routingPolicyName")
    def routing_policy_name(self) -> _builtins.str:
        return pulumi.get(self, "routing_policy_name")

    @_builtins.property
    @pulumi.getter
    def rules(self) -> Sequence['outputs.GetLoadBalancerRoutingPolicyRuleResult']:
        """
        The ordered list of routing rules.
        """
        return pulumi.get(self, "rules")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        return pulumi.get(self, "state")


class AwaitableGetLoadBalancerRoutingPolicyResult(GetLoadBalancerRoutingPolicyResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetLoadBalancerRoutingPolicyResult(
            condition_language_version=self.condition_language_version,
            id=self.id,
            load_balancer_id=self.load_balancer_id,
            name=self.name,
            routing_policy_name=self.routing_policy_name,
            rules=self.rules,
            state=self.state)


def get_load_balancer_routing_policy(load_balancer_id: Optional[_builtins.str] = None,
                                     routing_policy_name: Optional[_builtins.str] = None,
                                     opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetLoadBalancerRoutingPolicyResult:
    """
    This data source provides details about a specific Load Balancer Routing Policy resource in Oracle Cloud Infrastructure Load Balancer service.

    Gets the specified routing policy.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_load_balancer_routing_policy = oci.LoadBalancer.get_load_balancer_routing_policy(load_balancer_id=test_load_balancer["id"],
        routing_policy_name=test_routing_policy["name"])
    ```


    :param _builtins.str load_balancer_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the specified load balancer.
    :param _builtins.str routing_policy_name: The name of the routing policy to retrieve.  Example: `example_routing_policy`
    """
    __args__ = dict()
    __args__['loadBalancerId'] = load_balancer_id
    __args__['routingPolicyName'] = routing_policy_name
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:LoadBalancer/getLoadBalancerRoutingPolicy:getLoadBalancerRoutingPolicy', __args__, opts=opts, typ=GetLoadBalancerRoutingPolicyResult).value

    return AwaitableGetLoadBalancerRoutingPolicyResult(
        condition_language_version=pulumi.get(__ret__, 'condition_language_version'),
        id=pulumi.get(__ret__, 'id'),
        load_balancer_id=pulumi.get(__ret__, 'load_balancer_id'),
        name=pulumi.get(__ret__, 'name'),
        routing_policy_name=pulumi.get(__ret__, 'routing_policy_name'),
        rules=pulumi.get(__ret__, 'rules'),
        state=pulumi.get(__ret__, 'state'))
def get_load_balancer_routing_policy_output(load_balancer_id: Optional[pulumi.Input[_builtins.str]] = None,
                                            routing_policy_name: Optional[pulumi.Input[_builtins.str]] = None,
                                            opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetLoadBalancerRoutingPolicyResult]:
    """
    This data source provides details about a specific Load Balancer Routing Policy resource in Oracle Cloud Infrastructure Load Balancer service.

    Gets the specified routing policy.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_load_balancer_routing_policy = oci.LoadBalancer.get_load_balancer_routing_policy(load_balancer_id=test_load_balancer["id"],
        routing_policy_name=test_routing_policy["name"])
    ```


    :param _builtins.str load_balancer_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the specified load balancer.
    :param _builtins.str routing_policy_name: The name of the routing policy to retrieve.  Example: `example_routing_policy`
    """
    __args__ = dict()
    __args__['loadBalancerId'] = load_balancer_id
    __args__['routingPolicyName'] = routing_policy_name
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:LoadBalancer/getLoadBalancerRoutingPolicy:getLoadBalancerRoutingPolicy', __args__, opts=opts, typ=GetLoadBalancerRoutingPolicyResult)
    return __ret__.apply(lambda __response__: GetLoadBalancerRoutingPolicyResult(
        condition_language_version=pulumi.get(__response__, 'condition_language_version'),
        id=pulumi.get(__response__, 'id'),
        load_balancer_id=pulumi.get(__response__, 'load_balancer_id'),
        name=pulumi.get(__response__, 'name'),
        routing_policy_name=pulumi.get(__response__, 'routing_policy_name'),
        rules=pulumi.get(__response__, 'rules'),
        state=pulumi.get(__response__, 'state')))
