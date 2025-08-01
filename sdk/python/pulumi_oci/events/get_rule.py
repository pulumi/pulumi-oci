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
    'GetRuleResult',
    'AwaitableGetRuleResult',
    'get_rule',
    'get_rule_output',
]

@pulumi.output_type
class GetRuleResult:
    """
    A collection of values returned by getRule.
    """
    def __init__(__self__, actions=None, compartment_id=None, condition=None, defined_tags=None, description=None, display_name=None, freeform_tags=None, id=None, is_enabled=None, lifecycle_message=None, rule_id=None, state=None, time_created=None):
        if actions and not isinstance(actions, list):
            raise TypeError("Expected argument 'actions' to be a list")
        pulumi.set(__self__, "actions", actions)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if condition and not isinstance(condition, str):
            raise TypeError("Expected argument 'condition' to be a str")
        pulumi.set(__self__, "condition", condition)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        pulumi.set(__self__, "description", description)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if is_enabled and not isinstance(is_enabled, bool):
            raise TypeError("Expected argument 'is_enabled' to be a bool")
        pulumi.set(__self__, "is_enabled", is_enabled)
        if lifecycle_message and not isinstance(lifecycle_message, str):
            raise TypeError("Expected argument 'lifecycle_message' to be a str")
        pulumi.set(__self__, "lifecycle_message", lifecycle_message)
        if rule_id and not isinstance(rule_id, str):
            raise TypeError("Expected argument 'rule_id' to be a str")
        pulumi.set(__self__, "rule_id", rule_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)

    @_builtins.property
    @pulumi.getter
    def actions(self) -> Sequence['outputs.GetRuleActionResult']:
        """
        A list of one or more Action objects.
        """
        return pulumi.get(self, "actions")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to which this rule belongs.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter
    def condition(self) -> _builtins.str:
        """
        A filter that specifies the event that will trigger actions associated with this rule. A few  important things to remember about filters:
        * Fields not mentioned in the condition are ignored. You can create a valid filter that matches all events with two curly brackets: `{}`
        """
        return pulumi.get(self, "condition")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, _builtins.str]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter
    def description(self) -> _builtins.str:
        """
        A string that describes the details of the rule. It does not have to be unique, and you can change it. Avoid entering confidential information.
        """
        return pulumi.get(self, "description")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> _builtins.str:
        """
        A string that describes the rule. It does not have to be unique, and you can change it. Avoid entering confidential information.  Example: `"This rule sends a notification upon completion of DbaaS backup."`
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, _builtins.str]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this rule.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="isEnabled")
    def is_enabled(self) -> _builtins.bool:
        """
        Whether or not this rule is currently enabled.  Example: `true`
        """
        return pulumi.get(self, "is_enabled")

    @_builtins.property
    @pulumi.getter(name="lifecycleMessage")
    def lifecycle_message(self) -> _builtins.str:
        """
        A message generated by the Events service about the current state of this rule.
        """
        return pulumi.get(self, "lifecycle_message")

    @_builtins.property
    @pulumi.getter(name="ruleId")
    def rule_id(self) -> _builtins.str:
        return pulumi.get(self, "rule_id")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current state of the rule.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        The time this rule was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-09-12T22:47:12.613Z`
        """
        return pulumi.get(self, "time_created")


class AwaitableGetRuleResult(GetRuleResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetRuleResult(
            actions=self.actions,
            compartment_id=self.compartment_id,
            condition=self.condition,
            defined_tags=self.defined_tags,
            description=self.description,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            is_enabled=self.is_enabled,
            lifecycle_message=self.lifecycle_message,
            rule_id=self.rule_id,
            state=self.state,
            time_created=self.time_created)


def get_rule(rule_id: Optional[_builtins.str] = None,
             opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetRuleResult:
    """
    This data source provides details about a specific Rule resource in Oracle Cloud Infrastructure Events service.

    Retrieves a rule.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_rule = oci.Events.get_rule(rule_id=test_rule_oci_events_rule["id"])
    ```


    :param _builtins.str rule_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this rule.
    """
    __args__ = dict()
    __args__['ruleId'] = rule_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Events/getRule:getRule', __args__, opts=opts, typ=GetRuleResult).value

    return AwaitableGetRuleResult(
        actions=pulumi.get(__ret__, 'actions'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        condition=pulumi.get(__ret__, 'condition'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        description=pulumi.get(__ret__, 'description'),
        display_name=pulumi.get(__ret__, 'display_name'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        id=pulumi.get(__ret__, 'id'),
        is_enabled=pulumi.get(__ret__, 'is_enabled'),
        lifecycle_message=pulumi.get(__ret__, 'lifecycle_message'),
        rule_id=pulumi.get(__ret__, 'rule_id'),
        state=pulumi.get(__ret__, 'state'),
        time_created=pulumi.get(__ret__, 'time_created'))
def get_rule_output(rule_id: Optional[pulumi.Input[_builtins.str]] = None,
                    opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetRuleResult]:
    """
    This data source provides details about a specific Rule resource in Oracle Cloud Infrastructure Events service.

    Retrieves a rule.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_rule = oci.Events.get_rule(rule_id=test_rule_oci_events_rule["id"])
    ```


    :param _builtins.str rule_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this rule.
    """
    __args__ = dict()
    __args__['ruleId'] = rule_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Events/getRule:getRule', __args__, opts=opts, typ=GetRuleResult)
    return __ret__.apply(lambda __response__: GetRuleResult(
        actions=pulumi.get(__response__, 'actions'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        condition=pulumi.get(__response__, 'condition'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        description=pulumi.get(__response__, 'description'),
        display_name=pulumi.get(__response__, 'display_name'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        id=pulumi.get(__response__, 'id'),
        is_enabled=pulumi.get(__response__, 'is_enabled'),
        lifecycle_message=pulumi.get(__response__, 'lifecycle_message'),
        rule_id=pulumi.get(__response__, 'rule_id'),
        state=pulumi.get(__response__, 'state'),
        time_created=pulumi.get(__response__, 'time_created')))
