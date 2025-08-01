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
    'RuleActionsArgs',
    'RuleActionsArgsDict',
    'RuleActionsActionArgs',
    'RuleActionsActionArgsDict',
    'GetRulesFilterArgs',
    'GetRulesFilterArgsDict',
]

MYPY = False

if not MYPY:
    class RuleActionsArgsDict(TypedDict):
        actions: pulumi.Input[Sequence[pulumi.Input['RuleActionsActionArgsDict']]]
        """
        (Updatable) A list of one or more ActionDetails objects.
        """
elif False:
    RuleActionsArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class RuleActionsArgs:
    def __init__(__self__, *,
                 actions: pulumi.Input[Sequence[pulumi.Input['RuleActionsActionArgs']]]):
        """
        :param pulumi.Input[Sequence[pulumi.Input['RuleActionsActionArgs']]] actions: (Updatable) A list of one or more ActionDetails objects.
        """
        pulumi.set(__self__, "actions", actions)

    @_builtins.property
    @pulumi.getter
    def actions(self) -> pulumi.Input[Sequence[pulumi.Input['RuleActionsActionArgs']]]:
        """
        (Updatable) A list of one or more ActionDetails objects.
        """
        return pulumi.get(self, "actions")

    @actions.setter
    def actions(self, value: pulumi.Input[Sequence[pulumi.Input['RuleActionsActionArgs']]]):
        pulumi.set(self, "actions", value)


if not MYPY:
    class RuleActionsActionArgsDict(TypedDict):
        action_type: pulumi.Input[_builtins.str]
        """
        (Updatable) The action to perform if the condition in the rule matches an event.
        * **ONS:** Send to an Oracle Notification Service topic.
        * **OSS:** Send to a stream from Oracle Streaming Service.
        * **FAAS:** Send to an Oracle Functions Service endpoint.
        """
        is_enabled: pulumi.Input[_builtins.bool]
        """
        (Updatable) Whether or not this action is currently enabled.  Example: `true`
        """
        description: NotRequired[pulumi.Input[_builtins.str]]
        """
        (Updatable) A string that describes the details of the action. It does not have to be unique, and you can change it. Avoid entering confidential information.
        """
        function_id: NotRequired[pulumi.Input[_builtins.str]]
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a Function hosted by Oracle Functions Service.
        """
        id: NotRequired[pulumi.Input[_builtins.str]]
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this rule.
        """
        lifecycle_message: NotRequired[pulumi.Input[_builtins.str]]
        """
        A message generated by the Events service about the current state of this rule.
        """
        state: NotRequired[pulumi.Input[_builtins.str]]
        """
        The current state of the rule.
        """
        stream_id: NotRequired[pulumi.Input[_builtins.str]]
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the stream to which messages are delivered.
        """
        topic_id: NotRequired[pulumi.Input[_builtins.str]]
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the topic to which messages are delivered.
        """
elif False:
    RuleActionsActionArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class RuleActionsActionArgs:
    def __init__(__self__, *,
                 action_type: pulumi.Input[_builtins.str],
                 is_enabled: pulumi.Input[_builtins.bool],
                 description: Optional[pulumi.Input[_builtins.str]] = None,
                 function_id: Optional[pulumi.Input[_builtins.str]] = None,
                 id: Optional[pulumi.Input[_builtins.str]] = None,
                 lifecycle_message: Optional[pulumi.Input[_builtins.str]] = None,
                 state: Optional[pulumi.Input[_builtins.str]] = None,
                 stream_id: Optional[pulumi.Input[_builtins.str]] = None,
                 topic_id: Optional[pulumi.Input[_builtins.str]] = None):
        """
        :param pulumi.Input[_builtins.str] action_type: (Updatable) The action to perform if the condition in the rule matches an event.
               * **ONS:** Send to an Oracle Notification Service topic.
               * **OSS:** Send to a stream from Oracle Streaming Service.
               * **FAAS:** Send to an Oracle Functions Service endpoint.
        :param pulumi.Input[_builtins.bool] is_enabled: (Updatable) Whether or not this action is currently enabled.  Example: `true`
        :param pulumi.Input[_builtins.str] description: (Updatable) A string that describes the details of the action. It does not have to be unique, and you can change it. Avoid entering confidential information.
        :param pulumi.Input[_builtins.str] function_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a Function hosted by Oracle Functions Service.
        :param pulumi.Input[_builtins.str] id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this rule.
        :param pulumi.Input[_builtins.str] lifecycle_message: A message generated by the Events service about the current state of this rule.
        :param pulumi.Input[_builtins.str] state: The current state of the rule.
        :param pulumi.Input[_builtins.str] stream_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the stream to which messages are delivered.
        :param pulumi.Input[_builtins.str] topic_id: (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the topic to which messages are delivered.
        """
        pulumi.set(__self__, "action_type", action_type)
        pulumi.set(__self__, "is_enabled", is_enabled)
        if description is not None:
            pulumi.set(__self__, "description", description)
        if function_id is not None:
            pulumi.set(__self__, "function_id", function_id)
        if id is not None:
            pulumi.set(__self__, "id", id)
        if lifecycle_message is not None:
            pulumi.set(__self__, "lifecycle_message", lifecycle_message)
        if state is not None:
            pulumi.set(__self__, "state", state)
        if stream_id is not None:
            pulumi.set(__self__, "stream_id", stream_id)
        if topic_id is not None:
            pulumi.set(__self__, "topic_id", topic_id)

    @_builtins.property
    @pulumi.getter(name="actionType")
    def action_type(self) -> pulumi.Input[_builtins.str]:
        """
        (Updatable) The action to perform if the condition in the rule matches an event.
        * **ONS:** Send to an Oracle Notification Service topic.
        * **OSS:** Send to a stream from Oracle Streaming Service.
        * **FAAS:** Send to an Oracle Functions Service endpoint.
        """
        return pulumi.get(self, "action_type")

    @action_type.setter
    def action_type(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "action_type", value)

    @_builtins.property
    @pulumi.getter(name="isEnabled")
    def is_enabled(self) -> pulumi.Input[_builtins.bool]:
        """
        (Updatable) Whether or not this action is currently enabled.  Example: `true`
        """
        return pulumi.get(self, "is_enabled")

    @is_enabled.setter
    def is_enabled(self, value: pulumi.Input[_builtins.bool]):
        pulumi.set(self, "is_enabled", value)

    @_builtins.property
    @pulumi.getter
    def description(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) A string that describes the details of the action. It does not have to be unique, and you can change it. Avoid entering confidential information.
        """
        return pulumi.get(self, "description")

    @description.setter
    def description(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "description", value)

    @_builtins.property
    @pulumi.getter(name="functionId")
    def function_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a Function hosted by Oracle Functions Service.
        """
        return pulumi.get(self, "function_id")

    @function_id.setter
    def function_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "function_id", value)

    @_builtins.property
    @pulumi.getter
    def id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this rule.
        """
        return pulumi.get(self, "id")

    @id.setter
    def id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "id", value)

    @_builtins.property
    @pulumi.getter(name="lifecycleMessage")
    def lifecycle_message(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        A message generated by the Events service about the current state of this rule.
        """
        return pulumi.get(self, "lifecycle_message")

    @lifecycle_message.setter
    def lifecycle_message(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "lifecycle_message", value)

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The current state of the rule.
        """
        return pulumi.get(self, "state")

    @state.setter
    def state(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "state", value)

    @_builtins.property
    @pulumi.getter(name="streamId")
    def stream_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the stream to which messages are delivered.
        """
        return pulumi.get(self, "stream_id")

    @stream_id.setter
    def stream_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "stream_id", value)

    @_builtins.property
    @pulumi.getter(name="topicId")
    def topic_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the topic to which messages are delivered.
        """
        return pulumi.get(self, "topic_id")

    @topic_id.setter
    def topic_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "topic_id", value)


if not MYPY:
    class GetRulesFilterArgsDict(TypedDict):
        name: _builtins.str
        values: Sequence[_builtins.str]
        regex: NotRequired[_builtins.bool]
elif False:
    GetRulesFilterArgsDict: TypeAlias = Mapping[str, Any]

@pulumi.input_type
class GetRulesFilterArgs:
    def __init__(__self__, *,
                 name: _builtins.str,
                 values: Sequence[_builtins.str],
                 regex: Optional[_builtins.bool] = None):
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: _builtins.str):
        pulumi.set(self, "name", value)

    @_builtins.property
    @pulumi.getter
    def values(self) -> Sequence[_builtins.str]:
        return pulumi.get(self, "values")

    @values.setter
    def values(self, value: Sequence[_builtins.str]):
        pulumi.set(self, "values", value)

    @_builtins.property
    @pulumi.getter
    def regex(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "regex")

    @regex.setter
    def regex(self, value: Optional[_builtins.bool]):
        pulumi.set(self, "regex", value)


