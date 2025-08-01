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
    'GetNotificationTopicsResult',
    'AwaitableGetNotificationTopicsResult',
    'get_notification_topics',
    'get_notification_topics_output',
]

@pulumi.output_type
class GetNotificationTopicsResult:
    """
    A collection of values returned by getNotificationTopics.
    """
    def __init__(__self__, compartment_id=None, filters=None, id=None, name=None, notification_topics=None, state=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if notification_topics and not isinstance(notification_topics, list):
            raise TypeError("Expected argument 'notification_topics' to be a list")
        pulumi.set(__self__, "notification_topics", notification_topics)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment for the topic.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetNotificationTopicsFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter
    def name(self) -> Optional[_builtins.str]:
        """
        The name of the topic.
        """
        return pulumi.get(self, "name")

    @_builtins.property
    @pulumi.getter(name="notificationTopics")
    def notification_topics(self) -> Sequence['outputs.GetNotificationTopicsNotificationTopicResult']:
        """
        The list of notification_topics.
        """
        return pulumi.get(self, "notification_topics")

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[_builtins.str]:
        """
        The lifecycle state of the topic.
        """
        return pulumi.get(self, "state")


class AwaitableGetNotificationTopicsResult(GetNotificationTopicsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetNotificationTopicsResult(
            compartment_id=self.compartment_id,
            filters=self.filters,
            id=self.id,
            name=self.name,
            notification_topics=self.notification_topics,
            state=self.state)


def get_notification_topics(compartment_id: Optional[_builtins.str] = None,
                            filters: Optional[Sequence[Union['GetNotificationTopicsFilterArgs', 'GetNotificationTopicsFilterArgsDict']]] = None,
                            id: Optional[_builtins.str] = None,
                            name: Optional[_builtins.str] = None,
                            state: Optional[_builtins.str] = None,
                            opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetNotificationTopicsResult:
    """
    This data source provides the list of Notification Topics in Oracle Cloud Infrastructure Notifications service.

    Lists topics in the specified compartment.

    Transactions Per Minute (TPM) per-tenancy limit for this operation: 120.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_notification_topics = oci.Ons.get_notification_topics(compartment_id=compartment_id,
        id=notification_topic_id,
        name=notification_topic_name,
        state=notification_topic_state)
    ```


    :param _builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param _builtins.str id: A filter to only return resources that match the given id exactly.
    :param _builtins.str name: A filter to only return resources that match the given name exactly.
    :param _builtins.str state: Filter returned list by specified lifecycle state. This parameter is case-insensitive.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    __args__['id'] = id
    __args__['name'] = name
    __args__['state'] = state
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Ons/getNotificationTopics:getNotificationTopics', __args__, opts=opts, typ=GetNotificationTopicsResult).value

    return AwaitableGetNotificationTopicsResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        name=pulumi.get(__ret__, 'name'),
        notification_topics=pulumi.get(__ret__, 'notification_topics'),
        state=pulumi.get(__ret__, 'state'))
def get_notification_topics_output(compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                                   filters: Optional[pulumi.Input[Optional[Sequence[Union['GetNotificationTopicsFilterArgs', 'GetNotificationTopicsFilterArgsDict']]]]] = None,
                                   id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                   name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                   state: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                   opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetNotificationTopicsResult]:
    """
    This data source provides the list of Notification Topics in Oracle Cloud Infrastructure Notifications service.

    Lists topics in the specified compartment.

    Transactions Per Minute (TPM) per-tenancy limit for this operation: 120.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_notification_topics = oci.Ons.get_notification_topics(compartment_id=compartment_id,
        id=notification_topic_id,
        name=notification_topic_name,
        state=notification_topic_state)
    ```


    :param _builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param _builtins.str id: A filter to only return resources that match the given id exactly.
    :param _builtins.str name: A filter to only return resources that match the given name exactly.
    :param _builtins.str state: Filter returned list by specified lifecycle state. This parameter is case-insensitive.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    __args__['id'] = id
    __args__['name'] = name
    __args__['state'] = state
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Ons/getNotificationTopics:getNotificationTopics', __args__, opts=opts, typ=GetNotificationTopicsResult)
    return __ret__.apply(lambda __response__: GetNotificationTopicsResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        name=pulumi.get(__response__, 'name'),
        notification_topics=pulumi.get(__response__, 'notification_topics'),
        state=pulumi.get(__response__, 'state')))
