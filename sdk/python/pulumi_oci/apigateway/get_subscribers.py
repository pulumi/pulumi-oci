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
    'GetSubscribersResult',
    'AwaitableGetSubscribersResult',
    'get_subscribers',
    'get_subscribers_output',
]

@pulumi.output_type
class GetSubscribersResult:
    """
    A collection of values returned by getSubscribers.
    """
    def __init__(__self__, compartment_id=None, display_name=None, filters=None, id=None, state=None, subscriber_collections=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if subscriber_collections and not isinstance(subscriber_collections, list):
            raise TypeError("Expected argument 'subscriber_collections' to be a list")
        pulumi.set(__self__, "subscriber_collections", subscriber_collections)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[_builtins.str]:
        """
        A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetSubscribersFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[_builtins.str]:
        """
        The current state of the subscriber.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="subscriberCollections")
    def subscriber_collections(self) -> Sequence['outputs.GetSubscribersSubscriberCollectionResult']:
        """
        The list of subscriber_collection.
        """
        return pulumi.get(self, "subscriber_collections")


class AwaitableGetSubscribersResult(GetSubscribersResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetSubscribersResult(
            compartment_id=self.compartment_id,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            state=self.state,
            subscriber_collections=self.subscriber_collections)


def get_subscribers(compartment_id: Optional[_builtins.str] = None,
                    display_name: Optional[_builtins.str] = None,
                    filters: Optional[Sequence[Union['GetSubscribersFilterArgs', 'GetSubscribersFilterArgsDict']]] = None,
                    state: Optional[_builtins.str] = None,
                    opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetSubscribersResult:
    """
    This data source provides the list of Subscribers in Oracle Cloud Infrastructure API Gateway service.

    Returns a list of subscribers.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_subscribers = oci.ApiGateway.get_subscribers(compartment_id=compartment_id,
        display_name=subscriber_display_name,
        state=subscriber_state)
    ```


    :param _builtins.str compartment_id: The ocid of the compartment in which to list resources.
    :param _builtins.str display_name: A user-friendly name. Does not have to be unique, and it's changeable.  Example: `My new resource`
    :param _builtins.str state: A filter to return only resources that match the given lifecycle state. Example: `ACTIVE`
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['state'] = state
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:ApiGateway/getSubscribers:getSubscribers', __args__, opts=opts, typ=GetSubscribersResult).value

    return AwaitableGetSubscribersResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        display_name=pulumi.get(__ret__, 'display_name'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        state=pulumi.get(__ret__, 'state'),
        subscriber_collections=pulumi.get(__ret__, 'subscriber_collections'))
def get_subscribers_output(compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                           display_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                           filters: Optional[pulumi.Input[Optional[Sequence[Union['GetSubscribersFilterArgs', 'GetSubscribersFilterArgsDict']]]]] = None,
                           state: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                           opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetSubscribersResult]:
    """
    This data source provides the list of Subscribers in Oracle Cloud Infrastructure API Gateway service.

    Returns a list of subscribers.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_subscribers = oci.ApiGateway.get_subscribers(compartment_id=compartment_id,
        display_name=subscriber_display_name,
        state=subscriber_state)
    ```


    :param _builtins.str compartment_id: The ocid of the compartment in which to list resources.
    :param _builtins.str display_name: A user-friendly name. Does not have to be unique, and it's changeable.  Example: `My new resource`
    :param _builtins.str state: A filter to return only resources that match the given lifecycle state. Example: `ACTIVE`
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['state'] = state
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:ApiGateway/getSubscribers:getSubscribers', __args__, opts=opts, typ=GetSubscribersResult)
    return __ret__.apply(lambda __response__: GetSubscribersResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        display_name=pulumi.get(__response__, 'display_name'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        state=pulumi.get(__response__, 'state'),
        subscriber_collections=pulumi.get(__response__, 'subscriber_collections')))
