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
    'GetSubscriberResult',
    'AwaitableGetSubscriberResult',
    'get_subscriber',
    'get_subscriber_output',
]

@pulumi.output_type
class GetSubscriberResult:
    """
    A collection of values returned by getSubscriber.
    """
    def __init__(__self__, clients=None, compartment_id=None, defined_tags=None, display_name=None, freeform_tags=None, id=None, lifecycle_details=None, state=None, subscriber_id=None, time_created=None, time_updated=None, usage_plans=None):
        if clients and not isinstance(clients, list):
            raise TypeError("Expected argument 'clients' to be a list")
        pulumi.set(__self__, "clients", clients)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if subscriber_id and not isinstance(subscriber_id, str):
            raise TypeError("Expected argument 'subscriber_id' to be a str")
        pulumi.set(__self__, "subscriber_id", subscriber_id)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)
        if usage_plans and not isinstance(usage_plans, list):
            raise TypeError("Expected argument 'usage_plans' to be a list")
        pulumi.set(__self__, "usage_plans", usage_plans)

    @_builtins.property
    @pulumi.getter
    def clients(self) -> Sequence['outputs.GetSubscriberClientResult']:
        """
        The clients belonging to this subscriber.
        """
        return pulumi.get(self, "clients")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, _builtins.str]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> _builtins.str:
        """
        A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, _builtins.str]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> _builtins.str:
        """
        A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
        """
        return pulumi.get(self, "lifecycle_details")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current state of the subscriber.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="subscriberId")
    def subscriber_id(self) -> _builtins.str:
        return pulumi.get(self, "subscriber_id")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        The time this resource was created. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> _builtins.str:
        """
        The time this resource was last updated. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_updated")

    @_builtins.property
    @pulumi.getter(name="usagePlans")
    def usage_plans(self) -> Sequence[_builtins.str]:
        """
        An array of [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)s of usage plan resources.
        """
        return pulumi.get(self, "usage_plans")


class AwaitableGetSubscriberResult(GetSubscriberResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetSubscriberResult(
            clients=self.clients,
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            lifecycle_details=self.lifecycle_details,
            state=self.state,
            subscriber_id=self.subscriber_id,
            time_created=self.time_created,
            time_updated=self.time_updated,
            usage_plans=self.usage_plans)


def get_subscriber(subscriber_id: Optional[_builtins.str] = None,
                   opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetSubscriberResult:
    """
    This data source provides details about a specific Subscriber resource in Oracle Cloud Infrastructure API Gateway service.

    Gets a subscriber by identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_subscriber = oci.ApiGateway.get_subscriber(subscriber_id=test_subscriber_oci_apigateway_subscriber["id"])
    ```


    :param _builtins.str subscriber_id: The ocid of the subscriber.
    """
    __args__ = dict()
    __args__['subscriberId'] = subscriber_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:ApiGateway/getSubscriber:getSubscriber', __args__, opts=opts, typ=GetSubscriberResult).value

    return AwaitableGetSubscriberResult(
        clients=pulumi.get(__ret__, 'clients'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        display_name=pulumi.get(__ret__, 'display_name'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        id=pulumi.get(__ret__, 'id'),
        lifecycle_details=pulumi.get(__ret__, 'lifecycle_details'),
        state=pulumi.get(__ret__, 'state'),
        subscriber_id=pulumi.get(__ret__, 'subscriber_id'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_updated=pulumi.get(__ret__, 'time_updated'),
        usage_plans=pulumi.get(__ret__, 'usage_plans'))
def get_subscriber_output(subscriber_id: Optional[pulumi.Input[_builtins.str]] = None,
                          opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetSubscriberResult]:
    """
    This data source provides details about a specific Subscriber resource in Oracle Cloud Infrastructure API Gateway service.

    Gets a subscriber by identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_subscriber = oci.ApiGateway.get_subscriber(subscriber_id=test_subscriber_oci_apigateway_subscriber["id"])
    ```


    :param _builtins.str subscriber_id: The ocid of the subscriber.
    """
    __args__ = dict()
    __args__['subscriberId'] = subscriber_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:ApiGateway/getSubscriber:getSubscriber', __args__, opts=opts, typ=GetSubscriberResult)
    return __ret__.apply(lambda __response__: GetSubscriberResult(
        clients=pulumi.get(__response__, 'clients'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        display_name=pulumi.get(__response__, 'display_name'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        id=pulumi.get(__response__, 'id'),
        lifecycle_details=pulumi.get(__response__, 'lifecycle_details'),
        state=pulumi.get(__response__, 'state'),
        subscriber_id=pulumi.get(__response__, 'subscriber_id'),
        time_created=pulumi.get(__response__, 'time_created'),
        time_updated=pulumi.get(__response__, 'time_updated'),
        usage_plans=pulumi.get(__response__, 'usage_plans')))
