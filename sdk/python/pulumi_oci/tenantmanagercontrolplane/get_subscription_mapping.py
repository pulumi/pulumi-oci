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
    'GetSubscriptionMappingResult',
    'AwaitableGetSubscriptionMappingResult',
    'get_subscription_mapping',
    'get_subscription_mapping_output',
]

@pulumi.output_type
class GetSubscriptionMappingResult:
    """
    A collection of values returned by getSubscriptionMapping.
    """
    def __init__(__self__, compartment_id=None, id=None, is_explicitly_assigned=None, state=None, subscription_id=None, subscription_mapping_id=None, time_created=None, time_terminated=None, time_updated=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if is_explicitly_assigned and not isinstance(is_explicitly_assigned, bool):
            raise TypeError("Expected argument 'is_explicitly_assigned' to be a bool")
        pulumi.set(__self__, "is_explicitly_assigned", is_explicitly_assigned)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if subscription_id and not isinstance(subscription_id, str):
            raise TypeError("Expected argument 'subscription_id' to be a str")
        pulumi.set(__self__, "subscription_id", subscription_id)
        if subscription_mapping_id and not isinstance(subscription_mapping_id, str):
            raise TypeError("Expected argument 'subscription_mapping_id' to be a str")
        pulumi.set(__self__, "subscription_mapping_id", subscription_mapping_id)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_terminated and not isinstance(time_terminated, str):
            raise TypeError("Expected argument 'time_terminated' to be a str")
        pulumi.set(__self__, "time_terminated", time_terminated)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        OCID of the compartment. Always a tenancy OCID.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        OCID of the mapping between subscription and compartment identified by the tenancy.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="isExplicitlyAssigned")
    def is_explicitly_assigned(self) -> _builtins.bool:
        """
        Denotes if the subscription is explicity assigned to the root compartment or tenancy.
        """
        return pulumi.get(self, "is_explicitly_assigned")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        Lifecycle state of the subscriptionMapping.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="subscriptionId")
    def subscription_id(self) -> _builtins.str:
        """
        OCID of the subscription.
        """
        return pulumi.get(self, "subscription_id")

    @_builtins.property
    @pulumi.getter(name="subscriptionMappingId")
    def subscription_mapping_id(self) -> _builtins.str:
        return pulumi.get(self, "subscription_mapping_id")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        Date-time when subscription mapping was created.
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeTerminated")
    def time_terminated(self) -> _builtins.str:
        """
        Date-time when subscription mapping was terminated.
        """
        return pulumi.get(self, "time_terminated")

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> _builtins.str:
        """
        Date-time when subscription mapping was updated.
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetSubscriptionMappingResult(GetSubscriptionMappingResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetSubscriptionMappingResult(
            compartment_id=self.compartment_id,
            id=self.id,
            is_explicitly_assigned=self.is_explicitly_assigned,
            state=self.state,
            subscription_id=self.subscription_id,
            subscription_mapping_id=self.subscription_mapping_id,
            time_created=self.time_created,
            time_terminated=self.time_terminated,
            time_updated=self.time_updated)


def get_subscription_mapping(subscription_mapping_id: Optional[_builtins.str] = None,
                             opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetSubscriptionMappingResult:
    """
    This data source provides details about a specific Subscription Mapping resource in Oracle Cloud Infrastructure Tenantmanagercontrolplane service.

    Get the subscription mapping details by subscription mapping ID.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_subscription_mapping = oci.Tenantmanagercontrolplane.get_subscription_mapping(subscription_mapping_id=test_subscription_mapping_oci_tenantmanagercontrolplane_subscription_mapping["id"])
    ```


    :param _builtins.str subscription_mapping_id: OCID of the subscriptionMappingId.
    """
    __args__ = dict()
    __args__['subscriptionMappingId'] = subscription_mapping_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Tenantmanagercontrolplane/getSubscriptionMapping:getSubscriptionMapping', __args__, opts=opts, typ=GetSubscriptionMappingResult).value

    return AwaitableGetSubscriptionMappingResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        id=pulumi.get(__ret__, 'id'),
        is_explicitly_assigned=pulumi.get(__ret__, 'is_explicitly_assigned'),
        state=pulumi.get(__ret__, 'state'),
        subscription_id=pulumi.get(__ret__, 'subscription_id'),
        subscription_mapping_id=pulumi.get(__ret__, 'subscription_mapping_id'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_terminated=pulumi.get(__ret__, 'time_terminated'),
        time_updated=pulumi.get(__ret__, 'time_updated'))
def get_subscription_mapping_output(subscription_mapping_id: Optional[pulumi.Input[_builtins.str]] = None,
                                    opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetSubscriptionMappingResult]:
    """
    This data source provides details about a specific Subscription Mapping resource in Oracle Cloud Infrastructure Tenantmanagercontrolplane service.

    Get the subscription mapping details by subscription mapping ID.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_subscription_mapping = oci.Tenantmanagercontrolplane.get_subscription_mapping(subscription_mapping_id=test_subscription_mapping_oci_tenantmanagercontrolplane_subscription_mapping["id"])
    ```


    :param _builtins.str subscription_mapping_id: OCID of the subscriptionMappingId.
    """
    __args__ = dict()
    __args__['subscriptionMappingId'] = subscription_mapping_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Tenantmanagercontrolplane/getSubscriptionMapping:getSubscriptionMapping', __args__, opts=opts, typ=GetSubscriptionMappingResult)
    return __ret__.apply(lambda __response__: GetSubscriptionMappingResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        id=pulumi.get(__response__, 'id'),
        is_explicitly_assigned=pulumi.get(__response__, 'is_explicitly_assigned'),
        state=pulumi.get(__response__, 'state'),
        subscription_id=pulumi.get(__response__, 'subscription_id'),
        subscription_mapping_id=pulumi.get(__response__, 'subscription_mapping_id'),
        time_created=pulumi.get(__response__, 'time_created'),
        time_terminated=pulumi.get(__response__, 'time_terminated'),
        time_updated=pulumi.get(__response__, 'time_updated')))
