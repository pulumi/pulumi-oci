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
    'GetSubscriptionRedemptionResult',
    'AwaitableGetSubscriptionRedemptionResult',
    'get_subscription_redemption',
    'get_subscription_redemption_output',
]

@pulumi.output_type
class GetSubscriptionRedemptionResult:
    """
    A collection of values returned by getSubscriptionRedemption.
    """
    def __init__(__self__, id=None, items=None, subscription_id=None, tenancy_id=None, time_redeemed_greater_than_or_equal_to=None, time_redeemed_less_than=None):
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if items and not isinstance(items, list):
            raise TypeError("Expected argument 'items' to be a list")
        pulumi.set(__self__, "items", items)
        if subscription_id and not isinstance(subscription_id, str):
            raise TypeError("Expected argument 'subscription_id' to be a str")
        pulumi.set(__self__, "subscription_id", subscription_id)
        if tenancy_id and not isinstance(tenancy_id, str):
            raise TypeError("Expected argument 'tenancy_id' to be a str")
        pulumi.set(__self__, "tenancy_id", tenancy_id)
        if time_redeemed_greater_than_or_equal_to and not isinstance(time_redeemed_greater_than_or_equal_to, str):
            raise TypeError("Expected argument 'time_redeemed_greater_than_or_equal_to' to be a str")
        pulumi.set(__self__, "time_redeemed_greater_than_or_equal_to", time_redeemed_greater_than_or_equal_to)
        if time_redeemed_less_than and not isinstance(time_redeemed_less_than, str):
            raise TypeError("Expected argument 'time_redeemed_less_than' to be a str")
        pulumi.set(__self__, "time_redeemed_less_than", time_redeemed_less_than)

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter
    def items(self) -> Sequence['outputs.GetSubscriptionRedemptionItemResult']:
        """
        The list of redemption summary.
        """
        return pulumi.get(self, "items")

    @_builtins.property
    @pulumi.getter(name="subscriptionId")
    def subscription_id(self) -> _builtins.str:
        return pulumi.get(self, "subscription_id")

    @_builtins.property
    @pulumi.getter(name="tenancyId")
    def tenancy_id(self) -> _builtins.str:
        return pulumi.get(self, "tenancy_id")

    @_builtins.property
    @pulumi.getter(name="timeRedeemedGreaterThanOrEqualTo")
    def time_redeemed_greater_than_or_equal_to(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "time_redeemed_greater_than_or_equal_to")

    @_builtins.property
    @pulumi.getter(name="timeRedeemedLessThan")
    def time_redeemed_less_than(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "time_redeemed_less_than")


class AwaitableGetSubscriptionRedemptionResult(GetSubscriptionRedemptionResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetSubscriptionRedemptionResult(
            id=self.id,
            items=self.items,
            subscription_id=self.subscription_id,
            tenancy_id=self.tenancy_id,
            time_redeemed_greater_than_or_equal_to=self.time_redeemed_greater_than_or_equal_to,
            time_redeemed_less_than=self.time_redeemed_less_than)


def get_subscription_redemption(subscription_id: Optional[_builtins.str] = None,
                                tenancy_id: Optional[_builtins.str] = None,
                                time_redeemed_greater_than_or_equal_to: Optional[_builtins.str] = None,
                                time_redeemed_less_than: Optional[_builtins.str] = None,
                                opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetSubscriptionRedemptionResult:
    """
    This data source provides details about a specific Subscription Redemption resource in Oracle Cloud Infrastructure Usage Proxy service.

    Returns the list of redemption for the subscription ID.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_subscription_redemption = oci.UsageProxy.get_subscription_redemption(subscription_id=test_subscription["id"],
        tenancy_id=test_tenancy["id"],
        time_redeemed_greater_than_or_equal_to=subscription_redemption_time_redeemed_greater_than_or_equal_to,
        time_redeemed_less_than=subscription_redemption_time_redeemed_less_than)
    ```


    :param _builtins.str subscription_id: The subscription ID for which rewards information is requested for.
    :param _builtins.str tenancy_id: The OCID of the tenancy.
    :param _builtins.str time_redeemed_greater_than_or_equal_to: The starting redeemed date filter for the redemption history.
    :param _builtins.str time_redeemed_less_than: The ending redeemed date filter for the redemption history.
    """
    __args__ = dict()
    __args__['subscriptionId'] = subscription_id
    __args__['tenancyId'] = tenancy_id
    __args__['timeRedeemedGreaterThanOrEqualTo'] = time_redeemed_greater_than_or_equal_to
    __args__['timeRedeemedLessThan'] = time_redeemed_less_than
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:UsageProxy/getSubscriptionRedemption:getSubscriptionRedemption', __args__, opts=opts, typ=GetSubscriptionRedemptionResult).value

    return AwaitableGetSubscriptionRedemptionResult(
        id=pulumi.get(__ret__, 'id'),
        items=pulumi.get(__ret__, 'items'),
        subscription_id=pulumi.get(__ret__, 'subscription_id'),
        tenancy_id=pulumi.get(__ret__, 'tenancy_id'),
        time_redeemed_greater_than_or_equal_to=pulumi.get(__ret__, 'time_redeemed_greater_than_or_equal_to'),
        time_redeemed_less_than=pulumi.get(__ret__, 'time_redeemed_less_than'))
def get_subscription_redemption_output(subscription_id: Optional[pulumi.Input[_builtins.str]] = None,
                                       tenancy_id: Optional[pulumi.Input[_builtins.str]] = None,
                                       time_redeemed_greater_than_or_equal_to: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                       time_redeemed_less_than: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                       opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetSubscriptionRedemptionResult]:
    """
    This data source provides details about a specific Subscription Redemption resource in Oracle Cloud Infrastructure Usage Proxy service.

    Returns the list of redemption for the subscription ID.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_subscription_redemption = oci.UsageProxy.get_subscription_redemption(subscription_id=test_subscription["id"],
        tenancy_id=test_tenancy["id"],
        time_redeemed_greater_than_or_equal_to=subscription_redemption_time_redeemed_greater_than_or_equal_to,
        time_redeemed_less_than=subscription_redemption_time_redeemed_less_than)
    ```


    :param _builtins.str subscription_id: The subscription ID for which rewards information is requested for.
    :param _builtins.str tenancy_id: The OCID of the tenancy.
    :param _builtins.str time_redeemed_greater_than_or_equal_to: The starting redeemed date filter for the redemption history.
    :param _builtins.str time_redeemed_less_than: The ending redeemed date filter for the redemption history.
    """
    __args__ = dict()
    __args__['subscriptionId'] = subscription_id
    __args__['tenancyId'] = tenancy_id
    __args__['timeRedeemedGreaterThanOrEqualTo'] = time_redeemed_greater_than_or_equal_to
    __args__['timeRedeemedLessThan'] = time_redeemed_less_than
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:UsageProxy/getSubscriptionRedemption:getSubscriptionRedemption', __args__, opts=opts, typ=GetSubscriptionRedemptionResult)
    return __ret__.apply(lambda __response__: GetSubscriptionRedemptionResult(
        id=pulumi.get(__response__, 'id'),
        items=pulumi.get(__response__, 'items'),
        subscription_id=pulumi.get(__response__, 'subscription_id'),
        tenancy_id=pulumi.get(__response__, 'tenancy_id'),
        time_redeemed_greater_than_or_equal_to=pulumi.get(__response__, 'time_redeemed_greater_than_or_equal_to'),
        time_redeemed_less_than=pulumi.get(__response__, 'time_redeemed_less_than')))
