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

__all__ = [
    'GetSubscriptionsResult',
    'AwaitableGetSubscriptionsResult',
    'get_subscriptions',
    'get_subscriptions_output',
]

@pulumi.output_type
class GetSubscriptionsResult:
    """
    A collection of values returned by getSubscriptions.
    """
    def __init__(__self__, buyer_email=None, compartment_id=None, filters=None, id=None, is_commit_info_required=None, plan_number=None, subscription_id=None, subscriptions=None, x_one_gateway_subscription_id=None, x_one_origin_region=None):
        if buyer_email and not isinstance(buyer_email, str):
            raise TypeError("Expected argument 'buyer_email' to be a str")
        pulumi.set(__self__, "buyer_email", buyer_email)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if is_commit_info_required and not isinstance(is_commit_info_required, bool):
            raise TypeError("Expected argument 'is_commit_info_required' to be a bool")
        pulumi.set(__self__, "is_commit_info_required", is_commit_info_required)
        if plan_number and not isinstance(plan_number, str):
            raise TypeError("Expected argument 'plan_number' to be a str")
        pulumi.set(__self__, "plan_number", plan_number)
        if subscription_id and not isinstance(subscription_id, str):
            raise TypeError("Expected argument 'subscription_id' to be a str")
        pulumi.set(__self__, "subscription_id", subscription_id)
        if subscriptions and not isinstance(subscriptions, list):
            raise TypeError("Expected argument 'subscriptions' to be a list")
        pulumi.set(__self__, "subscriptions", subscriptions)
        if x_one_gateway_subscription_id and not isinstance(x_one_gateway_subscription_id, str):
            raise TypeError("Expected argument 'x_one_gateway_subscription_id' to be a str")
        pulumi.set(__self__, "x_one_gateway_subscription_id", x_one_gateway_subscription_id)
        if x_one_origin_region and not isinstance(x_one_origin_region, str):
            raise TypeError("Expected argument 'x_one_origin_region' to be a str")
        pulumi.set(__self__, "x_one_origin_region", x_one_origin_region)

    @property
    @pulumi.getter(name="buyerEmail")
    def buyer_email(self) -> Optional[str]:
        return pulumi.get(self, "buyer_email")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetSubscriptionsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="isCommitInfoRequired")
    def is_commit_info_required(self) -> Optional[bool]:
        return pulumi.get(self, "is_commit_info_required")

    @property
    @pulumi.getter(name="planNumber")
    def plan_number(self) -> Optional[str]:
        return pulumi.get(self, "plan_number")

    @property
    @pulumi.getter(name="subscriptionId")
    def subscription_id(self) -> Optional[str]:
        return pulumi.get(self, "subscription_id")

    @property
    @pulumi.getter
    def subscriptions(self) -> Sequence['outputs.GetSubscriptionsSubscriptionResult']:
        """
        The list of subscriptions.
        """
        return pulumi.get(self, "subscriptions")

    @property
    @pulumi.getter(name="xOneGatewaySubscriptionId")
    def x_one_gateway_subscription_id(self) -> Optional[str]:
        return pulumi.get(self, "x_one_gateway_subscription_id")

    @property
    @pulumi.getter(name="xOneOriginRegion")
    def x_one_origin_region(self) -> Optional[str]:
        return pulumi.get(self, "x_one_origin_region")


class AwaitableGetSubscriptionsResult(GetSubscriptionsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetSubscriptionsResult(
            buyer_email=self.buyer_email,
            compartment_id=self.compartment_id,
            filters=self.filters,
            id=self.id,
            is_commit_info_required=self.is_commit_info_required,
            plan_number=self.plan_number,
            subscription_id=self.subscription_id,
            subscriptions=self.subscriptions,
            x_one_gateway_subscription_id=self.x_one_gateway_subscription_id,
            x_one_origin_region=self.x_one_origin_region)


def get_subscriptions(buyer_email: Optional[str] = None,
                      compartment_id: Optional[str] = None,
                      filters: Optional[Sequence[pulumi.InputType['GetSubscriptionsFilterArgs']]] = None,
                      is_commit_info_required: Optional[bool] = None,
                      plan_number: Optional[str] = None,
                      subscription_id: Optional[str] = None,
                      x_one_gateway_subscription_id: Optional[str] = None,
                      x_one_origin_region: Optional[str] = None,
                      opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetSubscriptionsResult:
    """
    This data source provides the list of Subscriptions in Oracle Cloud Infrastructure Osub Subscription service.

    This list API returns all subscriptions for a given plan number or subscription id or buyer email
    and provides additional parameters to include ratecard and commitment details.
    This API expects exactly one of the above mentioned parameters as input. If more than one parameters are provided the API will throw
    a 400 - invalid parameters exception and if no parameters are provided it will throw a 400 - missing parameter exception

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_subscriptions = oci.OsubSubscription.get_subscriptions(compartment_id=var["compartment_id"],
        buyer_email=var["subscription_buyer_email"],
        is_commit_info_required=var["subscription_is_commit_info_required"],
        plan_number=var["subscription_plan_number"],
        subscription_id=oci_osub_subscription_subscription["test_subscription"]["id"],
        x_one_gateway_subscription_id=var["subscription_x_one_gateway_subscription_id"],
        x_one_origin_region=var["subscription_x_one_origin_region"])
    ```


    :param str buyer_email: Buyer Email Id
    :param str compartment_id: The OCID of the compartment.
    :param bool is_commit_info_required: Boolean value to decide whether commitment services will be shown
    :param str plan_number: The Plan Number
    :param str subscription_id: Line level Subscription Id
    :param str x_one_gateway_subscription_id: This header is meant to be used only for internal purposes and will be ignored on any public request. The purpose of this header is  to help on Gateway to API calls identification.
    :param str x_one_origin_region: The Oracle Cloud Infrastructure home region name in case home region is not us-ashburn-1 (IAD), e.g. ap-mumbai-1, us-phoenix-1 etc.
    """
    __args__ = dict()
    __args__['buyerEmail'] = buyer_email
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    __args__['isCommitInfoRequired'] = is_commit_info_required
    __args__['planNumber'] = plan_number
    __args__['subscriptionId'] = subscription_id
    __args__['xOneGatewaySubscriptionId'] = x_one_gateway_subscription_id
    __args__['xOneOriginRegion'] = x_one_origin_region
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:OsubSubscription/getSubscriptions:getSubscriptions', __args__, opts=opts, typ=GetSubscriptionsResult).value

    return AwaitableGetSubscriptionsResult(
        buyer_email=__ret__.buyer_email,
        compartment_id=__ret__.compartment_id,
        filters=__ret__.filters,
        id=__ret__.id,
        is_commit_info_required=__ret__.is_commit_info_required,
        plan_number=__ret__.plan_number,
        subscription_id=__ret__.subscription_id,
        subscriptions=__ret__.subscriptions,
        x_one_gateway_subscription_id=__ret__.x_one_gateway_subscription_id,
        x_one_origin_region=__ret__.x_one_origin_region)


@_utilities.lift_output_func(get_subscriptions)
def get_subscriptions_output(buyer_email: Optional[pulumi.Input[Optional[str]]] = None,
                             compartment_id: Optional[pulumi.Input[str]] = None,
                             filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetSubscriptionsFilterArgs']]]]] = None,
                             is_commit_info_required: Optional[pulumi.Input[Optional[bool]]] = None,
                             plan_number: Optional[pulumi.Input[Optional[str]]] = None,
                             subscription_id: Optional[pulumi.Input[Optional[str]]] = None,
                             x_one_gateway_subscription_id: Optional[pulumi.Input[Optional[str]]] = None,
                             x_one_origin_region: Optional[pulumi.Input[Optional[str]]] = None,
                             opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetSubscriptionsResult]:
    """
    This data source provides the list of Subscriptions in Oracle Cloud Infrastructure Osub Subscription service.

    This list API returns all subscriptions for a given plan number or subscription id or buyer email
    and provides additional parameters to include ratecard and commitment details.
    This API expects exactly one of the above mentioned parameters as input. If more than one parameters are provided the API will throw
    a 400 - invalid parameters exception and if no parameters are provided it will throw a 400 - missing parameter exception

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_subscriptions = oci.OsubSubscription.get_subscriptions(compartment_id=var["compartment_id"],
        buyer_email=var["subscription_buyer_email"],
        is_commit_info_required=var["subscription_is_commit_info_required"],
        plan_number=var["subscription_plan_number"],
        subscription_id=oci_osub_subscription_subscription["test_subscription"]["id"],
        x_one_gateway_subscription_id=var["subscription_x_one_gateway_subscription_id"],
        x_one_origin_region=var["subscription_x_one_origin_region"])
    ```


    :param str buyer_email: Buyer Email Id
    :param str compartment_id: The OCID of the compartment.
    :param bool is_commit_info_required: Boolean value to decide whether commitment services will be shown
    :param str plan_number: The Plan Number
    :param str subscription_id: Line level Subscription Id
    :param str x_one_gateway_subscription_id: This header is meant to be used only for internal purposes and will be ignored on any public request. The purpose of this header is  to help on Gateway to API calls identification.
    :param str x_one_origin_region: The Oracle Cloud Infrastructure home region name in case home region is not us-ashburn-1 (IAD), e.g. ap-mumbai-1, us-phoenix-1 etc.
    """
    ...