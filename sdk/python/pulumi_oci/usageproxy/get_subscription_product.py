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

__all__ = [
    'GetSubscriptionProductResult',
    'AwaitableGetSubscriptionProductResult',
    'get_subscription_product',
    'get_subscription_product_output',
]

@pulumi.output_type
class GetSubscriptionProductResult:
    """
    A collection of values returned by getSubscriptionProduct.
    """
    def __init__(__self__, id=None, items=None, producttype=None, subscription_id=None, tenancy_id=None, usage_period_key=None):
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if items and not isinstance(items, list):
            raise TypeError("Expected argument 'items' to be a list")
        pulumi.set(__self__, "items", items)
        if producttype and not isinstance(producttype, str):
            raise TypeError("Expected argument 'producttype' to be a str")
        pulumi.set(__self__, "producttype", producttype)
        if subscription_id and not isinstance(subscription_id, str):
            raise TypeError("Expected argument 'subscription_id' to be a str")
        pulumi.set(__self__, "subscription_id", subscription_id)
        if tenancy_id and not isinstance(tenancy_id, str):
            raise TypeError("Expected argument 'tenancy_id' to be a str")
        pulumi.set(__self__, "tenancy_id", tenancy_id)
        if usage_period_key and not isinstance(usage_period_key, str):
            raise TypeError("Expected argument 'usage_period_key' to be a str")
        pulumi.set(__self__, "usage_period_key", usage_period_key)

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def items(self) -> Sequence['outputs.GetSubscriptionProductItemResult']:
        """
        The list of product rewards summaries.
        """
        return pulumi.get(self, "items")

    @property
    @pulumi.getter
    def producttype(self) -> Optional[str]:
        return pulumi.get(self, "producttype")

    @property
    @pulumi.getter(name="subscriptionId")
    def subscription_id(self) -> str:
        return pulumi.get(self, "subscription_id")

    @property
    @pulumi.getter(name="tenancyId")
    def tenancy_id(self) -> str:
        return pulumi.get(self, "tenancy_id")

    @property
    @pulumi.getter(name="usagePeriodKey")
    def usage_period_key(self) -> str:
        return pulumi.get(self, "usage_period_key")


class AwaitableGetSubscriptionProductResult(GetSubscriptionProductResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetSubscriptionProductResult(
            id=self.id,
            items=self.items,
            producttype=self.producttype,
            subscription_id=self.subscription_id,
            tenancy_id=self.tenancy_id,
            usage_period_key=self.usage_period_key)


def get_subscription_product(producttype: Optional[str] = None,
                             subscription_id: Optional[str] = None,
                             tenancy_id: Optional[str] = None,
                             usage_period_key: Optional[str] = None,
                             opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetSubscriptionProductResult:
    """
    This data source provides details about a specific Subscription Product resource in Oracle Cloud Infrastructure Usage Proxy service.

    Provides product information that is specific to a reward usage period and its usage details.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_subscription_product = oci.UsageProxy.get_subscription_product(subscription_id=oci_ons_subscription["test_subscription"]["id"],
        tenancy_id=oci_identity_tenancy["test_tenancy"]["id"],
        usage_period_key=var["subscription_product_usage_period_key"],
        producttype=var["subscription_product_producttype"])
    ```


    :param str producttype: The field to specify the type of product.
    :param str subscription_id: The subscription ID for which rewards information is requested for.
    :param str tenancy_id: The OCID of the tenancy.
    :param str usage_period_key: The SPM Identifier for the usage period.
    """
    __args__ = dict()
    __args__['producttype'] = producttype
    __args__['subscriptionId'] = subscription_id
    __args__['tenancyId'] = tenancy_id
    __args__['usagePeriodKey'] = usage_period_key
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:UsageProxy/getSubscriptionProduct:getSubscriptionProduct', __args__, opts=opts, typ=GetSubscriptionProductResult).value

    return AwaitableGetSubscriptionProductResult(
        id=__ret__.id,
        items=__ret__.items,
        producttype=__ret__.producttype,
        subscription_id=__ret__.subscription_id,
        tenancy_id=__ret__.tenancy_id,
        usage_period_key=__ret__.usage_period_key)


@_utilities.lift_output_func(get_subscription_product)
def get_subscription_product_output(producttype: Optional[pulumi.Input[Optional[str]]] = None,
                                    subscription_id: Optional[pulumi.Input[str]] = None,
                                    tenancy_id: Optional[pulumi.Input[str]] = None,
                                    usage_period_key: Optional[pulumi.Input[str]] = None,
                                    opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetSubscriptionProductResult]:
    """
    This data source provides details about a specific Subscription Product resource in Oracle Cloud Infrastructure Usage Proxy service.

    Provides product information that is specific to a reward usage period and its usage details.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_subscription_product = oci.UsageProxy.get_subscription_product(subscription_id=oci_ons_subscription["test_subscription"]["id"],
        tenancy_id=oci_identity_tenancy["test_tenancy"]["id"],
        usage_period_key=var["subscription_product_usage_period_key"],
        producttype=var["subscription_product_producttype"])
    ```


    :param str producttype: The field to specify the type of product.
    :param str subscription_id: The subscription ID for which rewards information is requested for.
    :param str tenancy_id: The OCID of the tenancy.
    :param str usage_period_key: The SPM Identifier for the usage period.
    """
    ...