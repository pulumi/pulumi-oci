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
    'GetSubscribedServicesResult',
    'AwaitableGetSubscribedServicesResult',
    'get_subscribed_services',
    'get_subscribed_services_output',
]

@pulumi.output_type
class GetSubscribedServicesResult:
    """
    A collection of values returned by getSubscribedServices.
    """
    def __init__(__self__, compartment_id=None, filters=None, id=None, order_line_id=None, status=None, subscribed_services=None, subscription_id=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if order_line_id and not isinstance(order_line_id, str):
            raise TypeError("Expected argument 'order_line_id' to be a str")
        pulumi.set(__self__, "order_line_id", order_line_id)
        if status and not isinstance(status, str):
            raise TypeError("Expected argument 'status' to be a str")
        pulumi.set(__self__, "status", status)
        if subscribed_services and not isinstance(subscribed_services, list):
            raise TypeError("Expected argument 'subscribed_services' to be a list")
        pulumi.set(__self__, "subscribed_services", subscribed_services)
        if subscription_id and not isinstance(subscription_id, str):
            raise TypeError("Expected argument 'subscription_id' to be a str")
        pulumi.set(__self__, "subscription_id", subscription_id)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetSubscribedServicesFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="orderLineId")
    def order_line_id(self) -> Optional[str]:
        """
        Sales Order Line Id associated to the subscribed service
        """
        return pulumi.get(self, "order_line_id")

    @property
    @pulumi.getter
    def status(self) -> Optional[str]:
        """
        Subscribed service status
        """
        return pulumi.get(self, "status")

    @property
    @pulumi.getter(name="subscribedServices")
    def subscribed_services(self) -> Sequence['outputs.GetSubscribedServicesSubscribedServiceResult']:
        """
        The list of subscribed_services.
        """
        return pulumi.get(self, "subscribed_services")

    @property
    @pulumi.getter(name="subscriptionId")
    def subscription_id(self) -> str:
        """
        Subscription ID associated to the subscribed service
        """
        return pulumi.get(self, "subscription_id")


class AwaitableGetSubscribedServicesResult(GetSubscribedServicesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetSubscribedServicesResult(
            compartment_id=self.compartment_id,
            filters=self.filters,
            id=self.id,
            order_line_id=self.order_line_id,
            status=self.status,
            subscribed_services=self.subscribed_services,
            subscription_id=self.subscription_id)


def get_subscribed_services(compartment_id: Optional[str] = None,
                            filters: Optional[Sequence[pulumi.InputType['GetSubscribedServicesFilterArgs']]] = None,
                            order_line_id: Optional[str] = None,
                            status: Optional[str] = None,
                            subscription_id: Optional[str] = None,
                            opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetSubscribedServicesResult:
    """
    This data source provides the list of Subscribed Services in Oracle Cloud Infrastructure Onesubscription service.

    This list API returns all subscribed services for given Subscription ID

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_subscribed_services = oci.OneSubsription.get_subscribed_services(compartment_id=var["compartment_id"],
        subscription_id=oci_onesubscription_subscription["test_subscription"]["id"],
        order_line_id=oci_onesubscription_order_line["test_order_line"]["id"],
        status=var["subscribed_service_status"])
    ```


    :param str compartment_id: The OCID of the root compartment.
    :param str order_line_id: Order Line identifier at subscribed service level . This identifier is originated in Order Management module. Default is null.
    :param str status: This param is used to filter subscribed services based on its status
    :param str subscription_id: Line level Subscription Id
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    __args__['orderLineId'] = order_line_id
    __args__['status'] = status
    __args__['subscriptionId'] = subscription_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:OneSubsription/getSubscribedServices:getSubscribedServices', __args__, opts=opts, typ=GetSubscribedServicesResult).value

    return AwaitableGetSubscribedServicesResult(
        compartment_id=__ret__.compartment_id,
        filters=__ret__.filters,
        id=__ret__.id,
        order_line_id=__ret__.order_line_id,
        status=__ret__.status,
        subscribed_services=__ret__.subscribed_services,
        subscription_id=__ret__.subscription_id)


@_utilities.lift_output_func(get_subscribed_services)
def get_subscribed_services_output(compartment_id: Optional[pulumi.Input[str]] = None,
                                   filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetSubscribedServicesFilterArgs']]]]] = None,
                                   order_line_id: Optional[pulumi.Input[Optional[str]]] = None,
                                   status: Optional[pulumi.Input[Optional[str]]] = None,
                                   subscription_id: Optional[pulumi.Input[str]] = None,
                                   opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetSubscribedServicesResult]:
    """
    This data source provides the list of Subscribed Services in Oracle Cloud Infrastructure Onesubscription service.

    This list API returns all subscribed services for given Subscription ID

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_subscribed_services = oci.OneSubsription.get_subscribed_services(compartment_id=var["compartment_id"],
        subscription_id=oci_onesubscription_subscription["test_subscription"]["id"],
        order_line_id=oci_onesubscription_order_line["test_order_line"]["id"],
        status=var["subscribed_service_status"])
    ```


    :param str compartment_id: The OCID of the root compartment.
    :param str order_line_id: Order Line identifier at subscribed service level . This identifier is originated in Order Management module. Default is null.
    :param str status: This param is used to filter subscribed services based on its status
    :param str subscription_id: Line level Subscription Id
    """
    ...