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
    'GetRatecardsResult',
    'AwaitableGetRatecardsResult',
    'get_ratecards',
    'get_ratecards_output',
]

@pulumi.output_type
class GetRatecardsResult:
    """
    A collection of values returned by getRatecards.
    """
    def __init__(__self__, compartment_id=None, filters=None, id=None, part_number=None, rate_cards=None, subscription_id=None, time_from=None, time_to=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if part_number and not isinstance(part_number, str):
            raise TypeError("Expected argument 'part_number' to be a str")
        pulumi.set(__self__, "part_number", part_number)
        if rate_cards and not isinstance(rate_cards, list):
            raise TypeError("Expected argument 'rate_cards' to be a list")
        pulumi.set(__self__, "rate_cards", rate_cards)
        if subscription_id and not isinstance(subscription_id, str):
            raise TypeError("Expected argument 'subscription_id' to be a str")
        pulumi.set(__self__, "subscription_id", subscription_id)
        if time_from and not isinstance(time_from, str):
            raise TypeError("Expected argument 'time_from' to be a str")
        pulumi.set(__self__, "time_from", time_from)
        if time_to and not isinstance(time_to, str):
            raise TypeError("Expected argument 'time_to' to be a str")
        pulumi.set(__self__, "time_to", time_to)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetRatecardsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="partNumber")
    def part_number(self) -> Optional[str]:
        """
        Product part numner
        """
        return pulumi.get(self, "part_number")

    @property
    @pulumi.getter(name="rateCards")
    def rate_cards(self) -> Sequence['outputs.GetRatecardsRateCardResult']:
        """
        The list of rate_cards.
        """
        return pulumi.get(self, "rate_cards")

    @property
    @pulumi.getter(name="subscriptionId")
    def subscription_id(self) -> str:
        return pulumi.get(self, "subscription_id")

    @property
    @pulumi.getter(name="timeFrom")
    def time_from(self) -> Optional[str]:
        return pulumi.get(self, "time_from")

    @property
    @pulumi.getter(name="timeTo")
    def time_to(self) -> Optional[str]:
        return pulumi.get(self, "time_to")


class AwaitableGetRatecardsResult(GetRatecardsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetRatecardsResult(
            compartment_id=self.compartment_id,
            filters=self.filters,
            id=self.id,
            part_number=self.part_number,
            rate_cards=self.rate_cards,
            subscription_id=self.subscription_id,
            time_from=self.time_from,
            time_to=self.time_to)


def get_ratecards(compartment_id: Optional[str] = None,
                  filters: Optional[Sequence[pulumi.InputType['GetRatecardsFilterArgs']]] = None,
                  part_number: Optional[str] = None,
                  subscription_id: Optional[str] = None,
                  time_from: Optional[str] = None,
                  time_to: Optional[str] = None,
                  opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetRatecardsResult:
    """
    This data source provides the list of Ratecards in Oracle Cloud Infrastructure Onesubscription service.

    List API that returns all ratecards for given Subscription Id and Account ID (if provided) and
    for a particular date range

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_ratecards = oci.OneSubsription.get_ratecards(compartment_id=var["compartment_id"],
        subscription_id=oci_onesubscription_subscription["test_subscription"]["id"],
        part_number=var["ratecard_part_number"],
        time_from=var["ratecard_time_from"],
        time_to=var["ratecard_time_to"])
    ```


    :param str compartment_id: The OCID of the root compartment.
    :param str part_number: This param is used to get the rate card(s) filterd by the partNumber
    :param str subscription_id: Line level Subscription Id
    :param str time_from: This param is used to get the rate card(s) whose effective start date starts on or after a particular date
    :param str time_to: This param is used to get the rate card(s) whose effective end date ends on or before a particular date
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    __args__['partNumber'] = part_number
    __args__['subscriptionId'] = subscription_id
    __args__['timeFrom'] = time_from
    __args__['timeTo'] = time_to
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:OneSubsription/getRatecards:getRatecards', __args__, opts=opts, typ=GetRatecardsResult).value

    return AwaitableGetRatecardsResult(
        compartment_id=__ret__.compartment_id,
        filters=__ret__.filters,
        id=__ret__.id,
        part_number=__ret__.part_number,
        rate_cards=__ret__.rate_cards,
        subscription_id=__ret__.subscription_id,
        time_from=__ret__.time_from,
        time_to=__ret__.time_to)


@_utilities.lift_output_func(get_ratecards)
def get_ratecards_output(compartment_id: Optional[pulumi.Input[str]] = None,
                         filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetRatecardsFilterArgs']]]]] = None,
                         part_number: Optional[pulumi.Input[Optional[str]]] = None,
                         subscription_id: Optional[pulumi.Input[str]] = None,
                         time_from: Optional[pulumi.Input[Optional[str]]] = None,
                         time_to: Optional[pulumi.Input[Optional[str]]] = None,
                         opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetRatecardsResult]:
    """
    This data source provides the list of Ratecards in Oracle Cloud Infrastructure Onesubscription service.

    List API that returns all ratecards for given Subscription Id and Account ID (if provided) and
    for a particular date range

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_ratecards = oci.OneSubsription.get_ratecards(compartment_id=var["compartment_id"],
        subscription_id=oci_onesubscription_subscription["test_subscription"]["id"],
        part_number=var["ratecard_part_number"],
        time_from=var["ratecard_time_from"],
        time_to=var["ratecard_time_to"])
    ```


    :param str compartment_id: The OCID of the root compartment.
    :param str part_number: This param is used to get the rate card(s) filterd by the partNumber
    :param str subscription_id: Line level Subscription Id
    :param str time_from: This param is used to get the rate card(s) whose effective start date starts on or after a particular date
    :param str time_to: This param is used to get the rate card(s) whose effective end date ends on or before a particular date
    """
    ...