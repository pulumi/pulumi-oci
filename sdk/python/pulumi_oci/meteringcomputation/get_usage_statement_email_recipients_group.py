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
    'GetUsageStatementEmailRecipientsGroupResult',
    'AwaitableGetUsageStatementEmailRecipientsGroupResult',
    'get_usage_statement_email_recipients_group',
    'get_usage_statement_email_recipients_group_output',
]

@pulumi.output_type
class GetUsageStatementEmailRecipientsGroupResult:
    """
    A collection of values returned by getUsageStatementEmailRecipientsGroup.
    """
    def __init__(__self__, compartment_id=None, email_recipients_group_id=None, id=None, recipients_lists=None, state=None, subscription_id=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if email_recipients_group_id and not isinstance(email_recipients_group_id, str):
            raise TypeError("Expected argument 'email_recipients_group_id' to be a str")
        pulumi.set(__self__, "email_recipients_group_id", email_recipients_group_id)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if recipients_lists and not isinstance(recipients_lists, list):
            raise TypeError("Expected argument 'recipients_lists' to be a list")
        pulumi.set(__self__, "recipients_lists", recipients_lists)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if subscription_id and not isinstance(subscription_id, str):
            raise TypeError("Expected argument 'subscription_id' to be a str")
        pulumi.set(__self__, "subscription_id", subscription_id)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The customer tenancy OCID.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="emailRecipientsGroupId")
    def email_recipients_group_id(self) -> _builtins.str:
        return pulumi.get(self, "email_recipients_group_id")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The usage statement email recipients group OCID.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="recipientsLists")
    def recipients_lists(self) -> Sequence['outputs.GetUsageStatementEmailRecipientsGroupRecipientsListResult']:
        """
        The list of recipients that will receive usage statement emails.
        """
        return pulumi.get(self, "recipients_lists")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The email recipients group lifecycle state.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="subscriptionId")
    def subscription_id(self) -> _builtins.str:
        return pulumi.get(self, "subscription_id")


class AwaitableGetUsageStatementEmailRecipientsGroupResult(GetUsageStatementEmailRecipientsGroupResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetUsageStatementEmailRecipientsGroupResult(
            compartment_id=self.compartment_id,
            email_recipients_group_id=self.email_recipients_group_id,
            id=self.id,
            recipients_lists=self.recipients_lists,
            state=self.state,
            subscription_id=self.subscription_id)


def get_usage_statement_email_recipients_group(compartment_id: Optional[_builtins.str] = None,
                                               email_recipients_group_id: Optional[_builtins.str] = None,
                                               subscription_id: Optional[_builtins.str] = None,
                                               opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetUsageStatementEmailRecipientsGroupResult:
    """
    This data source provides details about a specific Usage Statement Email Recipients Group resource in Oracle Cloud Infrastructure Metering Computation service.

    Returns the saved usage statement email recipients group.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_usage_statement_email_recipients_group = oci.MeteringComputation.get_usage_statement_email_recipients_group(compartment_id=compartment_id,
        email_recipients_group_id=test_group["id"],
        subscription_id=test_subscription["id"])
    ```


    :param _builtins.str compartment_id: The compartment ID in which to list resources.
    :param _builtins.str email_recipients_group_id: The email recipients group OCID.
    :param _builtins.str subscription_id: The usage statement subscription unique OCID.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['emailRecipientsGroupId'] = email_recipients_group_id
    __args__['subscriptionId'] = subscription_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:MeteringComputation/getUsageStatementEmailRecipientsGroup:getUsageStatementEmailRecipientsGroup', __args__, opts=opts, typ=GetUsageStatementEmailRecipientsGroupResult).value

    return AwaitableGetUsageStatementEmailRecipientsGroupResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        email_recipients_group_id=pulumi.get(__ret__, 'email_recipients_group_id'),
        id=pulumi.get(__ret__, 'id'),
        recipients_lists=pulumi.get(__ret__, 'recipients_lists'),
        state=pulumi.get(__ret__, 'state'),
        subscription_id=pulumi.get(__ret__, 'subscription_id'))
def get_usage_statement_email_recipients_group_output(compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                                                      email_recipients_group_id: Optional[pulumi.Input[_builtins.str]] = None,
                                                      subscription_id: Optional[pulumi.Input[_builtins.str]] = None,
                                                      opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetUsageStatementEmailRecipientsGroupResult]:
    """
    This data source provides details about a specific Usage Statement Email Recipients Group resource in Oracle Cloud Infrastructure Metering Computation service.

    Returns the saved usage statement email recipients group.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_usage_statement_email_recipients_group = oci.MeteringComputation.get_usage_statement_email_recipients_group(compartment_id=compartment_id,
        email_recipients_group_id=test_group["id"],
        subscription_id=test_subscription["id"])
    ```


    :param _builtins.str compartment_id: The compartment ID in which to list resources.
    :param _builtins.str email_recipients_group_id: The email recipients group OCID.
    :param _builtins.str subscription_id: The usage statement subscription unique OCID.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['emailRecipientsGroupId'] = email_recipients_group_id
    __args__['subscriptionId'] = subscription_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:MeteringComputation/getUsageStatementEmailRecipientsGroup:getUsageStatementEmailRecipientsGroup', __args__, opts=opts, typ=GetUsageStatementEmailRecipientsGroupResult)
    return __ret__.apply(lambda __response__: GetUsageStatementEmailRecipientsGroupResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        email_recipients_group_id=pulumi.get(__response__, 'email_recipients_group_id'),
        id=pulumi.get(__response__, 'id'),
        recipients_lists=pulumi.get(__response__, 'recipients_lists'),
        state=pulumi.get(__response__, 'state'),
        subscription_id=pulumi.get(__response__, 'subscription_id')))
