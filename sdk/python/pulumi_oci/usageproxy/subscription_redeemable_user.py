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

__all__ = ['SubscriptionRedeemableUserArgs', 'SubscriptionRedeemableUser']

@pulumi.input_type
class SubscriptionRedeemableUserArgs:
    def __init__(__self__, *,
                 items: pulumi.Input[Sequence[pulumi.Input['SubscriptionRedeemableUserItemArgs']]],
                 subscription_id: pulumi.Input[str],
                 tenancy_id: pulumi.Input[str],
                 user_id: Optional[pulumi.Input[str]] = None):
        """
        The set of arguments for constructing a SubscriptionRedeemableUser resource.
        :param pulumi.Input[Sequence[pulumi.Input['SubscriptionRedeemableUserItemArgs']]] items: The list of new user to be added to the list of user that can redeem rewards.
        :param pulumi.Input[str] subscription_id: The subscription ID for which rewards information is requested for.
        :param pulumi.Input[str] tenancy_id: The OCID of the tenancy.
        :param pulumi.Input[str] user_id: The user ID of the person to send a copy of an email.
        """
        pulumi.set(__self__, "items", items)
        pulumi.set(__self__, "subscription_id", subscription_id)
        pulumi.set(__self__, "tenancy_id", tenancy_id)
        if user_id is not None:
            pulumi.set(__self__, "user_id", user_id)

    @property
    @pulumi.getter
    def items(self) -> pulumi.Input[Sequence[pulumi.Input['SubscriptionRedeemableUserItemArgs']]]:
        """
        The list of new user to be added to the list of user that can redeem rewards.
        """
        return pulumi.get(self, "items")

    @items.setter
    def items(self, value: pulumi.Input[Sequence[pulumi.Input['SubscriptionRedeemableUserItemArgs']]]):
        pulumi.set(self, "items", value)

    @property
    @pulumi.getter(name="subscriptionId")
    def subscription_id(self) -> pulumi.Input[str]:
        """
        The subscription ID for which rewards information is requested for.
        """
        return pulumi.get(self, "subscription_id")

    @subscription_id.setter
    def subscription_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "subscription_id", value)

    @property
    @pulumi.getter(name="tenancyId")
    def tenancy_id(self) -> pulumi.Input[str]:
        """
        The OCID of the tenancy.
        """
        return pulumi.get(self, "tenancy_id")

    @tenancy_id.setter
    def tenancy_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "tenancy_id", value)

    @property
    @pulumi.getter(name="userId")
    def user_id(self) -> Optional[pulumi.Input[str]]:
        """
        The user ID of the person to send a copy of an email.
        """
        return pulumi.get(self, "user_id")

    @user_id.setter
    def user_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "user_id", value)


@pulumi.input_type
class _SubscriptionRedeemableUserState:
    def __init__(__self__, *,
                 items: Optional[pulumi.Input[Sequence[pulumi.Input['SubscriptionRedeemableUserItemArgs']]]] = None,
                 subscription_id: Optional[pulumi.Input[str]] = None,
                 tenancy_id: Optional[pulumi.Input[str]] = None,
                 user_id: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering SubscriptionRedeemableUser resources.
        :param pulumi.Input[Sequence[pulumi.Input['SubscriptionRedeemableUserItemArgs']]] items: The list of new user to be added to the list of user that can redeem rewards.
        :param pulumi.Input[str] subscription_id: The subscription ID for which rewards information is requested for.
        :param pulumi.Input[str] tenancy_id: The OCID of the tenancy.
        :param pulumi.Input[str] user_id: The user ID of the person to send a copy of an email.
        """
        if items is not None:
            pulumi.set(__self__, "items", items)
        if subscription_id is not None:
            pulumi.set(__self__, "subscription_id", subscription_id)
        if tenancy_id is not None:
            pulumi.set(__self__, "tenancy_id", tenancy_id)
        if user_id is not None:
            pulumi.set(__self__, "user_id", user_id)

    @property
    @pulumi.getter
    def items(self) -> Optional[pulumi.Input[Sequence[pulumi.Input['SubscriptionRedeemableUserItemArgs']]]]:
        """
        The list of new user to be added to the list of user that can redeem rewards.
        """
        return pulumi.get(self, "items")

    @items.setter
    def items(self, value: Optional[pulumi.Input[Sequence[pulumi.Input['SubscriptionRedeemableUserItemArgs']]]]):
        pulumi.set(self, "items", value)

    @property
    @pulumi.getter(name="subscriptionId")
    def subscription_id(self) -> Optional[pulumi.Input[str]]:
        """
        The subscription ID for which rewards information is requested for.
        """
        return pulumi.get(self, "subscription_id")

    @subscription_id.setter
    def subscription_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "subscription_id", value)

    @property
    @pulumi.getter(name="tenancyId")
    def tenancy_id(self) -> Optional[pulumi.Input[str]]:
        """
        The OCID of the tenancy.
        """
        return pulumi.get(self, "tenancy_id")

    @tenancy_id.setter
    def tenancy_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "tenancy_id", value)

    @property
    @pulumi.getter(name="userId")
    def user_id(self) -> Optional[pulumi.Input[str]]:
        """
        The user ID of the person to send a copy of an email.
        """
        return pulumi.get(self, "user_id")

    @user_id.setter
    def user_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "user_id", value)


class SubscriptionRedeemableUser(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 items: Optional[pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['SubscriptionRedeemableUserItemArgs']]]]] = None,
                 subscription_id: Optional[pulumi.Input[str]] = None,
                 tenancy_id: Optional[pulumi.Input[str]] = None,
                 user_id: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        """
        This resource provides the Subscription Redeemable User resource in Oracle Cloud Infrastructure Usage Proxy service.

        Adds the list of redeemable user summary for a subscription ID.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_subscription_redeemable_user = oci.usage_proxy.SubscriptionRedeemableUser("testSubscriptionRedeemableUser",
            subscription_id=oci_ons_subscription["test_subscription"]["id"],
            tenancy_id=oci_identity_tenancy["test_tenancy"]["id"],
            items=[oci.usage_proxy.SubscriptionRedeemableUserItemArgs(
                email_id=oci_usage_proxy_email["test_email"]["id"],
                first_name=var["subscription_redeemable_user_items_first_name"],
                last_name=var["subscription_redeemable_user_items_last_name"],
            )],
            user_id=oci_identity_user["test_user"]["id"])
        ```

        ## Import

        SubscriptionRedeemableUsers can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:UsageProxy/subscriptionRedeemableUser:SubscriptionRedeemableUser test_subscription_redeemable_user "subscriptions/{subscriptionId}/redeemableUsers/tenancyId/{tenancyId}"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['SubscriptionRedeemableUserItemArgs']]]] items: The list of new user to be added to the list of user that can redeem rewards.
        :param pulumi.Input[str] subscription_id: The subscription ID for which rewards information is requested for.
        :param pulumi.Input[str] tenancy_id: The OCID of the tenancy.
        :param pulumi.Input[str] user_id: The user ID of the person to send a copy of an email.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: SubscriptionRedeemableUserArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Subscription Redeemable User resource in Oracle Cloud Infrastructure Usage Proxy service.

        Adds the list of redeemable user summary for a subscription ID.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_subscription_redeemable_user = oci.usage_proxy.SubscriptionRedeemableUser("testSubscriptionRedeemableUser",
            subscription_id=oci_ons_subscription["test_subscription"]["id"],
            tenancy_id=oci_identity_tenancy["test_tenancy"]["id"],
            items=[oci.usage_proxy.SubscriptionRedeemableUserItemArgs(
                email_id=oci_usage_proxy_email["test_email"]["id"],
                first_name=var["subscription_redeemable_user_items_first_name"],
                last_name=var["subscription_redeemable_user_items_last_name"],
            )],
            user_id=oci_identity_user["test_user"]["id"])
        ```

        ## Import

        SubscriptionRedeemableUsers can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:UsageProxy/subscriptionRedeemableUser:SubscriptionRedeemableUser test_subscription_redeemable_user "subscriptions/{subscriptionId}/redeemableUsers/tenancyId/{tenancyId}"
        ```

        :param str resource_name: The name of the resource.
        :param SubscriptionRedeemableUserArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(SubscriptionRedeemableUserArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 items: Optional[pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['SubscriptionRedeemableUserItemArgs']]]]] = None,
                 subscription_id: Optional[pulumi.Input[str]] = None,
                 tenancy_id: Optional[pulumi.Input[str]] = None,
                 user_id: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = SubscriptionRedeemableUserArgs.__new__(SubscriptionRedeemableUserArgs)

            if items is None and not opts.urn:
                raise TypeError("Missing required property 'items'")
            __props__.__dict__["items"] = items
            if subscription_id is None and not opts.urn:
                raise TypeError("Missing required property 'subscription_id'")
            __props__.__dict__["subscription_id"] = subscription_id
            if tenancy_id is None and not opts.urn:
                raise TypeError("Missing required property 'tenancy_id'")
            __props__.__dict__["tenancy_id"] = tenancy_id
            __props__.__dict__["user_id"] = user_id
        super(SubscriptionRedeemableUser, __self__).__init__(
            'oci:UsageProxy/subscriptionRedeemableUser:SubscriptionRedeemableUser',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            items: Optional[pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['SubscriptionRedeemableUserItemArgs']]]]] = None,
            subscription_id: Optional[pulumi.Input[str]] = None,
            tenancy_id: Optional[pulumi.Input[str]] = None,
            user_id: Optional[pulumi.Input[str]] = None) -> 'SubscriptionRedeemableUser':
        """
        Get an existing SubscriptionRedeemableUser resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[Sequence[pulumi.Input[pulumi.InputType['SubscriptionRedeemableUserItemArgs']]]] items: The list of new user to be added to the list of user that can redeem rewards.
        :param pulumi.Input[str] subscription_id: The subscription ID for which rewards information is requested for.
        :param pulumi.Input[str] tenancy_id: The OCID of the tenancy.
        :param pulumi.Input[str] user_id: The user ID of the person to send a copy of an email.
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _SubscriptionRedeemableUserState.__new__(_SubscriptionRedeemableUserState)

        __props__.__dict__["items"] = items
        __props__.__dict__["subscription_id"] = subscription_id
        __props__.__dict__["tenancy_id"] = tenancy_id
        __props__.__dict__["user_id"] = user_id
        return SubscriptionRedeemableUser(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter
    def items(self) -> pulumi.Output[Sequence['outputs.SubscriptionRedeemableUserItem']]:
        """
        The list of new user to be added to the list of user that can redeem rewards.
        """
        return pulumi.get(self, "items")

    @property
    @pulumi.getter(name="subscriptionId")
    def subscription_id(self) -> pulumi.Output[str]:
        """
        The subscription ID for which rewards information is requested for.
        """
        return pulumi.get(self, "subscription_id")

    @property
    @pulumi.getter(name="tenancyId")
    def tenancy_id(self) -> pulumi.Output[str]:
        """
        The OCID of the tenancy.
        """
        return pulumi.get(self, "tenancy_id")

    @property
    @pulumi.getter(name="userId")
    def user_id(self) -> pulumi.Output[str]:
        """
        The user ID of the person to send a copy of an email.
        """
        return pulumi.get(self, "user_id")
