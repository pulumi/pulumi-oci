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
    'GetBillingScheduleBillingScheduleResult',
    'GetBillingScheduleBillingScheduleProductResult',
    'GetBillingScheduleFilterResult',
]

@pulumi.output_type
class GetBillingScheduleBillingScheduleResult(dict):
    def __init__(__self__, *,
                 amount: str,
                 ar_customer_transaction_id: str,
                 ar_invoice_number: str,
                 billing_frequency: str,
                 invoice_status: str,
                 net_unit_price: str,
                 order_number: str,
                 products: Sequence['outputs.GetBillingScheduleBillingScheduleProductResult'],
                 quantity: str,
                 time_end: str,
                 time_invoicing: str,
                 time_start: str):
        """
        :param str amount: Billing schedule line net amount
        :param str ar_customer_transaction_id: Indicates the associated AR Customer transaction id a unique identifier existing on AR.
        :param str ar_invoice_number: Indicates the associated AR Invoice Number
        :param str billing_frequency: Billing frequency
        :param str invoice_status: Billing schedule invoice status
        :param str net_unit_price: Billing schedule net unit price
        :param str order_number: Order number associated with the Subscribed Service
        :param Sequence['GetBillingScheduleBillingScheduleProductArgs'] products: Product description
        :param str quantity: Billing schedule quantity
        :param str time_end: Billing schedule end date
        :param str time_invoicing: Billing schedule invoicing date
        :param str time_start: Billing schedule start date
        """
        pulumi.set(__self__, "amount", amount)
        pulumi.set(__self__, "ar_customer_transaction_id", ar_customer_transaction_id)
        pulumi.set(__self__, "ar_invoice_number", ar_invoice_number)
        pulumi.set(__self__, "billing_frequency", billing_frequency)
        pulumi.set(__self__, "invoice_status", invoice_status)
        pulumi.set(__self__, "net_unit_price", net_unit_price)
        pulumi.set(__self__, "order_number", order_number)
        pulumi.set(__self__, "products", products)
        pulumi.set(__self__, "quantity", quantity)
        pulumi.set(__self__, "time_end", time_end)
        pulumi.set(__self__, "time_invoicing", time_invoicing)
        pulumi.set(__self__, "time_start", time_start)

    @property
    @pulumi.getter
    def amount(self) -> str:
        """
        Billing schedule line net amount
        """
        return pulumi.get(self, "amount")

    @property
    @pulumi.getter(name="arCustomerTransactionId")
    def ar_customer_transaction_id(self) -> str:
        """
        Indicates the associated AR Customer transaction id a unique identifier existing on AR.
        """
        return pulumi.get(self, "ar_customer_transaction_id")

    @property
    @pulumi.getter(name="arInvoiceNumber")
    def ar_invoice_number(self) -> str:
        """
        Indicates the associated AR Invoice Number
        """
        return pulumi.get(self, "ar_invoice_number")

    @property
    @pulumi.getter(name="billingFrequency")
    def billing_frequency(self) -> str:
        """
        Billing frequency
        """
        return pulumi.get(self, "billing_frequency")

    @property
    @pulumi.getter(name="invoiceStatus")
    def invoice_status(self) -> str:
        """
        Billing schedule invoice status
        """
        return pulumi.get(self, "invoice_status")

    @property
    @pulumi.getter(name="netUnitPrice")
    def net_unit_price(self) -> str:
        """
        Billing schedule net unit price
        """
        return pulumi.get(self, "net_unit_price")

    @property
    @pulumi.getter(name="orderNumber")
    def order_number(self) -> str:
        """
        Order number associated with the Subscribed Service
        """
        return pulumi.get(self, "order_number")

    @property
    @pulumi.getter
    def products(self) -> Sequence['outputs.GetBillingScheduleBillingScheduleProductResult']:
        """
        Product description
        """
        return pulumi.get(self, "products")

    @property
    @pulumi.getter
    def quantity(self) -> str:
        """
        Billing schedule quantity
        """
        return pulumi.get(self, "quantity")

    @property
    @pulumi.getter(name="timeEnd")
    def time_end(self) -> str:
        """
        Billing schedule end date
        """
        return pulumi.get(self, "time_end")

    @property
    @pulumi.getter(name="timeInvoicing")
    def time_invoicing(self) -> str:
        """
        Billing schedule invoicing date
        """
        return pulumi.get(self, "time_invoicing")

    @property
    @pulumi.getter(name="timeStart")
    def time_start(self) -> str:
        """
        Billing schedule start date
        """
        return pulumi.get(self, "time_start")


@pulumi.output_type
class GetBillingScheduleBillingScheduleProductResult(dict):
    def __init__(__self__, *,
                 name: str,
                 part_number: str):
        """
        :param str name: Product name
        :param str part_number: Indicates the associated AR Invoice Number
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "part_number", part_number)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        Product name
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter(name="partNumber")
    def part_number(self) -> str:
        """
        Indicates the associated AR Invoice Number
        """
        return pulumi.get(self, "part_number")


@pulumi.output_type
class GetBillingScheduleFilterResult(dict):
    def __init__(__self__, *,
                 name: str,
                 values: Sequence[str],
                 regex: Optional[bool] = None):
        """
        :param str name: Product name
        """
        pulumi.set(__self__, "name", name)
        pulumi.set(__self__, "values", values)
        if regex is not None:
            pulumi.set(__self__, "regex", regex)

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        Product name
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter
    def values(self) -> Sequence[str]:
        return pulumi.get(self, "values")

    @property
    @pulumi.getter
    def regex(self) -> Optional[bool]:
        return pulumi.get(self, "regex")

