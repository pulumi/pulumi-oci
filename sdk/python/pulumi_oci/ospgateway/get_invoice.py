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
    'GetInvoiceResult',
    'AwaitableGetInvoiceResult',
    'get_invoice',
    'get_invoice_output',
]

@pulumi.output_type
class GetInvoiceResult:
    """
    A collection of values returned by getInvoice.
    """
    def __init__(__self__, bill_to_addresses=None, compartment_id=None, currencies=None, id=None, internal_invoice_id=None, invoice_amount=None, invoice_amount_adjusted=None, invoice_amount_applied=None, invoice_amount_credited=None, invoice_amount_due=None, invoice_id=None, invoice_number=None, invoice_po_number=None, invoice_ref_number=None, invoice_status=None, invoice_type=None, is_credit_card_payable=None, is_display_download_pdf=None, is_payable=None, is_pdf_email_available=None, last_payment_details=None, osp_home_region=None, payment_terms=None, preferred_email=None, subscription_ids=None, tax=None, time_invoice=None, time_invoice_due=None):
        if bill_to_addresses and not isinstance(bill_to_addresses, list):
            raise TypeError("Expected argument 'bill_to_addresses' to be a list")
        pulumi.set(__self__, "bill_to_addresses", bill_to_addresses)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if currencies and not isinstance(currencies, list):
            raise TypeError("Expected argument 'currencies' to be a list")
        pulumi.set(__self__, "currencies", currencies)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if internal_invoice_id and not isinstance(internal_invoice_id, str):
            raise TypeError("Expected argument 'internal_invoice_id' to be a str")
        pulumi.set(__self__, "internal_invoice_id", internal_invoice_id)
        if invoice_amount and not isinstance(invoice_amount, float):
            raise TypeError("Expected argument 'invoice_amount' to be a float")
        pulumi.set(__self__, "invoice_amount", invoice_amount)
        if invoice_amount_adjusted and not isinstance(invoice_amount_adjusted, float):
            raise TypeError("Expected argument 'invoice_amount_adjusted' to be a float")
        pulumi.set(__self__, "invoice_amount_adjusted", invoice_amount_adjusted)
        if invoice_amount_applied and not isinstance(invoice_amount_applied, float):
            raise TypeError("Expected argument 'invoice_amount_applied' to be a float")
        pulumi.set(__self__, "invoice_amount_applied", invoice_amount_applied)
        if invoice_amount_credited and not isinstance(invoice_amount_credited, float):
            raise TypeError("Expected argument 'invoice_amount_credited' to be a float")
        pulumi.set(__self__, "invoice_amount_credited", invoice_amount_credited)
        if invoice_amount_due and not isinstance(invoice_amount_due, float):
            raise TypeError("Expected argument 'invoice_amount_due' to be a float")
        pulumi.set(__self__, "invoice_amount_due", invoice_amount_due)
        if invoice_id and not isinstance(invoice_id, str):
            raise TypeError("Expected argument 'invoice_id' to be a str")
        pulumi.set(__self__, "invoice_id", invoice_id)
        if invoice_number and not isinstance(invoice_number, str):
            raise TypeError("Expected argument 'invoice_number' to be a str")
        pulumi.set(__self__, "invoice_number", invoice_number)
        if invoice_po_number and not isinstance(invoice_po_number, str):
            raise TypeError("Expected argument 'invoice_po_number' to be a str")
        pulumi.set(__self__, "invoice_po_number", invoice_po_number)
        if invoice_ref_number and not isinstance(invoice_ref_number, str):
            raise TypeError("Expected argument 'invoice_ref_number' to be a str")
        pulumi.set(__self__, "invoice_ref_number", invoice_ref_number)
        if invoice_status and not isinstance(invoice_status, str):
            raise TypeError("Expected argument 'invoice_status' to be a str")
        pulumi.set(__self__, "invoice_status", invoice_status)
        if invoice_type and not isinstance(invoice_type, str):
            raise TypeError("Expected argument 'invoice_type' to be a str")
        pulumi.set(__self__, "invoice_type", invoice_type)
        if is_credit_card_payable and not isinstance(is_credit_card_payable, bool):
            raise TypeError("Expected argument 'is_credit_card_payable' to be a bool")
        pulumi.set(__self__, "is_credit_card_payable", is_credit_card_payable)
        if is_display_download_pdf and not isinstance(is_display_download_pdf, bool):
            raise TypeError("Expected argument 'is_display_download_pdf' to be a bool")
        pulumi.set(__self__, "is_display_download_pdf", is_display_download_pdf)
        if is_payable and not isinstance(is_payable, bool):
            raise TypeError("Expected argument 'is_payable' to be a bool")
        pulumi.set(__self__, "is_payable", is_payable)
        if is_pdf_email_available and not isinstance(is_pdf_email_available, bool):
            raise TypeError("Expected argument 'is_pdf_email_available' to be a bool")
        pulumi.set(__self__, "is_pdf_email_available", is_pdf_email_available)
        if last_payment_details and not isinstance(last_payment_details, list):
            raise TypeError("Expected argument 'last_payment_details' to be a list")
        pulumi.set(__self__, "last_payment_details", last_payment_details)
        if osp_home_region and not isinstance(osp_home_region, str):
            raise TypeError("Expected argument 'osp_home_region' to be a str")
        pulumi.set(__self__, "osp_home_region", osp_home_region)
        if payment_terms and not isinstance(payment_terms, str):
            raise TypeError("Expected argument 'payment_terms' to be a str")
        pulumi.set(__self__, "payment_terms", payment_terms)
        if preferred_email and not isinstance(preferred_email, str):
            raise TypeError("Expected argument 'preferred_email' to be a str")
        pulumi.set(__self__, "preferred_email", preferred_email)
        if subscription_ids and not isinstance(subscription_ids, list):
            raise TypeError("Expected argument 'subscription_ids' to be a list")
        pulumi.set(__self__, "subscription_ids", subscription_ids)
        if tax and not isinstance(tax, float):
            raise TypeError("Expected argument 'tax' to be a float")
        pulumi.set(__self__, "tax", tax)
        if time_invoice and not isinstance(time_invoice, str):
            raise TypeError("Expected argument 'time_invoice' to be a str")
        pulumi.set(__self__, "time_invoice", time_invoice)
        if time_invoice_due and not isinstance(time_invoice_due, str):
            raise TypeError("Expected argument 'time_invoice_due' to be a str")
        pulumi.set(__self__, "time_invoice_due", time_invoice_due)

    @property
    @pulumi.getter(name="billToAddresses")
    def bill_to_addresses(self) -> Sequence['outputs.GetInvoiceBillToAddressResult']:
        """
        Address details model
        """
        return pulumi.get(self, "bill_to_addresses")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter
    def currencies(self) -> Sequence['outputs.GetInvoiceCurrencyResult']:
        """
        Currency details model
        """
        return pulumi.get(self, "currencies")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="internalInvoiceId")
    def internal_invoice_id(self) -> str:
        """
        Transaction identifier
        """
        return pulumi.get(self, "internal_invoice_id")

    @property
    @pulumi.getter(name="invoiceAmount")
    def invoice_amount(self) -> float:
        """
        Total amount of invoice
        """
        return pulumi.get(self, "invoice_amount")

    @property
    @pulumi.getter(name="invoiceAmountAdjusted")
    def invoice_amount_adjusted(self) -> float:
        """
        Invoice amount adjust
        """
        return pulumi.get(self, "invoice_amount_adjusted")

    @property
    @pulumi.getter(name="invoiceAmountApplied")
    def invoice_amount_applied(self) -> float:
        """
        Invoice amount applied
        """
        return pulumi.get(self, "invoice_amount_applied")

    @property
    @pulumi.getter(name="invoiceAmountCredited")
    def invoice_amount_credited(self) -> float:
        """
        Invoice amount credit
        """
        return pulumi.get(self, "invoice_amount_credited")

    @property
    @pulumi.getter(name="invoiceAmountDue")
    def invoice_amount_due(self) -> float:
        """
        Balance of invoice
        """
        return pulumi.get(self, "invoice_amount_due")

    @property
    @pulumi.getter(name="invoiceId")
    def invoice_id(self) -> str:
        """
        Invoice identifier which is generated on the on-premise sie. Pls note this is not an OCID
        """
        return pulumi.get(self, "invoice_id")

    @property
    @pulumi.getter(name="invoiceNumber")
    def invoice_number(self) -> str:
        """
        Invoice external reference
        """
        return pulumi.get(self, "invoice_number")

    @property
    @pulumi.getter(name="invoicePoNumber")
    def invoice_po_number(self) -> str:
        """
        Invoice PO number
        """
        return pulumi.get(self, "invoice_po_number")

    @property
    @pulumi.getter(name="invoiceRefNumber")
    def invoice_ref_number(self) -> str:
        """
        Invoice reference number
        """
        return pulumi.get(self, "invoice_ref_number")

    @property
    @pulumi.getter(name="invoiceStatus")
    def invoice_status(self) -> str:
        """
        Invoice status
        """
        return pulumi.get(self, "invoice_status")

    @property
    @pulumi.getter(name="invoiceType")
    def invoice_type(self) -> str:
        """
        Type of invoice
        """
        return pulumi.get(self, "invoice_type")

    @property
    @pulumi.getter(name="isCreditCardPayable")
    def is_credit_card_payable(self) -> bool:
        """
        Is credit card payment eligible
        """
        return pulumi.get(self, "is_credit_card_payable")

    @property
    @pulumi.getter(name="isDisplayDownloadPdf")
    def is_display_download_pdf(self) -> bool:
        """
        Is pdf download access allowed
        """
        return pulumi.get(self, "is_display_download_pdf")

    @property
    @pulumi.getter(name="isPayable")
    def is_payable(self) -> bool:
        """
        Whether invoice can be payed
        """
        return pulumi.get(self, "is_payable")

    @property
    @pulumi.getter(name="isPdfEmailAvailable")
    def is_pdf_email_available(self) -> bool:
        """
        Is emailing pdf allowed
        """
        return pulumi.get(self, "is_pdf_email_available")

    @property
    @pulumi.getter(name="lastPaymentDetails")
    def last_payment_details(self) -> Sequence['outputs.GetInvoiceLastPaymentDetailResult']:
        """
        Payment related details
        """
        return pulumi.get(self, "last_payment_details")

    @property
    @pulumi.getter(name="ospHomeRegion")
    def osp_home_region(self) -> str:
        return pulumi.get(self, "osp_home_region")

    @property
    @pulumi.getter(name="paymentTerms")
    def payment_terms(self) -> str:
        """
        Payment terms
        """
        return pulumi.get(self, "payment_terms")

    @property
    @pulumi.getter(name="preferredEmail")
    def preferred_email(self) -> str:
        """
        Preferred Email on the invoice
        """
        return pulumi.get(self, "preferred_email")

    @property
    @pulumi.getter(name="subscriptionIds")
    def subscription_ids(self) -> Sequence[str]:
        """
        List of subscription identifiers
        """
        return pulumi.get(self, "subscription_ids")

    @property
    @pulumi.getter
    def tax(self) -> float:
        """
        Tax of invoice amount
        """
        return pulumi.get(self, "tax")

    @property
    @pulumi.getter(name="timeInvoice")
    def time_invoice(self) -> str:
        """
        Date of invoice
        """
        return pulumi.get(self, "time_invoice")

    @property
    @pulumi.getter(name="timeInvoiceDue")
    def time_invoice_due(self) -> str:
        """
        Due date of invoice
        """
        return pulumi.get(self, "time_invoice_due")


class AwaitableGetInvoiceResult(GetInvoiceResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetInvoiceResult(
            bill_to_addresses=self.bill_to_addresses,
            compartment_id=self.compartment_id,
            currencies=self.currencies,
            id=self.id,
            internal_invoice_id=self.internal_invoice_id,
            invoice_amount=self.invoice_amount,
            invoice_amount_adjusted=self.invoice_amount_adjusted,
            invoice_amount_applied=self.invoice_amount_applied,
            invoice_amount_credited=self.invoice_amount_credited,
            invoice_amount_due=self.invoice_amount_due,
            invoice_id=self.invoice_id,
            invoice_number=self.invoice_number,
            invoice_po_number=self.invoice_po_number,
            invoice_ref_number=self.invoice_ref_number,
            invoice_status=self.invoice_status,
            invoice_type=self.invoice_type,
            is_credit_card_payable=self.is_credit_card_payable,
            is_display_download_pdf=self.is_display_download_pdf,
            is_payable=self.is_payable,
            is_pdf_email_available=self.is_pdf_email_available,
            last_payment_details=self.last_payment_details,
            osp_home_region=self.osp_home_region,
            payment_terms=self.payment_terms,
            preferred_email=self.preferred_email,
            subscription_ids=self.subscription_ids,
            tax=self.tax,
            time_invoice=self.time_invoice,
            time_invoice_due=self.time_invoice_due)


def get_invoice(compartment_id: Optional[str] = None,
                internal_invoice_id: Optional[str] = None,
                osp_home_region: Optional[str] = None,
                opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetInvoiceResult:
    """
    This data source provides details about a specific Invoice resource in Oracle Cloud Infrastructure Osp Gateway service.

    Returns an invoice by invoice id

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_invoice = oci.OspGateway.get_invoice(compartment_id=var["compartment_id"],
        internal_invoice_id=oci_osp_gateway_invoice["test_invoice"]["id"],
        osp_home_region=var["invoice_osp_home_region"])
    ```


    :param str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param str internal_invoice_id: The identifier of the invoice.
    :param str osp_home_region: The home region's public name of the logged in user.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['internalInvoiceId'] = internal_invoice_id
    __args__['ospHomeRegion'] = osp_home_region
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:OspGateway/getInvoice:getInvoice', __args__, opts=opts, typ=GetInvoiceResult).value

    return AwaitableGetInvoiceResult(
        bill_to_addresses=__ret__.bill_to_addresses,
        compartment_id=__ret__.compartment_id,
        currencies=__ret__.currencies,
        id=__ret__.id,
        internal_invoice_id=__ret__.internal_invoice_id,
        invoice_amount=__ret__.invoice_amount,
        invoice_amount_adjusted=__ret__.invoice_amount_adjusted,
        invoice_amount_applied=__ret__.invoice_amount_applied,
        invoice_amount_credited=__ret__.invoice_amount_credited,
        invoice_amount_due=__ret__.invoice_amount_due,
        invoice_id=__ret__.invoice_id,
        invoice_number=__ret__.invoice_number,
        invoice_po_number=__ret__.invoice_po_number,
        invoice_ref_number=__ret__.invoice_ref_number,
        invoice_status=__ret__.invoice_status,
        invoice_type=__ret__.invoice_type,
        is_credit_card_payable=__ret__.is_credit_card_payable,
        is_display_download_pdf=__ret__.is_display_download_pdf,
        is_payable=__ret__.is_payable,
        is_pdf_email_available=__ret__.is_pdf_email_available,
        last_payment_details=__ret__.last_payment_details,
        osp_home_region=__ret__.osp_home_region,
        payment_terms=__ret__.payment_terms,
        preferred_email=__ret__.preferred_email,
        subscription_ids=__ret__.subscription_ids,
        tax=__ret__.tax,
        time_invoice=__ret__.time_invoice,
        time_invoice_due=__ret__.time_invoice_due)


@_utilities.lift_output_func(get_invoice)
def get_invoice_output(compartment_id: Optional[pulumi.Input[str]] = None,
                       internal_invoice_id: Optional[pulumi.Input[str]] = None,
                       osp_home_region: Optional[pulumi.Input[str]] = None,
                       opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetInvoiceResult]:
    """
    This data source provides details about a specific Invoice resource in Oracle Cloud Infrastructure Osp Gateway service.

    Returns an invoice by invoice id

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_invoice = oci.OspGateway.get_invoice(compartment_id=var["compartment_id"],
        internal_invoice_id=oci_osp_gateway_invoice["test_invoice"]["id"],
        osp_home_region=var["invoice_osp_home_region"])
    ```


    :param str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param str internal_invoice_id: The identifier of the invoice.
    :param str osp_home_region: The home region's public name of the logged in user.
    """
    ...