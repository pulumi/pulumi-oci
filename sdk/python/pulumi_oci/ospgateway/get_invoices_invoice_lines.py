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
    'GetInvoicesInvoiceLinesResult',
    'AwaitableGetInvoicesInvoiceLinesResult',
    'get_invoices_invoice_lines',
    'get_invoices_invoice_lines_output',
]

@pulumi.output_type
class GetInvoicesInvoiceLinesResult:
    """
    A collection of values returned by getInvoicesInvoiceLines.
    """
    def __init__(__self__, compartment_id=None, filters=None, id=None, internal_invoice_id=None, invoice_line_collections=None, osp_home_region=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if internal_invoice_id and not isinstance(internal_invoice_id, str):
            raise TypeError("Expected argument 'internal_invoice_id' to be a str")
        pulumi.set(__self__, "internal_invoice_id", internal_invoice_id)
        if invoice_line_collections and not isinstance(invoice_line_collections, list):
            raise TypeError("Expected argument 'invoice_line_collections' to be a list")
        pulumi.set(__self__, "invoice_line_collections", invoice_line_collections)
        if osp_home_region and not isinstance(osp_home_region, str):
            raise TypeError("Expected argument 'osp_home_region' to be a str")
        pulumi.set(__self__, "osp_home_region", osp_home_region)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetInvoicesInvoiceLinesFilterResult']]:
        return pulumi.get(self, "filters")

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
        return pulumi.get(self, "internal_invoice_id")

    @property
    @pulumi.getter(name="invoiceLineCollections")
    def invoice_line_collections(self) -> Sequence['outputs.GetInvoicesInvoiceLinesInvoiceLineCollectionResult']:
        """
        The list of invoice_line_collection.
        """
        return pulumi.get(self, "invoice_line_collections")

    @property
    @pulumi.getter(name="ospHomeRegion")
    def osp_home_region(self) -> str:
        return pulumi.get(self, "osp_home_region")


class AwaitableGetInvoicesInvoiceLinesResult(GetInvoicesInvoiceLinesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetInvoicesInvoiceLinesResult(
            compartment_id=self.compartment_id,
            filters=self.filters,
            id=self.id,
            internal_invoice_id=self.internal_invoice_id,
            invoice_line_collections=self.invoice_line_collections,
            osp_home_region=self.osp_home_region)


def get_invoices_invoice_lines(compartment_id: Optional[str] = None,
                               filters: Optional[Sequence[pulumi.InputType['GetInvoicesInvoiceLinesFilterArgs']]] = None,
                               internal_invoice_id: Optional[str] = None,
                               osp_home_region: Optional[str] = None,
                               opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetInvoicesInvoiceLinesResult:
    """
    This data source provides the list of Invoices Invoice Lines in Oracle Cloud Infrastructure Osp Gateway service.

    Returns the invoice product list by invoice id

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_invoices_invoice_lines = oci.OspGateway.get_invoices_invoice_lines(compartment_id=var["compartment_id"],
        internal_invoice_id=oci_osp_gateway_invoice["test_invoice"]["id"],
        osp_home_region=var["invoices_invoice_line_osp_home_region"])
    ```


    :param str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param str internal_invoice_id: The identifier of the invoice.
    :param str osp_home_region: The home region's public name of the logged in user.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    __args__['internalInvoiceId'] = internal_invoice_id
    __args__['ospHomeRegion'] = osp_home_region
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:OspGateway/getInvoicesInvoiceLines:getInvoicesInvoiceLines', __args__, opts=opts, typ=GetInvoicesInvoiceLinesResult).value

    return AwaitableGetInvoicesInvoiceLinesResult(
        compartment_id=__ret__.compartment_id,
        filters=__ret__.filters,
        id=__ret__.id,
        internal_invoice_id=__ret__.internal_invoice_id,
        invoice_line_collections=__ret__.invoice_line_collections,
        osp_home_region=__ret__.osp_home_region)


@_utilities.lift_output_func(get_invoices_invoice_lines)
def get_invoices_invoice_lines_output(compartment_id: Optional[pulumi.Input[str]] = None,
                                      filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetInvoicesInvoiceLinesFilterArgs']]]]] = None,
                                      internal_invoice_id: Optional[pulumi.Input[str]] = None,
                                      osp_home_region: Optional[pulumi.Input[str]] = None,
                                      opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetInvoicesInvoiceLinesResult]:
    """
    This data source provides the list of Invoices Invoice Lines in Oracle Cloud Infrastructure Osp Gateway service.

    Returns the invoice product list by invoice id

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_invoices_invoice_lines = oci.OspGateway.get_invoices_invoice_lines(compartment_id=var["compartment_id"],
        internal_invoice_id=oci_osp_gateway_invoice["test_invoice"]["id"],
        osp_home_region=var["invoices_invoice_line_osp_home_region"])
    ```


    :param str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param str internal_invoice_id: The identifier of the invoice.
    :param str osp_home_region: The home region's public name of the logged in user.
    """
    ...