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
    'GetFaultDomainsResult',
    'AwaitableGetFaultDomainsResult',
    'get_fault_domains',
    'get_fault_domains_output',
]

@pulumi.output_type
class GetFaultDomainsResult:
    """
    A collection of values returned by getFaultDomains.
    """
    def __init__(__self__, availability_domain=None, compartment_id=None, fault_domains=None, filters=None, id=None):
        if availability_domain and not isinstance(availability_domain, str):
            raise TypeError("Expected argument 'availability_domain' to be a str")
        pulumi.set(__self__, "availability_domain", availability_domain)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if fault_domains and not isinstance(fault_domains, list):
            raise TypeError("Expected argument 'fault_domains' to be a list")
        pulumi.set(__self__, "fault_domains", fault_domains)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)

    @property
    @pulumi.getter(name="availabilityDomain")
    def availability_domain(self) -> str:
        """
        The name of the availabilityDomain where the Fault Domain belongs.
        """
        return pulumi.get(self, "availability_domain")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the compartment. Currently only tenancy (root) compartment can be provided.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="faultDomains")
    def fault_domains(self) -> Sequence['outputs.GetFaultDomainsFaultDomainResult']:
        """
        The list of fault_domains.
        """
        return pulumi.get(self, "fault_domains")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetFaultDomainsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")


class AwaitableGetFaultDomainsResult(GetFaultDomainsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetFaultDomainsResult(
            availability_domain=self.availability_domain,
            compartment_id=self.compartment_id,
            fault_domains=self.fault_domains,
            filters=self.filters,
            id=self.id)


def get_fault_domains(availability_domain: Optional[str] = None,
                      compartment_id: Optional[str] = None,
                      filters: Optional[Sequence[pulumi.InputType['GetFaultDomainsFilterArgs']]] = None,
                      opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetFaultDomainsResult:
    """
    This data source provides the list of Fault Domains in Oracle Cloud Infrastructure Identity service.

    Lists the Fault Domains in your tenancy. Specify the OCID of either the tenancy or another
    of your compartments as the value for the compartment ID (remember that the tenancy is simply the root compartment).
    See [Where to Get the Tenancy's OCID and User's OCID](https://docs.cloud.oracle.com/iaas/Content/API/Concepts/apisigningkey.htm#five).

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_fault_domains = oci.Identity.get_fault_domains(availability_domain=var["fault_domain_availability_domain"],
        compartment_id=var["compartment_id"])
    ```


    :param str availability_domain: The name of the availibilityDomain.
    :param str compartment_id: The OCID of the compartment (remember that the tenancy is simply the root compartment).
    """
    __args__ = dict()
    __args__['availabilityDomain'] = availability_domain
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Identity/getFaultDomains:getFaultDomains', __args__, opts=opts, typ=GetFaultDomainsResult).value

    return AwaitableGetFaultDomainsResult(
        availability_domain=__ret__.availability_domain,
        compartment_id=__ret__.compartment_id,
        fault_domains=__ret__.fault_domains,
        filters=__ret__.filters,
        id=__ret__.id)


@_utilities.lift_output_func(get_fault_domains)
def get_fault_domains_output(availability_domain: Optional[pulumi.Input[str]] = None,
                             compartment_id: Optional[pulumi.Input[str]] = None,
                             filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetFaultDomainsFilterArgs']]]]] = None,
                             opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetFaultDomainsResult]:
    """
    This data source provides the list of Fault Domains in Oracle Cloud Infrastructure Identity service.

    Lists the Fault Domains in your tenancy. Specify the OCID of either the tenancy or another
    of your compartments as the value for the compartment ID (remember that the tenancy is simply the root compartment).
    See [Where to Get the Tenancy's OCID and User's OCID](https://docs.cloud.oracle.com/iaas/Content/API/Concepts/apisigningkey.htm#five).

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_fault_domains = oci.Identity.get_fault_domains(availability_domain=var["fault_domain_availability_domain"],
        compartment_id=var["compartment_id"])
    ```


    :param str availability_domain: The name of the availibilityDomain.
    :param str compartment_id: The OCID of the compartment (remember that the tenancy is simply the root compartment).
    """
    ...