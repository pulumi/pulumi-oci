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
    'GetSoftwareSourceVendorsResult',
    'AwaitableGetSoftwareSourceVendorsResult',
    'get_software_source_vendors',
    'get_software_source_vendors_output',
]

@pulumi.output_type
class GetSoftwareSourceVendorsResult:
    """
    A collection of values returned by getSoftwareSourceVendors.
    """
    def __init__(__self__, compartment_id=None, filters=None, id=None, name=None, software_source_vendor_collections=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if software_source_vendor_collections and not isinstance(software_source_vendor_collections, list):
            raise TypeError("Expected argument 'software_source_vendor_collections' to be a list")
        pulumi.set(__self__, "software_source_vendor_collections", software_source_vendor_collections)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetSoftwareSourceVendorsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def name(self) -> Optional[str]:
        """
        Name of the vendor providing the software source.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter(name="softwareSourceVendorCollections")
    def software_source_vendor_collections(self) -> Sequence['outputs.GetSoftwareSourceVendorsSoftwareSourceVendorCollectionResult']:
        """
        The list of software_source_vendor_collection.
        """
        return pulumi.get(self, "software_source_vendor_collections")


class AwaitableGetSoftwareSourceVendorsResult(GetSoftwareSourceVendorsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetSoftwareSourceVendorsResult(
            compartment_id=self.compartment_id,
            filters=self.filters,
            id=self.id,
            name=self.name,
            software_source_vendor_collections=self.software_source_vendor_collections)


def get_software_source_vendors(compartment_id: Optional[str] = None,
                                filters: Optional[Sequence[pulumi.InputType['GetSoftwareSourceVendorsFilterArgs']]] = None,
                                name: Optional[str] = None,
                                opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetSoftwareSourceVendorsResult:
    """
    This data source provides the list of Software Source Vendors in Oracle Cloud Infrastructure Os Management Hub service.

    Lists available software source vendors. Filter the list against a variety of criteria including but not limited
    to its name.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_software_source_vendors = oci.OsManagementHub.get_software_source_vendors(compartment_id=var["compartment_id"],
        name=var["software_source_vendor_name"])
    ```


    :param str compartment_id: The OCID of the compartment that contains the resources to list. This parameter is required.
    :param str name: The name of the entity to be queried.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    __args__['name'] = name
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:OsManagementHub/getSoftwareSourceVendors:getSoftwareSourceVendors', __args__, opts=opts, typ=GetSoftwareSourceVendorsResult).value

    return AwaitableGetSoftwareSourceVendorsResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        name=pulumi.get(__ret__, 'name'),
        software_source_vendor_collections=pulumi.get(__ret__, 'software_source_vendor_collections'))


@_utilities.lift_output_func(get_software_source_vendors)
def get_software_source_vendors_output(compartment_id: Optional[pulumi.Input[str]] = None,
                                       filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetSoftwareSourceVendorsFilterArgs']]]]] = None,
                                       name: Optional[pulumi.Input[Optional[str]]] = None,
                                       opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetSoftwareSourceVendorsResult]:
    """
    This data source provides the list of Software Source Vendors in Oracle Cloud Infrastructure Os Management Hub service.

    Lists available software source vendors. Filter the list against a variety of criteria including but not limited
    to its name.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_software_source_vendors = oci.OsManagementHub.get_software_source_vendors(compartment_id=var["compartment_id"],
        name=var["software_source_vendor_name"])
    ```


    :param str compartment_id: The OCID of the compartment that contains the resources to list. This parameter is required.
    :param str name: The name of the entity to be queried.
    """
    ...