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
from ._inputs import *

__all__ = [
    'GetLicenseRecordsResult',
    'AwaitableGetLicenseRecordsResult',
    'get_license_records',
    'get_license_records_output',
]

@pulumi.output_type
class GetLicenseRecordsResult:
    """
    A collection of values returned by getLicenseRecords.
    """
    def __init__(__self__, filters=None, id=None, license_record_collections=None, product_license_id=None):
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if license_record_collections and not isinstance(license_record_collections, list):
            raise TypeError("Expected argument 'license_record_collections' to be a list")
        pulumi.set(__self__, "license_record_collections", license_record_collections)
        if product_license_id and not isinstance(product_license_id, str):
            raise TypeError("Expected argument 'product_license_id' to be a str")
        pulumi.set(__self__, "product_license_id", product_license_id)

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetLicenseRecordsFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="licenseRecordCollections")
    def license_record_collections(self) -> Sequence['outputs.GetLicenseRecordsLicenseRecordCollectionResult']:
        """
        The list of license_record_collection.
        """
        return pulumi.get(self, "license_record_collections")

    @_builtins.property
    @pulumi.getter(name="productLicenseId")
    def product_license_id(self) -> _builtins.str:
        """
        The product license [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) with which the license record is associated.
        """
        return pulumi.get(self, "product_license_id")


class AwaitableGetLicenseRecordsResult(GetLicenseRecordsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetLicenseRecordsResult(
            filters=self.filters,
            id=self.id,
            license_record_collections=self.license_record_collections,
            product_license_id=self.product_license_id)


def get_license_records(filters: Optional[Sequence[Union['GetLicenseRecordsFilterArgs', 'GetLicenseRecordsFilterArgsDict']]] = None,
                        product_license_id: Optional[_builtins.str] = None,
                        opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetLicenseRecordsResult:
    """
    This data source provides the list of License Records in Oracle Cloud Infrastructure License Manager service.

    Retrieves all license records for a given product license ID.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_license_records = oci.LicenseManager.get_license_records(product_license_id=test_product_license["id"])
    ```


    :param _builtins.str product_license_id: Unique product license identifier.
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['productLicenseId'] = product_license_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:LicenseManager/getLicenseRecords:getLicenseRecords', __args__, opts=opts, typ=GetLicenseRecordsResult).value

    return AwaitableGetLicenseRecordsResult(
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        license_record_collections=pulumi.get(__ret__, 'license_record_collections'),
        product_license_id=pulumi.get(__ret__, 'product_license_id'))
def get_license_records_output(filters: Optional[pulumi.Input[Optional[Sequence[Union['GetLicenseRecordsFilterArgs', 'GetLicenseRecordsFilterArgsDict']]]]] = None,
                               product_license_id: Optional[pulumi.Input[_builtins.str]] = None,
                               opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetLicenseRecordsResult]:
    """
    This data source provides the list of License Records in Oracle Cloud Infrastructure License Manager service.

    Retrieves all license records for a given product license ID.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_license_records = oci.LicenseManager.get_license_records(product_license_id=test_product_license["id"])
    ```


    :param _builtins.str product_license_id: Unique product license identifier.
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['productLicenseId'] = product_license_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:LicenseManager/getLicenseRecords:getLicenseRecords', __args__, opts=opts, typ=GetLicenseRecordsResult)
    return __ret__.apply(lambda __response__: GetLicenseRecordsResult(
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        license_record_collections=pulumi.get(__response__, 'license_record_collections'),
        product_license_id=pulumi.get(__response__, 'product_license_id')))
