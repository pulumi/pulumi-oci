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
    'GetKeyVersionsResult',
    'AwaitableGetKeyVersionsResult',
    'get_key_versions',
    'get_key_versions_output',
]

@pulumi.output_type
class GetKeyVersionsResult:
    """
    A collection of values returned by getKeyVersions.
    """
    def __init__(__self__, filters=None, id=None, key_id=None, key_versions=None, management_endpoint=None):
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if key_id and not isinstance(key_id, str):
            raise TypeError("Expected argument 'key_id' to be a str")
        pulumi.set(__self__, "key_id", key_id)
        if key_versions and not isinstance(key_versions, list):
            raise TypeError("Expected argument 'key_versions' to be a list")
        pulumi.set(__self__, "key_versions", key_versions)
        if management_endpoint and not isinstance(management_endpoint, str):
            raise TypeError("Expected argument 'management_endpoint' to be a str")
        pulumi.set(__self__, "management_endpoint", management_endpoint)

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetKeyVersionsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="keyId")
    def key_id(self) -> str:
        """
        The OCID of the master encryption key associated with this key version.
        """
        return pulumi.get(self, "key_id")

    @property
    @pulumi.getter(name="keyVersions")
    def key_versions(self) -> Sequence['outputs.GetKeyVersionsKeyVersionResult']:
        """
        The list of key_versions.
        """
        return pulumi.get(self, "key_versions")

    @property
    @pulumi.getter(name="managementEndpoint")
    def management_endpoint(self) -> str:
        return pulumi.get(self, "management_endpoint")


class AwaitableGetKeyVersionsResult(GetKeyVersionsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetKeyVersionsResult(
            filters=self.filters,
            id=self.id,
            key_id=self.key_id,
            key_versions=self.key_versions,
            management_endpoint=self.management_endpoint)


def get_key_versions(filters: Optional[Sequence[pulumi.InputType['GetKeyVersionsFilterArgs']]] = None,
                     key_id: Optional[str] = None,
                     management_endpoint: Optional[str] = None,
                     opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetKeyVersionsResult:
    """
    This data source provides the list of Key Versions in Oracle Cloud Infrastructure Kms service.

    Lists all [KeyVersion](https://docs.cloud.oracle.com/iaas/api/#/en/key/latest/KeyVersion/) resources for the specified
    master encryption key.

    As a management operation, this call is subject to a Key Management limit that applies to the total number
    of requests across all management read operations. Key Management might throttle this call to reject an
    otherwise valid request when the total rate of management read operations exceeds 10 requests per second
    for a given tenancy.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_key_versions = oci.Kms.get_key_versions(key_id=oci_kms_key["test_key"]["id"],
        management_endpoint=var["key_version_management_endpoint"])
    ```


    :param str key_id: The OCID of the key.
    :param str management_endpoint: The service endpoint to perform management operations against. Management operations include 'Create,' 'Update,' 'List,' 'Get,' and 'Delete' operations. See Vault Management endpoint.
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['keyId'] = key_id
    __args__['managementEndpoint'] = management_endpoint
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Kms/getKeyVersions:getKeyVersions', __args__, opts=opts, typ=GetKeyVersionsResult).value

    return AwaitableGetKeyVersionsResult(
        filters=__ret__.filters,
        id=__ret__.id,
        key_id=__ret__.key_id,
        key_versions=__ret__.key_versions,
        management_endpoint=__ret__.management_endpoint)


@_utilities.lift_output_func(get_key_versions)
def get_key_versions_output(filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetKeyVersionsFilterArgs']]]]] = None,
                            key_id: Optional[pulumi.Input[str]] = None,
                            management_endpoint: Optional[pulumi.Input[str]] = None,
                            opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetKeyVersionsResult]:
    """
    This data source provides the list of Key Versions in Oracle Cloud Infrastructure Kms service.

    Lists all [KeyVersion](https://docs.cloud.oracle.com/iaas/api/#/en/key/latest/KeyVersion/) resources for the specified
    master encryption key.

    As a management operation, this call is subject to a Key Management limit that applies to the total number
    of requests across all management read operations. Key Management might throttle this call to reject an
    otherwise valid request when the total rate of management read operations exceeds 10 requests per second
    for a given tenancy.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_key_versions = oci.Kms.get_key_versions(key_id=oci_kms_key["test_key"]["id"],
        management_endpoint=var["key_version_management_endpoint"])
    ```


    :param str key_id: The OCID of the key.
    :param str management_endpoint: The service endpoint to perform management operations against. Management operations include 'Create,' 'Update,' 'List,' 'Get,' and 'Delete' operations. See Vault Management endpoint.
    """
    ...