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
    'GetManagedPreferredCredentialsResult',
    'AwaitableGetManagedPreferredCredentialsResult',
    'get_managed_preferred_credentials',
    'get_managed_preferred_credentials_output',
]

@pulumi.output_type
class GetManagedPreferredCredentialsResult:
    """
    A collection of values returned by getManagedPreferredCredentials.
    """
    def __init__(__self__, filters=None, id=None, managed_database_id=None, preferred_credential_collections=None):
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if managed_database_id and not isinstance(managed_database_id, str):
            raise TypeError("Expected argument 'managed_database_id' to be a str")
        pulumi.set(__self__, "managed_database_id", managed_database_id)
        if preferred_credential_collections and not isinstance(preferred_credential_collections, list):
            raise TypeError("Expected argument 'preferred_credential_collections' to be a list")
        pulumi.set(__self__, "preferred_credential_collections", preferred_credential_collections)

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetManagedPreferredCredentialsFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="managedDatabaseId")
    def managed_database_id(self) -> _builtins.str:
        return pulumi.get(self, "managed_database_id")

    @_builtins.property
    @pulumi.getter(name="preferredCredentialCollections")
    def preferred_credential_collections(self) -> Sequence['outputs.GetManagedPreferredCredentialsPreferredCredentialCollectionResult']:
        """
        The list of preferred_credential_collection.
        """
        return pulumi.get(self, "preferred_credential_collections")


class AwaitableGetManagedPreferredCredentialsResult(GetManagedPreferredCredentialsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetManagedPreferredCredentialsResult(
            filters=self.filters,
            id=self.id,
            managed_database_id=self.managed_database_id,
            preferred_credential_collections=self.preferred_credential_collections)


def get_managed_preferred_credentials(filters: Optional[Sequence[Union['GetManagedPreferredCredentialsFilterArgs', 'GetManagedPreferredCredentialsFilterArgsDict']]] = None,
                                      managed_database_id: Optional[_builtins.str] = None,
                                      opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetManagedPreferredCredentialsResult:
    """
    This data source provides the list of Managed Database Preferred Credentials in Oracle Cloud Infrastructure Database Management service.

    Gets the list of preferred credentials for a given Managed Database.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_managed_database_preferred_credentials = oci.Database.get_managed_preferred_credentials(managed_database_id=test_managed_database["id"])
    ```


    :param _builtins.str managed_database_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['managedDatabaseId'] = managed_database_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Database/getManagedPreferredCredentials:getManagedPreferredCredentials', __args__, opts=opts, typ=GetManagedPreferredCredentialsResult).value

    return AwaitableGetManagedPreferredCredentialsResult(
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        managed_database_id=pulumi.get(__ret__, 'managed_database_id'),
        preferred_credential_collections=pulumi.get(__ret__, 'preferred_credential_collections'))
def get_managed_preferred_credentials_output(filters: Optional[pulumi.Input[Optional[Sequence[Union['GetManagedPreferredCredentialsFilterArgs', 'GetManagedPreferredCredentialsFilterArgsDict']]]]] = None,
                                             managed_database_id: Optional[pulumi.Input[_builtins.str]] = None,
                                             opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetManagedPreferredCredentialsResult]:
    """
    This data source provides the list of Managed Database Preferred Credentials in Oracle Cloud Infrastructure Database Management service.

    Gets the list of preferred credentials for a given Managed Database.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_managed_database_preferred_credentials = oci.Database.get_managed_preferred_credentials(managed_database_id=test_managed_database["id"])
    ```


    :param _builtins.str managed_database_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['managedDatabaseId'] = managed_database_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Database/getManagedPreferredCredentials:getManagedPreferredCredentials', __args__, opts=opts, typ=GetManagedPreferredCredentialsResult)
    return __ret__.apply(lambda __response__: GetManagedPreferredCredentialsResult(
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        managed_database_id=pulumi.get(__response__, 'managed_database_id'),
        preferred_credential_collections=pulumi.get(__response__, 'preferred_credential_collections')))
