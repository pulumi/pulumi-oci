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
    'GetManagedDatabaseSqlTuningSetResult',
    'AwaitableGetManagedDatabaseSqlTuningSetResult',
    'get_managed_database_sql_tuning_set',
    'get_managed_database_sql_tuning_set_output',
]

@pulumi.output_type
class GetManagedDatabaseSqlTuningSetResult:
    """
    A collection of values returned by getManagedDatabaseSqlTuningSet.
    """
    def __init__(__self__, id=None, items=None, managed_database_id=None, name_contains=None, owner=None):
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if items and not isinstance(items, list):
            raise TypeError("Expected argument 'items' to be a list")
        pulumi.set(__self__, "items", items)
        if managed_database_id and not isinstance(managed_database_id, str):
            raise TypeError("Expected argument 'managed_database_id' to be a str")
        pulumi.set(__self__, "managed_database_id", managed_database_id)
        if name_contains and not isinstance(name_contains, str):
            raise TypeError("Expected argument 'name_contains' to be a str")
        pulumi.set(__self__, "name_contains", name_contains)
        if owner and not isinstance(owner, str):
            raise TypeError("Expected argument 'owner' to be a str")
        pulumi.set(__self__, "owner", owner)

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def items(self) -> Sequence['outputs.GetManagedDatabaseSqlTuningSetItemResult']:
        """
        The details in the SQL tuning set summary.
        """
        return pulumi.get(self, "items")

    @property
    @pulumi.getter(name="managedDatabaseId")
    def managed_database_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
        """
        return pulumi.get(self, "managed_database_id")

    @property
    @pulumi.getter(name="nameContains")
    def name_contains(self) -> Optional[str]:
        return pulumi.get(self, "name_contains")

    @property
    @pulumi.getter
    def owner(self) -> Optional[str]:
        """
        The owner of the SQL tuning set.
        """
        return pulumi.get(self, "owner")


class AwaitableGetManagedDatabaseSqlTuningSetResult(GetManagedDatabaseSqlTuningSetResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetManagedDatabaseSqlTuningSetResult(
            id=self.id,
            items=self.items,
            managed_database_id=self.managed_database_id,
            name_contains=self.name_contains,
            owner=self.owner)


def get_managed_database_sql_tuning_set(managed_database_id: Optional[str] = None,
                                        name_contains: Optional[str] = None,
                                        owner: Optional[str] = None,
                                        opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetManagedDatabaseSqlTuningSetResult:
    """
    This data source provides details about a specific Managed Database Sql Tuning Set resource in Oracle Cloud Infrastructure Database Management service.

    Lists the SQL tuning sets for the specified Managed Database.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_managed_database_sql_tuning_set = oci.DatabaseManagement.get_managed_database_sql_tuning_set(managed_database_id=oci_database_management_managed_database["test_managed_database"]["id"],
        name_contains=var["managed_database_sql_tuning_set_name_contains"],
        owner=var["managed_database_sql_tuning_set_owner"])
    ```


    :param str managed_database_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
    :param str name_contains: Allow searching the name of the SQL tuning set by partial matching. The search is case insensitive.
    :param str owner: The owner of the SQL tuning set.
    """
    __args__ = dict()
    __args__['managedDatabaseId'] = managed_database_id
    __args__['nameContains'] = name_contains
    __args__['owner'] = owner
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DatabaseManagement/getManagedDatabaseSqlTuningSet:getManagedDatabaseSqlTuningSet', __args__, opts=opts, typ=GetManagedDatabaseSqlTuningSetResult).value

    return AwaitableGetManagedDatabaseSqlTuningSetResult(
        id=__ret__.id,
        items=__ret__.items,
        managed_database_id=__ret__.managed_database_id,
        name_contains=__ret__.name_contains,
        owner=__ret__.owner)


@_utilities.lift_output_func(get_managed_database_sql_tuning_set)
def get_managed_database_sql_tuning_set_output(managed_database_id: Optional[pulumi.Input[str]] = None,
                                               name_contains: Optional[pulumi.Input[Optional[str]]] = None,
                                               owner: Optional[pulumi.Input[Optional[str]]] = None,
                                               opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetManagedDatabaseSqlTuningSetResult]:
    """
    This data source provides details about a specific Managed Database Sql Tuning Set resource in Oracle Cloud Infrastructure Database Management service.

    Lists the SQL tuning sets for the specified Managed Database.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_managed_database_sql_tuning_set = oci.DatabaseManagement.get_managed_database_sql_tuning_set(managed_database_id=oci_database_management_managed_database["test_managed_database"]["id"],
        name_contains=var["managed_database_sql_tuning_set_name_contains"],
        owner=var["managed_database_sql_tuning_set_owner"])
    ```


    :param str managed_database_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
    :param str name_contains: Allow searching the name of the SQL tuning set by partial matching. The search is case insensitive.
    :param str owner: The owner of the SQL tuning set.
    """
    ...