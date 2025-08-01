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
    'GetManagedDatabaseTableStatisticsResult',
    'AwaitableGetManagedDatabaseTableStatisticsResult',
    'get_managed_database_table_statistics',
    'get_managed_database_table_statistics_output',
]

@pulumi.output_type
class GetManagedDatabaseTableStatisticsResult:
    """
    A collection of values returned by getManagedDatabaseTableStatistics.
    """
    def __init__(__self__, filters=None, id=None, managed_database_id=None, table_statistics_collections=None):
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if managed_database_id and not isinstance(managed_database_id, str):
            raise TypeError("Expected argument 'managed_database_id' to be a str")
        pulumi.set(__self__, "managed_database_id", managed_database_id)
        if table_statistics_collections and not isinstance(table_statistics_collections, list):
            raise TypeError("Expected argument 'table_statistics_collections' to be a list")
        pulumi.set(__self__, "table_statistics_collections", table_statistics_collections)

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetManagedDatabaseTableStatisticsFilterResult']]:
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
    @pulumi.getter(name="tableStatisticsCollections")
    def table_statistics_collections(self) -> Sequence['outputs.GetManagedDatabaseTableStatisticsTableStatisticsCollectionResult']:
        """
        The list of table_statistics_collection.
        """
        return pulumi.get(self, "table_statistics_collections")


class AwaitableGetManagedDatabaseTableStatisticsResult(GetManagedDatabaseTableStatisticsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetManagedDatabaseTableStatisticsResult(
            filters=self.filters,
            id=self.id,
            managed_database_id=self.managed_database_id,
            table_statistics_collections=self.table_statistics_collections)


def get_managed_database_table_statistics(filters: Optional[Sequence[Union['GetManagedDatabaseTableStatisticsFilterArgs', 'GetManagedDatabaseTableStatisticsFilterArgsDict']]] = None,
                                          managed_database_id: Optional[_builtins.str] = None,
                                          opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetManagedDatabaseTableStatisticsResult:
    """
    This data source provides the list of Managed Database Table Statistics in Oracle Cloud Infrastructure Database Management service.

    Gets the number of database table objects grouped by different statuses such as
    Not Stale Stats, Stale Stats, and No Stats. This also includes the percentage of each status.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_managed_database_table_statistics = oci.DatabaseManagement.get_managed_database_table_statistics(managed_database_id=test_managed_database["id"])
    ```


    :param _builtins.str managed_database_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['managedDatabaseId'] = managed_database_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DatabaseManagement/getManagedDatabaseTableStatistics:getManagedDatabaseTableStatistics', __args__, opts=opts, typ=GetManagedDatabaseTableStatisticsResult).value

    return AwaitableGetManagedDatabaseTableStatisticsResult(
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        managed_database_id=pulumi.get(__ret__, 'managed_database_id'),
        table_statistics_collections=pulumi.get(__ret__, 'table_statistics_collections'))
def get_managed_database_table_statistics_output(filters: Optional[pulumi.Input[Optional[Sequence[Union['GetManagedDatabaseTableStatisticsFilterArgs', 'GetManagedDatabaseTableStatisticsFilterArgsDict']]]]] = None,
                                                 managed_database_id: Optional[pulumi.Input[_builtins.str]] = None,
                                                 opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetManagedDatabaseTableStatisticsResult]:
    """
    This data source provides the list of Managed Database Table Statistics in Oracle Cloud Infrastructure Database Management service.

    Gets the number of database table objects grouped by different statuses such as
    Not Stale Stats, Stale Stats, and No Stats. This also includes the percentage of each status.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_managed_database_table_statistics = oci.DatabaseManagement.get_managed_database_table_statistics(managed_database_id=test_managed_database["id"])
    ```


    :param _builtins.str managed_database_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['managedDatabaseId'] = managed_database_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:DatabaseManagement/getManagedDatabaseTableStatistics:getManagedDatabaseTableStatistics', __args__, opts=opts, typ=GetManagedDatabaseTableStatisticsResult)
    return __ret__.apply(lambda __response__: GetManagedDatabaseTableStatisticsResult(
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        managed_database_id=pulumi.get(__response__, 'managed_database_id'),
        table_statistics_collections=pulumi.get(__response__, 'table_statistics_collections')))
