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
    'GetIndexesResult',
    'AwaitableGetIndexesResult',
    'get_indexes',
    'get_indexes_output',
]

@pulumi.output_type
class GetIndexesResult:
    """
    A collection of values returned by getIndexes.
    """
    def __init__(__self__, compartment_id=None, filters=None, id=None, index_collections=None, name=None, state=None, table_name_or_id=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if index_collections and not isinstance(index_collections, list):
            raise TypeError("Expected argument 'index_collections' to be a list")
        pulumi.set(__self__, "index_collections", index_collections)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if table_name_or_id and not isinstance(table_name_or_id, str):
            raise TypeError("Expected argument 'table_name_or_id' to be a str")
        pulumi.set(__self__, "table_name_or_id", table_name_or_id)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[str]:
        """
        Compartment Identifier.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetIndexesFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="indexCollections")
    def index_collections(self) -> Sequence['outputs.GetIndexesIndexCollectionResult']:
        """
        The list of index_collection.
        """
        return pulumi.get(self, "index_collections")

    @property
    @pulumi.getter
    def name(self) -> Optional[str]:
        """
        Index name.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter
    def state(self) -> Optional[str]:
        """
        The state of an index.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="tableNameOrId")
    def table_name_or_id(self) -> str:
        return pulumi.get(self, "table_name_or_id")


class AwaitableGetIndexesResult(GetIndexesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetIndexesResult(
            compartment_id=self.compartment_id,
            filters=self.filters,
            id=self.id,
            index_collections=self.index_collections,
            name=self.name,
            state=self.state,
            table_name_or_id=self.table_name_or_id)


def get_indexes(compartment_id: Optional[str] = None,
                filters: Optional[Sequence[pulumi.InputType['GetIndexesFilterArgs']]] = None,
                name: Optional[str] = None,
                state: Optional[str] = None,
                table_name_or_id: Optional[str] = None,
                opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetIndexesResult:
    """
    This data source provides the list of Indexes in Oracle Cloud Infrastructure NoSQL Database service.

    Get a list of indexes on a table.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_indexes = oci.Nosql.get_indexes(table_name_or_id=oci_nosql_table_name_or["test_table_name_or"]["id"],
        compartment_id=var["compartment_id"],
        name=var["index_name"],
        state=var["index_state"])
    ```


    :param str compartment_id: The ID of a table's compartment. When a table is identified by name, the compartmentId is often needed to provide context for interpreting the name.
    :param str name: A shell-globbing-style (*?[]) filter for names.
    :param str state: Filter list by the lifecycle state of the item.
    :param str table_name_or_id: A table name within the compartment, or a table OCID.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    __args__['name'] = name
    __args__['state'] = state
    __args__['tableNameOrId'] = table_name_or_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Nosql/getIndexes:getIndexes', __args__, opts=opts, typ=GetIndexesResult).value

    return AwaitableGetIndexesResult(
        compartment_id=__ret__.compartment_id,
        filters=__ret__.filters,
        id=__ret__.id,
        index_collections=__ret__.index_collections,
        name=__ret__.name,
        state=__ret__.state,
        table_name_or_id=__ret__.table_name_or_id)


@_utilities.lift_output_func(get_indexes)
def get_indexes_output(compartment_id: Optional[pulumi.Input[Optional[str]]] = None,
                       filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetIndexesFilterArgs']]]]] = None,
                       name: Optional[pulumi.Input[Optional[str]]] = None,
                       state: Optional[pulumi.Input[Optional[str]]] = None,
                       table_name_or_id: Optional[pulumi.Input[str]] = None,
                       opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetIndexesResult]:
    """
    This data source provides the list of Indexes in Oracle Cloud Infrastructure NoSQL Database service.

    Get a list of indexes on a table.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_indexes = oci.Nosql.get_indexes(table_name_or_id=oci_nosql_table_name_or["test_table_name_or"]["id"],
        compartment_id=var["compartment_id"],
        name=var["index_name"],
        state=var["index_state"])
    ```


    :param str compartment_id: The ID of a table's compartment. When a table is identified by name, the compartmentId is often needed to provide context for interpreting the name.
    :param str name: A shell-globbing-style (*?[]) filter for names.
    :param str state: Filter list by the lifecycle state of the item.
    :param str table_name_or_id: A table name within the compartment, or a table OCID.
    """
    ...