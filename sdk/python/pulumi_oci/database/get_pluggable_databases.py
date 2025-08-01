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
    'GetPluggableDatabasesResult',
    'AwaitableGetPluggableDatabasesResult',
    'get_pluggable_databases',
    'get_pluggable_databases_output',
]

@pulumi.output_type
class GetPluggableDatabasesResult:
    """
    A collection of values returned by getPluggableDatabases.
    """
    def __init__(__self__, compartment_id=None, database_id=None, filters=None, id=None, pdb_name=None, pluggable_databases=None, state=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if database_id and not isinstance(database_id, str):
            raise TypeError("Expected argument 'database_id' to be a str")
        pulumi.set(__self__, "database_id", database_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if pdb_name and not isinstance(pdb_name, str):
            raise TypeError("Expected argument 'pdb_name' to be a str")
        pulumi.set(__self__, "pdb_name", pdb_name)
        if pluggable_databases and not isinstance(pluggable_databases, list):
            raise TypeError("Expected argument 'pluggable_databases' to be a list")
        pulumi.set(__self__, "pluggable_databases", pluggable_databases)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="databaseId")
    def database_id(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "database_id")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetPluggableDatabasesFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="pdbName")
    def pdb_name(self) -> Optional[_builtins.str]:
        """
        The name for the pluggable database (PDB). The name is unique in the context of a [container database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/Database/). The name must begin with an alphabetic character and can contain a maximum of thirty alphanumeric characters. Special characters are not permitted. The pluggable database name should not be same as the container database name.
        """
        return pulumi.get(self, "pdb_name")

    @_builtins.property
    @pulumi.getter(name="pluggableDatabases")
    def pluggable_databases(self) -> Sequence['outputs.GetPluggableDatabasesPluggableDatabaseResult']:
        """
        The list of pluggable_databases.
        """
        return pulumi.get(self, "pluggable_databases")

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[_builtins.str]:
        """
        The current state of the pluggable database.
        """
        return pulumi.get(self, "state")


class AwaitableGetPluggableDatabasesResult(GetPluggableDatabasesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetPluggableDatabasesResult(
            compartment_id=self.compartment_id,
            database_id=self.database_id,
            filters=self.filters,
            id=self.id,
            pdb_name=self.pdb_name,
            pluggable_databases=self.pluggable_databases,
            state=self.state)


def get_pluggable_databases(compartment_id: Optional[_builtins.str] = None,
                            database_id: Optional[_builtins.str] = None,
                            filters: Optional[Sequence[Union['GetPluggableDatabasesFilterArgs', 'GetPluggableDatabasesFilterArgsDict']]] = None,
                            pdb_name: Optional[_builtins.str] = None,
                            state: Optional[_builtins.str] = None,
                            opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetPluggableDatabasesResult:
    """
    This data source provides the list of Pluggable Databases in Oracle Cloud Infrastructure Database service.

    Gets a list of the pluggable databases in a database or compartment. You must provide either a `databaseId` or `compartmentId` value.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_pluggable_databases = oci.Database.get_pluggable_databases(compartment_id=compartment_id,
        database_id=test_database["id"],
        pdb_name=pluggable_database_pdb_name,
        state=pluggable_database_state)
    ```


    :param _builtins.str compartment_id: The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    :param _builtins.str database_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database.
    :param _builtins.str pdb_name: A filter to return only pluggable databases that match the entire name given. The match is not case sensitive.
    :param _builtins.str state: A filter to return only resources that match the given lifecycle state exactly.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['databaseId'] = database_id
    __args__['filters'] = filters
    __args__['pdbName'] = pdb_name
    __args__['state'] = state
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Database/getPluggableDatabases:getPluggableDatabases', __args__, opts=opts, typ=GetPluggableDatabasesResult).value

    return AwaitableGetPluggableDatabasesResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        database_id=pulumi.get(__ret__, 'database_id'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        pdb_name=pulumi.get(__ret__, 'pdb_name'),
        pluggable_databases=pulumi.get(__ret__, 'pluggable_databases'),
        state=pulumi.get(__ret__, 'state'))
def get_pluggable_databases_output(compartment_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                   database_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                   filters: Optional[pulumi.Input[Optional[Sequence[Union['GetPluggableDatabasesFilterArgs', 'GetPluggableDatabasesFilterArgsDict']]]]] = None,
                                   pdb_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                   state: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                   opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetPluggableDatabasesResult]:
    """
    This data source provides the list of Pluggable Databases in Oracle Cloud Infrastructure Database service.

    Gets a list of the pluggable databases in a database or compartment. You must provide either a `databaseId` or `compartmentId` value.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_pluggable_databases = oci.Database.get_pluggable_databases(compartment_id=compartment_id,
        database_id=test_database["id"],
        pdb_name=pluggable_database_pdb_name,
        state=pluggable_database_state)
    ```


    :param _builtins.str compartment_id: The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    :param _builtins.str database_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database.
    :param _builtins.str pdb_name: A filter to return only pluggable databases that match the entire name given. The match is not case sensitive.
    :param _builtins.str state: A filter to return only resources that match the given lifecycle state exactly.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['databaseId'] = database_id
    __args__['filters'] = filters
    __args__['pdbName'] = pdb_name
    __args__['state'] = state
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Database/getPluggableDatabases:getPluggableDatabases', __args__, opts=opts, typ=GetPluggableDatabasesResult)
    return __ret__.apply(lambda __response__: GetPluggableDatabasesResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        database_id=pulumi.get(__response__, 'database_id'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        pdb_name=pulumi.get(__response__, 'pdb_name'),
        pluggable_databases=pulumi.get(__response__, 'pluggable_databases'),
        state=pulumi.get(__response__, 'state')))
