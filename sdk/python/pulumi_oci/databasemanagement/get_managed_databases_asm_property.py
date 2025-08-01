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

__all__ = [
    'GetManagedDatabasesAsmPropertyResult',
    'AwaitableGetManagedDatabasesAsmPropertyResult',
    'get_managed_databases_asm_property',
    'get_managed_databases_asm_property_output',
]

@pulumi.output_type
class GetManagedDatabasesAsmPropertyResult:
    """
    A collection of values returned by getManagedDatabasesAsmProperty.
    """
    def __init__(__self__, id=None, items=None, managed_database_id=None, name=None):
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if items and not isinstance(items, list):
            raise TypeError("Expected argument 'items' to be a list")
        pulumi.set(__self__, "items", items)
        if managed_database_id and not isinstance(managed_database_id, str):
            raise TypeError("Expected argument 'managed_database_id' to be a str")
        pulumi.set(__self__, "managed_database_id", managed_database_id)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter
    def items(self) -> Sequence['outputs.GetManagedDatabasesAsmPropertyItemResult']:
        """
        An array of AsmPropertySummary resources.
        """
        return pulumi.get(self, "items")

    @_builtins.property
    @pulumi.getter(name="managedDatabaseId")
    def managed_database_id(self) -> _builtins.str:
        return pulumi.get(self, "managed_database_id")

    @_builtins.property
    @pulumi.getter
    def name(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "name")


class AwaitableGetManagedDatabasesAsmPropertyResult(GetManagedDatabasesAsmPropertyResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetManagedDatabasesAsmPropertyResult(
            id=self.id,
            items=self.items,
            managed_database_id=self.managed_database_id,
            name=self.name)


def get_managed_databases_asm_property(managed_database_id: Optional[_builtins.str] = None,
                                       name: Optional[_builtins.str] = None,
                                       opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetManagedDatabasesAsmPropertyResult:
    """
    This data source provides details about a specific Managed Databases Asm Property resource in Oracle Cloud Infrastructure Database Management service.

    Gets the list of ASM properties for the specified managedDatabaseId.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_managed_databases_asm_property = oci.DatabaseManagement.get_managed_databases_asm_property(managed_database_id=test_managed_database["id"],
        name=managed_databases_asm_property_name)
    ```


    :param _builtins.str managed_database_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
    :param _builtins.str name: A filter to return only resources that match the entire name.
    """
    __args__ = dict()
    __args__['managedDatabaseId'] = managed_database_id
    __args__['name'] = name
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DatabaseManagement/getManagedDatabasesAsmProperty:getManagedDatabasesAsmProperty', __args__, opts=opts, typ=GetManagedDatabasesAsmPropertyResult).value

    return AwaitableGetManagedDatabasesAsmPropertyResult(
        id=pulumi.get(__ret__, 'id'),
        items=pulumi.get(__ret__, 'items'),
        managed_database_id=pulumi.get(__ret__, 'managed_database_id'),
        name=pulumi.get(__ret__, 'name'))
def get_managed_databases_asm_property_output(managed_database_id: Optional[pulumi.Input[_builtins.str]] = None,
                                              name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                              opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetManagedDatabasesAsmPropertyResult]:
    """
    This data source provides details about a specific Managed Databases Asm Property resource in Oracle Cloud Infrastructure Database Management service.

    Gets the list of ASM properties for the specified managedDatabaseId.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_managed_databases_asm_property = oci.DatabaseManagement.get_managed_databases_asm_property(managed_database_id=test_managed_database["id"],
        name=managed_databases_asm_property_name)
    ```


    :param _builtins.str managed_database_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
    :param _builtins.str name: A filter to return only resources that match the entire name.
    """
    __args__ = dict()
    __args__['managedDatabaseId'] = managed_database_id
    __args__['name'] = name
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:DatabaseManagement/getManagedDatabasesAsmProperty:getManagedDatabasesAsmProperty', __args__, opts=opts, typ=GetManagedDatabasesAsmPropertyResult)
    return __ret__.apply(lambda __response__: GetManagedDatabasesAsmPropertyResult(
        id=pulumi.get(__response__, 'id'),
        items=pulumi.get(__response__, 'items'),
        managed_database_id=pulumi.get(__response__, 'managed_database_id'),
        name=pulumi.get(__response__, 'name')))
