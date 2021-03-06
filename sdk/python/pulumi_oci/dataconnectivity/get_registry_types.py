# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities
from . import outputs
from ._inputs import *

__all__ = [
    'GetRegistryTypesResult',
    'AwaitableGetRegistryTypesResult',
    'get_registry_types',
    'get_registry_types_output',
]

@pulumi.output_type
class GetRegistryTypesResult:
    """
    A collection of values returned by getRegistryTypes.
    """
    def __init__(__self__, filters=None, id=None, name=None, registry_id=None, type=None, types_summary_collections=None):
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if registry_id and not isinstance(registry_id, str):
            raise TypeError("Expected argument 'registry_id' to be a str")
        pulumi.set(__self__, "registry_id", registry_id)
        if type and not isinstance(type, str):
            raise TypeError("Expected argument 'type' to be a str")
        pulumi.set(__self__, "type", type)
        if types_summary_collections and not isinstance(types_summary_collections, list):
            raise TypeError("Expected argument 'types_summary_collections' to be a list")
        pulumi.set(__self__, "types_summary_collections", types_summary_collections)

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetRegistryTypesFilterResult']]:
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
        The name of of the Attribute.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter(name="registryId")
    def registry_id(self) -> str:
        return pulumi.get(self, "registry_id")

    @property
    @pulumi.getter
    def type(self) -> Optional[str]:
        return pulumi.get(self, "type")

    @property
    @pulumi.getter(name="typesSummaryCollections")
    def types_summary_collections(self) -> Sequence['outputs.GetRegistryTypesTypesSummaryCollectionResult']:
        """
        The list of types_summary_collection.
        """
        return pulumi.get(self, "types_summary_collections")


class AwaitableGetRegistryTypesResult(GetRegistryTypesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetRegistryTypesResult(
            filters=self.filters,
            id=self.id,
            name=self.name,
            registry_id=self.registry_id,
            type=self.type,
            types_summary_collections=self.types_summary_collections)


def get_registry_types(filters: Optional[Sequence[pulumi.InputType['GetRegistryTypesFilterArgs']]] = None,
                       name: Optional[str] = None,
                       registry_id: Optional[str] = None,
                       type: Optional[str] = None,
                       opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetRegistryTypesResult:
    """
    This data source provides the list of Registry Types in Oracle Cloud Infrastructure Data Connectivity service.

    This endpoint retrieves list of all the supported connector types

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_registry_types = oci.DataConnectivity.get_registry_types(registry_id=oci_data_connectivity_registry["test_registry"]["id"],
        name=var["registry_type_name"],
        type=var["registry_type_type"])
    ```


    :param str name: Used to filter by the name of the object.
    :param str registry_id: The registry Ocid.
    :param str type: Type of the object to filter the results with.
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['name'] = name
    __args__['registryId'] = registry_id
    __args__['type'] = type
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:DataConnectivity/getRegistryTypes:getRegistryTypes', __args__, opts=opts, typ=GetRegistryTypesResult).value

    return AwaitableGetRegistryTypesResult(
        filters=__ret__.filters,
        id=__ret__.id,
        name=__ret__.name,
        registry_id=__ret__.registry_id,
        type=__ret__.type,
        types_summary_collections=__ret__.types_summary_collections)


@_utilities.lift_output_func(get_registry_types)
def get_registry_types_output(filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetRegistryTypesFilterArgs']]]]] = None,
                              name: Optional[pulumi.Input[Optional[str]]] = None,
                              registry_id: Optional[pulumi.Input[str]] = None,
                              type: Optional[pulumi.Input[Optional[str]]] = None,
                              opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetRegistryTypesResult]:
    """
    This data source provides the list of Registry Types in Oracle Cloud Infrastructure Data Connectivity service.

    This endpoint retrieves list of all the supported connector types

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_registry_types = oci.DataConnectivity.get_registry_types(registry_id=oci_data_connectivity_registry["test_registry"]["id"],
        name=var["registry_type_name"],
        type=var["registry_type_type"])
    ```


    :param str name: Used to filter by the name of the object.
    :param str registry_id: The registry Ocid.
    :param str type: Type of the object to filter the results with.
    """
    ...
