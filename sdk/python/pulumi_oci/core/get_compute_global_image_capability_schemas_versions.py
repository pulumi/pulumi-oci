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
    'GetComputeGlobalImageCapabilitySchemasVersionsResult',
    'AwaitableGetComputeGlobalImageCapabilitySchemasVersionsResult',
    'get_compute_global_image_capability_schemas_versions',
    'get_compute_global_image_capability_schemas_versions_output',
]

@pulumi.output_type
class GetComputeGlobalImageCapabilitySchemasVersionsResult:
    """
    A collection of values returned by getComputeGlobalImageCapabilitySchemasVersions.
    """
    def __init__(__self__, compute_global_image_capability_schema_id=None, compute_global_image_capability_schema_versions=None, display_name=None, filters=None, id=None):
        if compute_global_image_capability_schema_id and not isinstance(compute_global_image_capability_schema_id, str):
            raise TypeError("Expected argument 'compute_global_image_capability_schema_id' to be a str")
        pulumi.set(__self__, "compute_global_image_capability_schema_id", compute_global_image_capability_schema_id)
        if compute_global_image_capability_schema_versions and not isinstance(compute_global_image_capability_schema_versions, list):
            raise TypeError("Expected argument 'compute_global_image_capability_schema_versions' to be a list")
        pulumi.set(__self__, "compute_global_image_capability_schema_versions", compute_global_image_capability_schema_versions)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)

    @_builtins.property
    @pulumi.getter(name="computeGlobalImageCapabilitySchemaId")
    def compute_global_image_capability_schema_id(self) -> _builtins.str:
        """
        The ocid of the compute global image capability schema
        """
        return pulumi.get(self, "compute_global_image_capability_schema_id")

    @_builtins.property
    @pulumi.getter(name="computeGlobalImageCapabilitySchemaVersions")
    def compute_global_image_capability_schema_versions(self) -> Sequence['outputs.GetComputeGlobalImageCapabilitySchemasVersionsComputeGlobalImageCapabilitySchemaVersionResult']:
        """
        The list of compute_global_image_capability_schema_versions.
        """
        return pulumi.get(self, "compute_global_image_capability_schema_versions")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[_builtins.str]:
        """
        A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetComputeGlobalImageCapabilitySchemasVersionsFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")


class AwaitableGetComputeGlobalImageCapabilitySchemasVersionsResult(GetComputeGlobalImageCapabilitySchemasVersionsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetComputeGlobalImageCapabilitySchemasVersionsResult(
            compute_global_image_capability_schema_id=self.compute_global_image_capability_schema_id,
            compute_global_image_capability_schema_versions=self.compute_global_image_capability_schema_versions,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id)


def get_compute_global_image_capability_schemas_versions(compute_global_image_capability_schema_id: Optional[_builtins.str] = None,
                                                         display_name: Optional[_builtins.str] = None,
                                                         filters: Optional[Sequence[Union['GetComputeGlobalImageCapabilitySchemasVersionsFilterArgs', 'GetComputeGlobalImageCapabilitySchemasVersionsFilterArgsDict']]] = None,
                                                         opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetComputeGlobalImageCapabilitySchemasVersionsResult:
    """
    This data source provides the list of Compute Global Image Capability Schemas Versions in Oracle Cloud Infrastructure Core service.

    Lists Compute Global Image Capability Schema versions in the specified compartment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_compute_global_image_capability_schemas_versions = oci.Core.get_compute_global_image_capability_schemas_versions(compute_global_image_capability_schema_id=test_compute_global_image_capability_schema["id"],
        display_name=compute_global_image_capability_schemas_version_display_name)
    ```


    :param _builtins.str compute_global_image_capability_schema_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute global image capability schema
    :param _builtins.str display_name: A filter to return only resources that match the given display name exactly.
    """
    __args__ = dict()
    __args__['computeGlobalImageCapabilitySchemaId'] = compute_global_image_capability_schema_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Core/getComputeGlobalImageCapabilitySchemasVersions:getComputeGlobalImageCapabilitySchemasVersions', __args__, opts=opts, typ=GetComputeGlobalImageCapabilitySchemasVersionsResult).value

    return AwaitableGetComputeGlobalImageCapabilitySchemasVersionsResult(
        compute_global_image_capability_schema_id=pulumi.get(__ret__, 'compute_global_image_capability_schema_id'),
        compute_global_image_capability_schema_versions=pulumi.get(__ret__, 'compute_global_image_capability_schema_versions'),
        display_name=pulumi.get(__ret__, 'display_name'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'))
def get_compute_global_image_capability_schemas_versions_output(compute_global_image_capability_schema_id: Optional[pulumi.Input[_builtins.str]] = None,
                                                                display_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                                filters: Optional[pulumi.Input[Optional[Sequence[Union['GetComputeGlobalImageCapabilitySchemasVersionsFilterArgs', 'GetComputeGlobalImageCapabilitySchemasVersionsFilterArgsDict']]]]] = None,
                                                                opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetComputeGlobalImageCapabilitySchemasVersionsResult]:
    """
    This data source provides the list of Compute Global Image Capability Schemas Versions in Oracle Cloud Infrastructure Core service.

    Lists Compute Global Image Capability Schema versions in the specified compartment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_compute_global_image_capability_schemas_versions = oci.Core.get_compute_global_image_capability_schemas_versions(compute_global_image_capability_schema_id=test_compute_global_image_capability_schema["id"],
        display_name=compute_global_image_capability_schemas_version_display_name)
    ```


    :param _builtins.str compute_global_image_capability_schema_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute global image capability schema
    :param _builtins.str display_name: A filter to return only resources that match the given display name exactly.
    """
    __args__ = dict()
    __args__['computeGlobalImageCapabilitySchemaId'] = compute_global_image_capability_schema_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Core/getComputeGlobalImageCapabilitySchemasVersions:getComputeGlobalImageCapabilitySchemasVersions', __args__, opts=opts, typ=GetComputeGlobalImageCapabilitySchemasVersionsResult)
    return __ret__.apply(lambda __response__: GetComputeGlobalImageCapabilitySchemasVersionsResult(
        compute_global_image_capability_schema_id=pulumi.get(__response__, 'compute_global_image_capability_schema_id'),
        compute_global_image_capability_schema_versions=pulumi.get(__response__, 'compute_global_image_capability_schema_versions'),
        display_name=pulumi.get(__response__, 'display_name'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id')))
