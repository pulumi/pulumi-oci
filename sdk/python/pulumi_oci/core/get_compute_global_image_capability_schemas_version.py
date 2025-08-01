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

__all__ = [
    'GetComputeGlobalImageCapabilitySchemasVersionResult',
    'AwaitableGetComputeGlobalImageCapabilitySchemasVersionResult',
    'get_compute_global_image_capability_schemas_version',
    'get_compute_global_image_capability_schemas_version_output',
]

@pulumi.output_type
class GetComputeGlobalImageCapabilitySchemasVersionResult:
    """
    A collection of values returned by getComputeGlobalImageCapabilitySchemasVersion.
    """
    def __init__(__self__, compute_global_image_capability_schema_id=None, compute_global_image_capability_schema_version_name=None, display_name=None, id=None, name=None, schema_data=None, time_created=None):
        if compute_global_image_capability_schema_id and not isinstance(compute_global_image_capability_schema_id, str):
            raise TypeError("Expected argument 'compute_global_image_capability_schema_id' to be a str")
        pulumi.set(__self__, "compute_global_image_capability_schema_id", compute_global_image_capability_schema_id)
        if compute_global_image_capability_schema_version_name and not isinstance(compute_global_image_capability_schema_version_name, str):
            raise TypeError("Expected argument 'compute_global_image_capability_schema_version_name' to be a str")
        pulumi.set(__self__, "compute_global_image_capability_schema_version_name", compute_global_image_capability_schema_version_name)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if schema_data and not isinstance(schema_data, dict):
            raise TypeError("Expected argument 'schema_data' to be a dict")
        pulumi.set(__self__, "schema_data", schema_data)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)

    @_builtins.property
    @pulumi.getter(name="computeGlobalImageCapabilitySchemaId")
    def compute_global_image_capability_schema_id(self) -> _builtins.str:
        """
        The ocid of the compute global image capability schema
        """
        return pulumi.get(self, "compute_global_image_capability_schema_id")

    @_builtins.property
    @pulumi.getter(name="computeGlobalImageCapabilitySchemaVersionName")
    def compute_global_image_capability_schema_version_name(self) -> _builtins.str:
        return pulumi.get(self, "compute_global_image_capability_schema_version_name")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> _builtins.str:
        """
        A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        """
        The name of the compute global image capability schema version
        """
        return pulumi.get(self, "name")

    @_builtins.property
    @pulumi.getter(name="schemaData")
    def schema_data(self) -> Mapping[str, _builtins.str]:
        """
        The map of each capability name to its ImageCapabilityDescriptor.
        """
        return pulumi.get(self, "schema_data")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        The date and time the compute global image capability schema version was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")


class AwaitableGetComputeGlobalImageCapabilitySchemasVersionResult(GetComputeGlobalImageCapabilitySchemasVersionResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetComputeGlobalImageCapabilitySchemasVersionResult(
            compute_global_image_capability_schema_id=self.compute_global_image_capability_schema_id,
            compute_global_image_capability_schema_version_name=self.compute_global_image_capability_schema_version_name,
            display_name=self.display_name,
            id=self.id,
            name=self.name,
            schema_data=self.schema_data,
            time_created=self.time_created)


def get_compute_global_image_capability_schemas_version(compute_global_image_capability_schema_id: Optional[_builtins.str] = None,
                                                        compute_global_image_capability_schema_version_name: Optional[_builtins.str] = None,
                                                        opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetComputeGlobalImageCapabilitySchemasVersionResult:
    """
    This data source provides details about a specific Compute Global Image Capability Schemas Version resource in Oracle Cloud Infrastructure Core service.

    Gets the specified Compute Global Image Capability Schema Version

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_compute_global_image_capability_schemas_version = oci.Core.get_compute_global_image_capability_schemas_version(compute_global_image_capability_schema_id=test_compute_global_image_capability_schema["id"],
        compute_global_image_capability_schema_version_name=compute_global_image_capability_schemas_version_compute_global_image_capability_schema_version_name)
    ```


    :param _builtins.str compute_global_image_capability_schema_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute global image capability schema
    :param _builtins.str compute_global_image_capability_schema_version_name: The name of the compute global image capability schema version
    """
    __args__ = dict()
    __args__['computeGlobalImageCapabilitySchemaId'] = compute_global_image_capability_schema_id
    __args__['computeGlobalImageCapabilitySchemaVersionName'] = compute_global_image_capability_schema_version_name
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Core/getComputeGlobalImageCapabilitySchemasVersion:getComputeGlobalImageCapabilitySchemasVersion', __args__, opts=opts, typ=GetComputeGlobalImageCapabilitySchemasVersionResult).value

    return AwaitableGetComputeGlobalImageCapabilitySchemasVersionResult(
        compute_global_image_capability_schema_id=pulumi.get(__ret__, 'compute_global_image_capability_schema_id'),
        compute_global_image_capability_schema_version_name=pulumi.get(__ret__, 'compute_global_image_capability_schema_version_name'),
        display_name=pulumi.get(__ret__, 'display_name'),
        id=pulumi.get(__ret__, 'id'),
        name=pulumi.get(__ret__, 'name'),
        schema_data=pulumi.get(__ret__, 'schema_data'),
        time_created=pulumi.get(__ret__, 'time_created'))
def get_compute_global_image_capability_schemas_version_output(compute_global_image_capability_schema_id: Optional[pulumi.Input[_builtins.str]] = None,
                                                               compute_global_image_capability_schema_version_name: Optional[pulumi.Input[_builtins.str]] = None,
                                                               opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetComputeGlobalImageCapabilitySchemasVersionResult]:
    """
    This data source provides details about a specific Compute Global Image Capability Schemas Version resource in Oracle Cloud Infrastructure Core service.

    Gets the specified Compute Global Image Capability Schema Version

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_compute_global_image_capability_schemas_version = oci.Core.get_compute_global_image_capability_schemas_version(compute_global_image_capability_schema_id=test_compute_global_image_capability_schema["id"],
        compute_global_image_capability_schema_version_name=compute_global_image_capability_schemas_version_compute_global_image_capability_schema_version_name)
    ```


    :param _builtins.str compute_global_image_capability_schema_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute global image capability schema
    :param _builtins.str compute_global_image_capability_schema_version_name: The name of the compute global image capability schema version
    """
    __args__ = dict()
    __args__['computeGlobalImageCapabilitySchemaId'] = compute_global_image_capability_schema_id
    __args__['computeGlobalImageCapabilitySchemaVersionName'] = compute_global_image_capability_schema_version_name
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Core/getComputeGlobalImageCapabilitySchemasVersion:getComputeGlobalImageCapabilitySchemasVersion', __args__, opts=opts, typ=GetComputeGlobalImageCapabilitySchemasVersionResult)
    return __ret__.apply(lambda __response__: GetComputeGlobalImageCapabilitySchemasVersionResult(
        compute_global_image_capability_schema_id=pulumi.get(__response__, 'compute_global_image_capability_schema_id'),
        compute_global_image_capability_schema_version_name=pulumi.get(__response__, 'compute_global_image_capability_schema_version_name'),
        display_name=pulumi.get(__response__, 'display_name'),
        id=pulumi.get(__response__, 'id'),
        name=pulumi.get(__response__, 'name'),
        schema_data=pulumi.get(__response__, 'schema_data'),
        time_created=pulumi.get(__response__, 'time_created')))
