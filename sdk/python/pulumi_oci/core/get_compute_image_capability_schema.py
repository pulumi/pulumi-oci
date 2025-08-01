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
    'GetComputeImageCapabilitySchemaResult',
    'AwaitableGetComputeImageCapabilitySchemaResult',
    'get_compute_image_capability_schema',
    'get_compute_image_capability_schema_output',
]

@pulumi.output_type
class GetComputeImageCapabilitySchemaResult:
    """
    A collection of values returned by getComputeImageCapabilitySchema.
    """
    def __init__(__self__, compartment_id=None, compute_global_image_capability_schema_id=None, compute_global_image_capability_schema_version_name=None, compute_image_capability_schema_id=None, defined_tags=None, display_name=None, freeform_tags=None, id=None, image_id=None, is_merge_enabled=None, schema_data=None, time_created=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if compute_global_image_capability_schema_id and not isinstance(compute_global_image_capability_schema_id, str):
            raise TypeError("Expected argument 'compute_global_image_capability_schema_id' to be a str")
        pulumi.set(__self__, "compute_global_image_capability_schema_id", compute_global_image_capability_schema_id)
        if compute_global_image_capability_schema_version_name and not isinstance(compute_global_image_capability_schema_version_name, str):
            raise TypeError("Expected argument 'compute_global_image_capability_schema_version_name' to be a str")
        pulumi.set(__self__, "compute_global_image_capability_schema_version_name", compute_global_image_capability_schema_version_name)
        if compute_image_capability_schema_id and not isinstance(compute_image_capability_schema_id, str):
            raise TypeError("Expected argument 'compute_image_capability_schema_id' to be a str")
        pulumi.set(__self__, "compute_image_capability_schema_id", compute_image_capability_schema_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if image_id and not isinstance(image_id, str):
            raise TypeError("Expected argument 'image_id' to be a str")
        pulumi.set(__self__, "image_id", image_id)
        if is_merge_enabled and not isinstance(is_merge_enabled, str):
            raise TypeError("Expected argument 'is_merge_enabled' to be a str")
        pulumi.set(__self__, "is_merge_enabled", is_merge_enabled)
        if schema_data and not isinstance(schema_data, dict):
            raise TypeError("Expected argument 'schema_data' to be a dict")
        pulumi.set(__self__, "schema_data", schema_data)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The OCID of the compartment containing the compute global image capability schema
        """
        return pulumi.get(self, "compartment_id")

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
        """
        The name of the compute global image capability schema version
        """
        return pulumi.get(self, "compute_global_image_capability_schema_version_name")

    @_builtins.property
    @pulumi.getter(name="computeImageCapabilitySchemaId")
    def compute_image_capability_schema_id(self) -> _builtins.str:
        return pulumi.get(self, "compute_image_capability_schema_id")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, _builtins.str]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> _builtins.str:
        """
        A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, _builtins.str]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The compute image capability schema [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="imageId")
    def image_id(self) -> _builtins.str:
        """
        The OCID of the image associated with this compute image capability schema
        """
        return pulumi.get(self, "image_id")

    @_builtins.property
    @pulumi.getter(name="isMergeEnabled")
    def is_merge_enabled(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "is_merge_enabled")

    @_builtins.property
    @pulumi.getter(name="schemaData")
    def schema_data(self) -> Mapping[str, _builtins.str]:
        """
        A mapping of each capability name to its ImageCapabilityDescriptor.
        """
        return pulumi.get(self, "schema_data")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        The date and time the compute image capability schema was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")


class AwaitableGetComputeImageCapabilitySchemaResult(GetComputeImageCapabilitySchemaResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetComputeImageCapabilitySchemaResult(
            compartment_id=self.compartment_id,
            compute_global_image_capability_schema_id=self.compute_global_image_capability_schema_id,
            compute_global_image_capability_schema_version_name=self.compute_global_image_capability_schema_version_name,
            compute_image_capability_schema_id=self.compute_image_capability_schema_id,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            image_id=self.image_id,
            is_merge_enabled=self.is_merge_enabled,
            schema_data=self.schema_data,
            time_created=self.time_created)


def get_compute_image_capability_schema(compute_image_capability_schema_id: Optional[_builtins.str] = None,
                                        is_merge_enabled: Optional[_builtins.str] = None,
                                        opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetComputeImageCapabilitySchemaResult:
    """
    This data source provides details about a specific Compute Image Capability Schema resource in Oracle Cloud Infrastructure Core service.

    Gets the specified Compute Image Capability Schema

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_compute_image_capability_schema = oci.Core.get_compute_image_capability_schema(compute_image_capability_schema_id=test_compute_image_capability_schema_oci_core_compute_image_capability_schema["id"],
        is_merge_enabled=compute_image_capability_schema_is_merge_enabled)
    ```


    :param _builtins.str compute_image_capability_schema_id: The id of the compute image capability schema or the image ocid
    :param _builtins.str is_merge_enabled: Merge the image capability schema with the global image capability schema
    """
    __args__ = dict()
    __args__['computeImageCapabilitySchemaId'] = compute_image_capability_schema_id
    __args__['isMergeEnabled'] = is_merge_enabled
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Core/getComputeImageCapabilitySchema:getComputeImageCapabilitySchema', __args__, opts=opts, typ=GetComputeImageCapabilitySchemaResult).value

    return AwaitableGetComputeImageCapabilitySchemaResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        compute_global_image_capability_schema_id=pulumi.get(__ret__, 'compute_global_image_capability_schema_id'),
        compute_global_image_capability_schema_version_name=pulumi.get(__ret__, 'compute_global_image_capability_schema_version_name'),
        compute_image_capability_schema_id=pulumi.get(__ret__, 'compute_image_capability_schema_id'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        display_name=pulumi.get(__ret__, 'display_name'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        id=pulumi.get(__ret__, 'id'),
        image_id=pulumi.get(__ret__, 'image_id'),
        is_merge_enabled=pulumi.get(__ret__, 'is_merge_enabled'),
        schema_data=pulumi.get(__ret__, 'schema_data'),
        time_created=pulumi.get(__ret__, 'time_created'))
def get_compute_image_capability_schema_output(compute_image_capability_schema_id: Optional[pulumi.Input[_builtins.str]] = None,
                                               is_merge_enabled: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                               opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetComputeImageCapabilitySchemaResult]:
    """
    This data source provides details about a specific Compute Image Capability Schema resource in Oracle Cloud Infrastructure Core service.

    Gets the specified Compute Image Capability Schema

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_compute_image_capability_schema = oci.Core.get_compute_image_capability_schema(compute_image_capability_schema_id=test_compute_image_capability_schema_oci_core_compute_image_capability_schema["id"],
        is_merge_enabled=compute_image_capability_schema_is_merge_enabled)
    ```


    :param _builtins.str compute_image_capability_schema_id: The id of the compute image capability schema or the image ocid
    :param _builtins.str is_merge_enabled: Merge the image capability schema with the global image capability schema
    """
    __args__ = dict()
    __args__['computeImageCapabilitySchemaId'] = compute_image_capability_schema_id
    __args__['isMergeEnabled'] = is_merge_enabled
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Core/getComputeImageCapabilitySchema:getComputeImageCapabilitySchema', __args__, opts=opts, typ=GetComputeImageCapabilitySchemaResult)
    return __ret__.apply(lambda __response__: GetComputeImageCapabilitySchemaResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        compute_global_image_capability_schema_id=pulumi.get(__response__, 'compute_global_image_capability_schema_id'),
        compute_global_image_capability_schema_version_name=pulumi.get(__response__, 'compute_global_image_capability_schema_version_name'),
        compute_image_capability_schema_id=pulumi.get(__response__, 'compute_image_capability_schema_id'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        display_name=pulumi.get(__response__, 'display_name'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        id=pulumi.get(__response__, 'id'),
        image_id=pulumi.get(__response__, 'image_id'),
        is_merge_enabled=pulumi.get(__response__, 'is_merge_enabled'),
        schema_data=pulumi.get(__response__, 'schema_data'),
        time_created=pulumi.get(__response__, 'time_created')))
