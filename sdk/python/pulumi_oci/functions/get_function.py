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
    'GetFunctionResult',
    'AwaitableGetFunctionResult',
    'get_function',
    'get_function_output',
]

@pulumi.output_type
class GetFunctionResult:
    """
    A collection of values returned by getFunction.
    """
    def __init__(__self__, application_id=None, compartment_id=None, config=None, defined_tags=None, display_name=None, freeform_tags=None, function_id=None, id=None, image=None, image_digest=None, invoke_endpoint=None, memory_in_mbs=None, provisioned_concurrency_configs=None, shape=None, source_details=None, state=None, time_created=None, time_updated=None, timeout_in_seconds=None, trace_configs=None):
        if application_id and not isinstance(application_id, str):
            raise TypeError("Expected argument 'application_id' to be a str")
        pulumi.set(__self__, "application_id", application_id)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if config and not isinstance(config, dict):
            raise TypeError("Expected argument 'config' to be a dict")
        pulumi.set(__self__, "config", config)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if function_id and not isinstance(function_id, str):
            raise TypeError("Expected argument 'function_id' to be a str")
        pulumi.set(__self__, "function_id", function_id)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if image and not isinstance(image, str):
            raise TypeError("Expected argument 'image' to be a str")
        pulumi.set(__self__, "image", image)
        if image_digest and not isinstance(image_digest, str):
            raise TypeError("Expected argument 'image_digest' to be a str")
        pulumi.set(__self__, "image_digest", image_digest)
        if invoke_endpoint and not isinstance(invoke_endpoint, str):
            raise TypeError("Expected argument 'invoke_endpoint' to be a str")
        pulumi.set(__self__, "invoke_endpoint", invoke_endpoint)
        if memory_in_mbs and not isinstance(memory_in_mbs, str):
            raise TypeError("Expected argument 'memory_in_mbs' to be a str")
        pulumi.set(__self__, "memory_in_mbs", memory_in_mbs)
        if provisioned_concurrency_configs and not isinstance(provisioned_concurrency_configs, list):
            raise TypeError("Expected argument 'provisioned_concurrency_configs' to be a list")
        pulumi.set(__self__, "provisioned_concurrency_configs", provisioned_concurrency_configs)
        if shape and not isinstance(shape, str):
            raise TypeError("Expected argument 'shape' to be a str")
        pulumi.set(__self__, "shape", shape)
        if source_details and not isinstance(source_details, list):
            raise TypeError("Expected argument 'source_details' to be a list")
        pulumi.set(__self__, "source_details", source_details)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)
        if timeout_in_seconds and not isinstance(timeout_in_seconds, int):
            raise TypeError("Expected argument 'timeout_in_seconds' to be a int")
        pulumi.set(__self__, "timeout_in_seconds", timeout_in_seconds)
        if trace_configs and not isinstance(trace_configs, list):
            raise TypeError("Expected argument 'trace_configs' to be a list")
        pulumi.set(__self__, "trace_configs", trace_configs)

    @_builtins.property
    @pulumi.getter(name="applicationId")
    def application_id(self) -> _builtins.str:
        """
        The OCID of the application the function belongs to.
        """
        return pulumi.get(self, "application_id")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The OCID of the compartment that contains the function.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter
    def config(self) -> Mapping[str, _builtins.str]:
        """
        Function configuration. Overrides application configuration. Keys must be ASCII strings consisting solely of letters, digits, and the '_' (underscore) character, and must not begin with a digit. Values should be limited to printable unicode characters.  Example: `{"MY_FUNCTION_CONFIG": "ConfVal"}`
        """
        return pulumi.get(self, "config")

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
        The display name of the function. The display name is unique within the application containing the function.
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
    @pulumi.getter(name="functionId")
    def function_id(self) -> _builtins.str:
        return pulumi.get(self, "function_id")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the function.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter
    def image(self) -> _builtins.str:
        """
        The qualified name of the Docker image to use in the function, including the image tag. The image should be in the Oracle Cloud Infrastructure Registry that is in the same region as the function itself. Example: `phx.ocir.io/ten/functions/function:0.0.1`
        """
        return pulumi.get(self, "image")

    @_builtins.property
    @pulumi.getter(name="imageDigest")
    def image_digest(self) -> _builtins.str:
        """
        The image digest for the version of the image that will be pulled when invoking this function. If no value is specified, the digest currently associated with the image in the Oracle Cloud Infrastructure Registry will be used. Example: `sha256:ca0eeb6fb05351dfc8759c20733c91def84cb8007aa89a5bf606bc8b315b9fc7`
        """
        return pulumi.get(self, "image_digest")

    @_builtins.property
    @pulumi.getter(name="invokeEndpoint")
    def invoke_endpoint(self) -> _builtins.str:
        """
        The base https invoke URL to set on a client in order to invoke a function. This URL will never change over the lifetime of the function and can be cached.
        """
        return pulumi.get(self, "invoke_endpoint")

    @_builtins.property
    @pulumi.getter(name="memoryInMbs")
    def memory_in_mbs(self) -> _builtins.str:
        """
        Maximum usable memory for the function (MiB).
        """
        return pulumi.get(self, "memory_in_mbs")

    @_builtins.property
    @pulumi.getter(name="provisionedConcurrencyConfigs")
    def provisioned_concurrency_configs(self) -> Sequence['outputs.GetFunctionProvisionedConcurrencyConfigResult']:
        """
        Define the strategy for provisioned concurrency for the function.
        """
        return pulumi.get(self, "provisioned_concurrency_configs")

    @_builtins.property
    @pulumi.getter
    def shape(self) -> _builtins.str:
        """
        The processor shape (`GENERIC_X86`/`GENERIC_ARM`) on which to run functions in the application, extracted from the image manifest.
        """
        return pulumi.get(self, "shape")

    @_builtins.property
    @pulumi.getter(name="sourceDetails")
    def source_details(self) -> Sequence['outputs.GetFunctionSourceDetailResult']:
        """
        The source details for the Function. The function can be created from various sources.
        """
        return pulumi.get(self, "source_details")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current state of the function.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        The time the function was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-09-12T22:47:12.613Z`
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> _builtins.str:
        """
        The time the function was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-09-12T22:47:12.613Z`
        """
        return pulumi.get(self, "time_updated")

    @_builtins.property
    @pulumi.getter(name="timeoutInSeconds")
    def timeout_in_seconds(self) -> _builtins.int:
        """
        Timeout for executions of the function. Value in seconds.
        """
        return pulumi.get(self, "timeout_in_seconds")

    @_builtins.property
    @pulumi.getter(name="traceConfigs")
    def trace_configs(self) -> Sequence['outputs.GetFunctionTraceConfigResult']:
        """
        Define the tracing configuration for a function.
        """
        return pulumi.get(self, "trace_configs")


class AwaitableGetFunctionResult(GetFunctionResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetFunctionResult(
            application_id=self.application_id,
            compartment_id=self.compartment_id,
            config=self.config,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            function_id=self.function_id,
            id=self.id,
            image=self.image,
            image_digest=self.image_digest,
            invoke_endpoint=self.invoke_endpoint,
            memory_in_mbs=self.memory_in_mbs,
            provisioned_concurrency_configs=self.provisioned_concurrency_configs,
            shape=self.shape,
            source_details=self.source_details,
            state=self.state,
            time_created=self.time_created,
            time_updated=self.time_updated,
            timeout_in_seconds=self.timeout_in_seconds,
            trace_configs=self.trace_configs)


def get_function(function_id: Optional[_builtins.str] = None,
                 opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetFunctionResult:
    """
    This data source provides details about a specific Function resource in Oracle Cloud Infrastructure Functions service.

    Retrieves a function.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_function = oci.Functions.get_function(function_id=test_function_oci_functions_function["id"])
    ```


    :param _builtins.str function_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this function.
    """
    __args__ = dict()
    __args__['functionId'] = function_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Functions/getFunction:getFunction', __args__, opts=opts, typ=GetFunctionResult).value

    return AwaitableGetFunctionResult(
        application_id=pulumi.get(__ret__, 'application_id'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        config=pulumi.get(__ret__, 'config'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        display_name=pulumi.get(__ret__, 'display_name'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        function_id=pulumi.get(__ret__, 'function_id'),
        id=pulumi.get(__ret__, 'id'),
        image=pulumi.get(__ret__, 'image'),
        image_digest=pulumi.get(__ret__, 'image_digest'),
        invoke_endpoint=pulumi.get(__ret__, 'invoke_endpoint'),
        memory_in_mbs=pulumi.get(__ret__, 'memory_in_mbs'),
        provisioned_concurrency_configs=pulumi.get(__ret__, 'provisioned_concurrency_configs'),
        shape=pulumi.get(__ret__, 'shape'),
        source_details=pulumi.get(__ret__, 'source_details'),
        state=pulumi.get(__ret__, 'state'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_updated=pulumi.get(__ret__, 'time_updated'),
        timeout_in_seconds=pulumi.get(__ret__, 'timeout_in_seconds'),
        trace_configs=pulumi.get(__ret__, 'trace_configs'))
def get_function_output(function_id: Optional[pulumi.Input[_builtins.str]] = None,
                        opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetFunctionResult]:
    """
    This data source provides details about a specific Function resource in Oracle Cloud Infrastructure Functions service.

    Retrieves a function.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_function = oci.Functions.get_function(function_id=test_function_oci_functions_function["id"])
    ```


    :param _builtins.str function_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this function.
    """
    __args__ = dict()
    __args__['functionId'] = function_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Functions/getFunction:getFunction', __args__, opts=opts, typ=GetFunctionResult)
    return __ret__.apply(lambda __response__: GetFunctionResult(
        application_id=pulumi.get(__response__, 'application_id'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        config=pulumi.get(__response__, 'config'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        display_name=pulumi.get(__response__, 'display_name'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        function_id=pulumi.get(__response__, 'function_id'),
        id=pulumi.get(__response__, 'id'),
        image=pulumi.get(__response__, 'image'),
        image_digest=pulumi.get(__response__, 'image_digest'),
        invoke_endpoint=pulumi.get(__response__, 'invoke_endpoint'),
        memory_in_mbs=pulumi.get(__response__, 'memory_in_mbs'),
        provisioned_concurrency_configs=pulumi.get(__response__, 'provisioned_concurrency_configs'),
        shape=pulumi.get(__response__, 'shape'),
        source_details=pulumi.get(__response__, 'source_details'),
        state=pulumi.get(__response__, 'state'),
        time_created=pulumi.get(__response__, 'time_created'),
        time_updated=pulumi.get(__response__, 'time_updated'),
        timeout_in_seconds=pulumi.get(__response__, 'timeout_in_seconds'),
        trace_configs=pulumi.get(__response__, 'trace_configs')))
