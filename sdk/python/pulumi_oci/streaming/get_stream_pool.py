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
    'GetStreamPoolResult',
    'AwaitableGetStreamPoolResult',
    'get_stream_pool',
    'get_stream_pool_output',
]

@pulumi.output_type
class GetStreamPoolResult:
    """
    A collection of values returned by getStreamPool.
    """
    def __init__(__self__, compartment_id=None, custom_encryption_keys=None, defined_tags=None, endpoint_fqdn=None, freeform_tags=None, id=None, is_private=None, kafka_settings=None, lifecycle_state_details=None, name=None, private_endpoint_settings=None, state=None, stream_pool_id=None, time_created=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if custom_encryption_keys and not isinstance(custom_encryption_keys, list):
            raise TypeError("Expected argument 'custom_encryption_keys' to be a list")
        pulumi.set(__self__, "custom_encryption_keys", custom_encryption_keys)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if endpoint_fqdn and not isinstance(endpoint_fqdn, str):
            raise TypeError("Expected argument 'endpoint_fqdn' to be a str")
        pulumi.set(__self__, "endpoint_fqdn", endpoint_fqdn)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if is_private and not isinstance(is_private, bool):
            raise TypeError("Expected argument 'is_private' to be a bool")
        pulumi.set(__self__, "is_private", is_private)
        if kafka_settings and not isinstance(kafka_settings, list):
            raise TypeError("Expected argument 'kafka_settings' to be a list")
        pulumi.set(__self__, "kafka_settings", kafka_settings)
        if lifecycle_state_details and not isinstance(lifecycle_state_details, str):
            raise TypeError("Expected argument 'lifecycle_state_details' to be a str")
        pulumi.set(__self__, "lifecycle_state_details", lifecycle_state_details)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if private_endpoint_settings and not isinstance(private_endpoint_settings, list):
            raise TypeError("Expected argument 'private_endpoint_settings' to be a list")
        pulumi.set(__self__, "private_endpoint_settings", private_endpoint_settings)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if stream_pool_id and not isinstance(stream_pool_id, str):
            raise TypeError("Expected argument 'stream_pool_id' to be a str")
        pulumi.set(__self__, "stream_pool_id", stream_pool_id)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        Compartment OCID that the pool belongs to.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="customEncryptionKeys")
    def custom_encryption_keys(self) -> Sequence['outputs.GetStreamPoolCustomEncryptionKeyResult']:
        """
        Custom Encryption Key which will be used for encryption by all the streams in the pool.
        """
        return pulumi.get(self, "custom_encryption_keys")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, _builtins.str]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations": {"CostCenter": "42"}}'
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter(name="endpointFqdn")
    def endpoint_fqdn(self) -> _builtins.str:
        """
        The FQDN used to access the streams inside the stream pool (same FQDN as the messagesEndpoint attribute of a [Stream](https://docs.cloud.oracle.com/iaas/api/#/en/streaming/20180418/Stream) object). If the stream pool is private, the FQDN is customized and can only be accessed from inside the associated subnetId, otherwise the FQDN is publicly resolvable. Depending on which protocol you attempt to use, you need to either prepend https or append the Kafka port.
        """
        return pulumi.get(self, "endpoint_fqdn")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, _builtins.str]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair that is applied with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The OCID of the stream pool.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="isPrivate")
    def is_private(self) -> _builtins.bool:
        """
        True if the stream pool is private, false otherwise. The associated endpoint and subnetId of a private stream pool can be retrieved through the [GetStreamPool](https://docs.cloud.oracle.com/iaas/api/#/en/streaming/20180418/StreamPool/GetStreamPool) API.
        """
        return pulumi.get(self, "is_private")

    @_builtins.property
    @pulumi.getter(name="kafkaSettings")
    def kafka_settings(self) -> Sequence['outputs.GetStreamPoolKafkaSettingResult']:
        """
        Settings for the Kafka compatibility layer.
        """
        return pulumi.get(self, "kafka_settings")

    @_builtins.property
    @pulumi.getter(name="lifecycleStateDetails")
    def lifecycle_state_details(self) -> _builtins.str:
        """
        Any additional details about the current state of the stream.
        """
        return pulumi.get(self, "lifecycle_state_details")

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        """
        The name of the stream pool.
        """
        return pulumi.get(self, "name")

    @_builtins.property
    @pulumi.getter(name="privateEndpointSettings")
    def private_endpoint_settings(self) -> Sequence['outputs.GetStreamPoolPrivateEndpointSettingResult']:
        """
        Optional settings if the stream pool is private.
        """
        return pulumi.get(self, "private_endpoint_settings")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current state of the stream pool.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="streamPoolId")
    def stream_pool_id(self) -> _builtins.str:
        return pulumi.get(self, "stream_pool_id")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        The date and time the stream pool was created, expressed in in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2018-04-20T00:00:07.405Z`
        """
        return pulumi.get(self, "time_created")


class AwaitableGetStreamPoolResult(GetStreamPoolResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetStreamPoolResult(
            compartment_id=self.compartment_id,
            custom_encryption_keys=self.custom_encryption_keys,
            defined_tags=self.defined_tags,
            endpoint_fqdn=self.endpoint_fqdn,
            freeform_tags=self.freeform_tags,
            id=self.id,
            is_private=self.is_private,
            kafka_settings=self.kafka_settings,
            lifecycle_state_details=self.lifecycle_state_details,
            name=self.name,
            private_endpoint_settings=self.private_endpoint_settings,
            state=self.state,
            stream_pool_id=self.stream_pool_id,
            time_created=self.time_created)


def get_stream_pool(stream_pool_id: Optional[_builtins.str] = None,
                    opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetStreamPoolResult:
    """
    This data source provides details about a specific Stream Pool resource in Oracle Cloud Infrastructure Streaming service.

    Gets detailed information about the stream pool, such as Kafka settings.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_stream_pool = oci.Streaming.get_stream_pool(stream_pool_id=test_stream_pool_oci_streaming_stream_pool["id"])
    ```


    :param _builtins.str stream_pool_id: The OCID of the stream pool.
    """
    __args__ = dict()
    __args__['streamPoolId'] = stream_pool_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Streaming/getStreamPool:getStreamPool', __args__, opts=opts, typ=GetStreamPoolResult).value

    return AwaitableGetStreamPoolResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        custom_encryption_keys=pulumi.get(__ret__, 'custom_encryption_keys'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        endpoint_fqdn=pulumi.get(__ret__, 'endpoint_fqdn'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        id=pulumi.get(__ret__, 'id'),
        is_private=pulumi.get(__ret__, 'is_private'),
        kafka_settings=pulumi.get(__ret__, 'kafka_settings'),
        lifecycle_state_details=pulumi.get(__ret__, 'lifecycle_state_details'),
        name=pulumi.get(__ret__, 'name'),
        private_endpoint_settings=pulumi.get(__ret__, 'private_endpoint_settings'),
        state=pulumi.get(__ret__, 'state'),
        stream_pool_id=pulumi.get(__ret__, 'stream_pool_id'),
        time_created=pulumi.get(__ret__, 'time_created'))
def get_stream_pool_output(stream_pool_id: Optional[pulumi.Input[_builtins.str]] = None,
                           opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetStreamPoolResult]:
    """
    This data source provides details about a specific Stream Pool resource in Oracle Cloud Infrastructure Streaming service.

    Gets detailed information about the stream pool, such as Kafka settings.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_stream_pool = oci.Streaming.get_stream_pool(stream_pool_id=test_stream_pool_oci_streaming_stream_pool["id"])
    ```


    :param _builtins.str stream_pool_id: The OCID of the stream pool.
    """
    __args__ = dict()
    __args__['streamPoolId'] = stream_pool_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Streaming/getStreamPool:getStreamPool', __args__, opts=opts, typ=GetStreamPoolResult)
    return __ret__.apply(lambda __response__: GetStreamPoolResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        custom_encryption_keys=pulumi.get(__response__, 'custom_encryption_keys'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        endpoint_fqdn=pulumi.get(__response__, 'endpoint_fqdn'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        id=pulumi.get(__response__, 'id'),
        is_private=pulumi.get(__response__, 'is_private'),
        kafka_settings=pulumi.get(__response__, 'kafka_settings'),
        lifecycle_state_details=pulumi.get(__response__, 'lifecycle_state_details'),
        name=pulumi.get(__response__, 'name'),
        private_endpoint_settings=pulumi.get(__response__, 'private_endpoint_settings'),
        state=pulumi.get(__response__, 'state'),
        stream_pool_id=pulumi.get(__response__, 'stream_pool_id'),
        time_created=pulumi.get(__response__, 'time_created')))
