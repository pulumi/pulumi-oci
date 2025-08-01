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
    'GetStreamPackagingConfigResult',
    'AwaitableGetStreamPackagingConfigResult',
    'get_stream_packaging_config',
    'get_stream_packaging_config_output',
]

@pulumi.output_type
class GetStreamPackagingConfigResult:
    """
    A collection of values returned by getStreamPackagingConfig.
    """
    def __init__(__self__, compartment_id=None, defined_tags=None, display_name=None, distribution_channel_id=None, encryptions=None, freeform_tags=None, id=None, is_lock_override=None, locks=None, segment_time_in_seconds=None, state=None, stream_packaging_config_id=None, stream_packaging_format=None, system_tags=None, time_created=None, time_updated=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if distribution_channel_id and not isinstance(distribution_channel_id, str):
            raise TypeError("Expected argument 'distribution_channel_id' to be a str")
        pulumi.set(__self__, "distribution_channel_id", distribution_channel_id)
        if encryptions and not isinstance(encryptions, list):
            raise TypeError("Expected argument 'encryptions' to be a list")
        pulumi.set(__self__, "encryptions", encryptions)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if is_lock_override and not isinstance(is_lock_override, bool):
            raise TypeError("Expected argument 'is_lock_override' to be a bool")
        pulumi.set(__self__, "is_lock_override", is_lock_override)
        if locks and not isinstance(locks, list):
            raise TypeError("Expected argument 'locks' to be a list")
        pulumi.set(__self__, "locks", locks)
        if segment_time_in_seconds and not isinstance(segment_time_in_seconds, int):
            raise TypeError("Expected argument 'segment_time_in_seconds' to be a int")
        pulumi.set(__self__, "segment_time_in_seconds", segment_time_in_seconds)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if stream_packaging_config_id and not isinstance(stream_packaging_config_id, str):
            raise TypeError("Expected argument 'stream_packaging_config_id' to be a str")
        pulumi.set(__self__, "stream_packaging_config_id", stream_packaging_config_id)
        if stream_packaging_format and not isinstance(stream_packaging_format, str):
            raise TypeError("Expected argument 'stream_packaging_format' to be a str")
        pulumi.set(__self__, "stream_packaging_format", stream_packaging_format)
        if system_tags and not isinstance(system_tags, dict):
            raise TypeError("Expected argument 'system_tags' to be a dict")
        pulumi.set(__self__, "system_tags", system_tags)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The compartment ID of the lock.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, _builtins.str]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> _builtins.str:
        """
        The name of the stream packaging configuration. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="distributionChannelId")
    def distribution_channel_id(self) -> _builtins.str:
        """
        Unique identifier of the Distribution Channel that this stream packaging configuration belongs to.
        """
        return pulumi.get(self, "distribution_channel_id")

    @_builtins.property
    @pulumi.getter
    def encryptions(self) -> Sequence['outputs.GetStreamPackagingConfigEncryptionResult']:
        """
        The encryption used by the stream packaging configuration.
        """
        return pulumi.get(self, "encryptions")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, _builtins.str]:
        """
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        Unique identifier that is immutable on creation.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="isLockOverride")
    def is_lock_override(self) -> _builtins.bool:
        return pulumi.get(self, "is_lock_override")

    @_builtins.property
    @pulumi.getter
    def locks(self) -> Sequence['outputs.GetStreamPackagingConfigLockResult']:
        """
        Locks associated with this resource.
        """
        return pulumi.get(self, "locks")

    @_builtins.property
    @pulumi.getter(name="segmentTimeInSeconds")
    def segment_time_in_seconds(self) -> _builtins.int:
        """
        The duration in seconds for each fragment.
        """
        return pulumi.get(self, "segment_time_in_seconds")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current state of the Packaging Configuration.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="streamPackagingConfigId")
    def stream_packaging_config_id(self) -> _builtins.str:
        return pulumi.get(self, "stream_packaging_config_id")

    @_builtins.property
    @pulumi.getter(name="streamPackagingFormat")
    def stream_packaging_format(self) -> _builtins.str:
        """
        The output format for the package.
        """
        return pulumi.get(self, "stream_packaging_format")

    @_builtins.property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, _builtins.str]:
        """
        Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        The time when the Packaging Configuration was created. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> _builtins.str:
        """
        The time when the Packaging Configuration was updated. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetStreamPackagingConfigResult(GetStreamPackagingConfigResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetStreamPackagingConfigResult(
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            distribution_channel_id=self.distribution_channel_id,
            encryptions=self.encryptions,
            freeform_tags=self.freeform_tags,
            id=self.id,
            is_lock_override=self.is_lock_override,
            locks=self.locks,
            segment_time_in_seconds=self.segment_time_in_seconds,
            state=self.state,
            stream_packaging_config_id=self.stream_packaging_config_id,
            stream_packaging_format=self.stream_packaging_format,
            system_tags=self.system_tags,
            time_created=self.time_created,
            time_updated=self.time_updated)


def get_stream_packaging_config(stream_packaging_config_id: Optional[_builtins.str] = None,
                                opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetStreamPackagingConfigResult:
    """
    This data source provides details about a specific Stream Packaging Config resource in Oracle Cloud Infrastructure Media Services service.

    Gets a Stream Packaging Configuration by identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_stream_packaging_config = oci.MediaServices.get_stream_packaging_config(stream_packaging_config_id=test_stream_packaging_config_oci_media_services_stream_packaging_config["id"])
    ```


    :param _builtins.str stream_packaging_config_id: Unique Stream Packaging Configuration path identifier.
    """
    __args__ = dict()
    __args__['streamPackagingConfigId'] = stream_packaging_config_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:MediaServices/getStreamPackagingConfig:getStreamPackagingConfig', __args__, opts=opts, typ=GetStreamPackagingConfigResult).value

    return AwaitableGetStreamPackagingConfigResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        display_name=pulumi.get(__ret__, 'display_name'),
        distribution_channel_id=pulumi.get(__ret__, 'distribution_channel_id'),
        encryptions=pulumi.get(__ret__, 'encryptions'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        id=pulumi.get(__ret__, 'id'),
        is_lock_override=pulumi.get(__ret__, 'is_lock_override'),
        locks=pulumi.get(__ret__, 'locks'),
        segment_time_in_seconds=pulumi.get(__ret__, 'segment_time_in_seconds'),
        state=pulumi.get(__ret__, 'state'),
        stream_packaging_config_id=pulumi.get(__ret__, 'stream_packaging_config_id'),
        stream_packaging_format=pulumi.get(__ret__, 'stream_packaging_format'),
        system_tags=pulumi.get(__ret__, 'system_tags'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_updated=pulumi.get(__ret__, 'time_updated'))
def get_stream_packaging_config_output(stream_packaging_config_id: Optional[pulumi.Input[_builtins.str]] = None,
                                       opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetStreamPackagingConfigResult]:
    """
    This data source provides details about a specific Stream Packaging Config resource in Oracle Cloud Infrastructure Media Services service.

    Gets a Stream Packaging Configuration by identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_stream_packaging_config = oci.MediaServices.get_stream_packaging_config(stream_packaging_config_id=test_stream_packaging_config_oci_media_services_stream_packaging_config["id"])
    ```


    :param _builtins.str stream_packaging_config_id: Unique Stream Packaging Configuration path identifier.
    """
    __args__ = dict()
    __args__['streamPackagingConfigId'] = stream_packaging_config_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:MediaServices/getStreamPackagingConfig:getStreamPackagingConfig', __args__, opts=opts, typ=GetStreamPackagingConfigResult)
    return __ret__.apply(lambda __response__: GetStreamPackagingConfigResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        display_name=pulumi.get(__response__, 'display_name'),
        distribution_channel_id=pulumi.get(__response__, 'distribution_channel_id'),
        encryptions=pulumi.get(__response__, 'encryptions'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        id=pulumi.get(__response__, 'id'),
        is_lock_override=pulumi.get(__response__, 'is_lock_override'),
        locks=pulumi.get(__response__, 'locks'),
        segment_time_in_seconds=pulumi.get(__response__, 'segment_time_in_seconds'),
        state=pulumi.get(__response__, 'state'),
        stream_packaging_config_id=pulumi.get(__response__, 'stream_packaging_config_id'),
        stream_packaging_format=pulumi.get(__response__, 'stream_packaging_format'),
        system_tags=pulumi.get(__response__, 'system_tags'),
        time_created=pulumi.get(__response__, 'time_created'),
        time_updated=pulumi.get(__response__, 'time_updated')))
