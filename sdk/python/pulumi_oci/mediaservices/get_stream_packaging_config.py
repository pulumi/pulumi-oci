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
    def __init__(__self__, compartment_id=None, defined_tags=None, display_name=None, distribution_channel_id=None, encryptions=None, freeform_tags=None, id=None, segment_time_in_seconds=None, state=None, stream_packaging_config_id=None, stream_packaging_format=None, system_tags=None, time_created=None, time_updated=None):
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

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        Compartment Identifier
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        The name of the stream packaging configuration. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="distributionChannelId")
    def distribution_channel_id(self) -> str:
        """
        Unique identifier of the Distribution Channel that this stream packaging configuration belongs to.
        """
        return pulumi.get(self, "distribution_channel_id")

    @property
    @pulumi.getter
    def encryptions(self) -> Sequence['outputs.GetStreamPackagingConfigEncryptionResult']:
        """
        The encryption used by the stream packaging configuration.
        """
        return pulumi.get(self, "encryptions")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        Unique identifier that is immutable on creation.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="segmentTimeInSeconds")
    def segment_time_in_seconds(self) -> int:
        """
        The duration in seconds for each fragment.
        """
        return pulumi.get(self, "segment_time_in_seconds")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The current state of the Packaging Configuration.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="streamPackagingConfigId")
    def stream_packaging_config_id(self) -> str:
        return pulumi.get(self, "stream_packaging_config_id")

    @property
    @pulumi.getter(name="streamPackagingFormat")
    def stream_packaging_format(self) -> str:
        """
        The output format for the package.
        """
        return pulumi.get(self, "stream_packaging_format")

    @property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, Any]:
        """
        Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The time when the Packaging Configuration was created. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
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
            segment_time_in_seconds=self.segment_time_in_seconds,
            state=self.state,
            stream_packaging_config_id=self.stream_packaging_config_id,
            stream_packaging_format=self.stream_packaging_format,
            system_tags=self.system_tags,
            time_created=self.time_created,
            time_updated=self.time_updated)


def get_stream_packaging_config(stream_packaging_config_id: Optional[str] = None,
                                opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetStreamPackagingConfigResult:
    """
    This data source provides details about a specific Stream Packaging Config resource in Oracle Cloud Infrastructure Media Services service.

    Gets a Stream Packaging Configuration by identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_stream_packaging_config = oci.MediaServices.get_stream_packaging_config(stream_packaging_config_id=oci_media_services_stream_packaging_config["test_stream_packaging_config"]["id"])
    ```


    :param str stream_packaging_config_id: Unique Stream Packaging Configuration path identifier.
    """
    __args__ = dict()
    __args__['streamPackagingConfigId'] = stream_packaging_config_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:MediaServices/getStreamPackagingConfig:getStreamPackagingConfig', __args__, opts=opts, typ=GetStreamPackagingConfigResult).value

    return AwaitableGetStreamPackagingConfigResult(
        compartment_id=__ret__.compartment_id,
        defined_tags=__ret__.defined_tags,
        display_name=__ret__.display_name,
        distribution_channel_id=__ret__.distribution_channel_id,
        encryptions=__ret__.encryptions,
        freeform_tags=__ret__.freeform_tags,
        id=__ret__.id,
        segment_time_in_seconds=__ret__.segment_time_in_seconds,
        state=__ret__.state,
        stream_packaging_config_id=__ret__.stream_packaging_config_id,
        stream_packaging_format=__ret__.stream_packaging_format,
        system_tags=__ret__.system_tags,
        time_created=__ret__.time_created,
        time_updated=__ret__.time_updated)


@_utilities.lift_output_func(get_stream_packaging_config)
def get_stream_packaging_config_output(stream_packaging_config_id: Optional[pulumi.Input[str]] = None,
                                       opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetStreamPackagingConfigResult]:
    """
    This data source provides details about a specific Stream Packaging Config resource in Oracle Cloud Infrastructure Media Services service.

    Gets a Stream Packaging Configuration by identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_stream_packaging_config = oci.MediaServices.get_stream_packaging_config(stream_packaging_config_id=oci_media_services_stream_packaging_config["test_stream_packaging_config"]["id"])
    ```


    :param str stream_packaging_config_id: Unique Stream Packaging Configuration path identifier.
    """
    ...