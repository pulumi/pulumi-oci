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
from ._inputs import *

__all__ = ['StreamPackagingConfigArgs', 'StreamPackagingConfig']

@pulumi.input_type
class StreamPackagingConfigArgs:
    def __init__(__self__, *,
                 display_name: pulumi.Input[str],
                 distribution_channel_id: pulumi.Input[str],
                 segment_time_in_seconds: pulumi.Input[int],
                 stream_packaging_format: pulumi.Input[str],
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 encryption: Optional[pulumi.Input['StreamPackagingConfigEncryptionArgs']] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None):
        """
        The set of arguments for constructing a StreamPackagingConfig resource.
        :param pulumi.Input[str] display_name: (Updatable) The name of the stream Packaging Configuration. Avoid entering confidential information.
        :param pulumi.Input[str] distribution_channel_id: Unique identifier of the Distribution Channel that this stream packaging configuration belongs to.
        :param pulumi.Input[int] segment_time_in_seconds: The duration in seconds for each fragment.
        :param pulumi.Input[str] stream_packaging_format: The output format for the package.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input['StreamPackagingConfigEncryptionArgs'] encryption: The encryption used by the stream packaging configuration.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        pulumi.set(__self__, "display_name", display_name)
        pulumi.set(__self__, "distribution_channel_id", distribution_channel_id)
        pulumi.set(__self__, "segment_time_in_seconds", segment_time_in_seconds)
        pulumi.set(__self__, "stream_packaging_format", stream_packaging_format)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if encryption is not None:
            pulumi.set(__self__, "encryption", encryption)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> pulumi.Input[str]:
        """
        (Updatable) The name of the stream Packaging Configuration. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @display_name.setter
    def display_name(self, value: pulumi.Input[str]):
        pulumi.set(self, "display_name", value)

    @property
    @pulumi.getter(name="distributionChannelId")
    def distribution_channel_id(self) -> pulumi.Input[str]:
        """
        Unique identifier of the Distribution Channel that this stream packaging configuration belongs to.
        """
        return pulumi.get(self, "distribution_channel_id")

    @distribution_channel_id.setter
    def distribution_channel_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "distribution_channel_id", value)

    @property
    @pulumi.getter(name="segmentTimeInSeconds")
    def segment_time_in_seconds(self) -> pulumi.Input[int]:
        """
        The duration in seconds for each fragment.
        """
        return pulumi.get(self, "segment_time_in_seconds")

    @segment_time_in_seconds.setter
    def segment_time_in_seconds(self, value: pulumi.Input[int]):
        pulumi.set(self, "segment_time_in_seconds", value)

    @property
    @pulumi.getter(name="streamPackagingFormat")
    def stream_packaging_format(self) -> pulumi.Input[str]:
        """
        The output format for the package.
        """
        return pulumi.get(self, "stream_packaging_format")

    @stream_packaging_format.setter
    def stream_packaging_format(self, value: pulumi.Input[str]):
        pulumi.set(self, "stream_packaging_format", value)

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @defined_tags.setter
    def defined_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "defined_tags", value)

    @property
    @pulumi.getter
    def encryption(self) -> Optional[pulumi.Input['StreamPackagingConfigEncryptionArgs']]:
        """
        The encryption used by the stream packaging configuration.
        """
        return pulumi.get(self, "encryption")

    @encryption.setter
    def encryption(self, value: Optional[pulumi.Input['StreamPackagingConfigEncryptionArgs']]):
        pulumi.set(self, "encryption", value)

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @freeform_tags.setter
    def freeform_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "freeform_tags", value)


@pulumi.input_type
class _StreamPackagingConfigState:
    def __init__(__self__, *,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 distribution_channel_id: Optional[pulumi.Input[str]] = None,
                 encryption: Optional[pulumi.Input['StreamPackagingConfigEncryptionArgs']] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 segment_time_in_seconds: Optional[pulumi.Input[int]] = None,
                 state: Optional[pulumi.Input[str]] = None,
                 stream_packaging_format: Optional[pulumi.Input[str]] = None,
                 system_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 time_created: Optional[pulumi.Input[str]] = None,
                 time_updated: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering StreamPackagingConfig resources.
        :param pulumi.Input[str] compartment_id: Compartment Identifier
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[str] display_name: (Updatable) The name of the stream Packaging Configuration. Avoid entering confidential information.
        :param pulumi.Input[str] distribution_channel_id: Unique identifier of the Distribution Channel that this stream packaging configuration belongs to.
        :param pulumi.Input['StreamPackagingConfigEncryptionArgs'] encryption: The encryption used by the stream packaging configuration.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param pulumi.Input[int] segment_time_in_seconds: The duration in seconds for each fragment.
        :param pulumi.Input[str] state: The current state of the Packaging Configuration.
        :param pulumi.Input[str] stream_packaging_format: The output format for the package.
        :param pulumi.Input[Mapping[str, Any]] system_tags: Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        :param pulumi.Input[str] time_created: The time when the Packaging Configuration was created. An RFC3339 formatted datetime string.
        :param pulumi.Input[str] time_updated: The time when the Packaging Configuration was updated. An RFC3339 formatted datetime string.
        """
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name is not None:
            pulumi.set(__self__, "display_name", display_name)
        if distribution_channel_id is not None:
            pulumi.set(__self__, "distribution_channel_id", distribution_channel_id)
        if encryption is not None:
            pulumi.set(__self__, "encryption", encryption)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if segment_time_in_seconds is not None:
            pulumi.set(__self__, "segment_time_in_seconds", segment_time_in_seconds)
        if state is not None:
            pulumi.set(__self__, "state", state)
        if stream_packaging_format is not None:
            pulumi.set(__self__, "stream_packaging_format", stream_packaging_format)
        if system_tags is not None:
            pulumi.set(__self__, "system_tags", system_tags)
        if time_created is not None:
            pulumi.set(__self__, "time_created", time_created)
        if time_updated is not None:
            pulumi.set(__self__, "time_updated", time_updated)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[str]]:
        """
        Compartment Identifier
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "compartment_id", value)

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @defined_tags.setter
    def defined_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "defined_tags", value)

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[pulumi.Input[str]]:
        """
        (Updatable) The name of the stream Packaging Configuration. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @display_name.setter
    def display_name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "display_name", value)

    @property
    @pulumi.getter(name="distributionChannelId")
    def distribution_channel_id(self) -> Optional[pulumi.Input[str]]:
        """
        Unique identifier of the Distribution Channel that this stream packaging configuration belongs to.
        """
        return pulumi.get(self, "distribution_channel_id")

    @distribution_channel_id.setter
    def distribution_channel_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "distribution_channel_id", value)

    @property
    @pulumi.getter
    def encryption(self) -> Optional[pulumi.Input['StreamPackagingConfigEncryptionArgs']]:
        """
        The encryption used by the stream packaging configuration.
        """
        return pulumi.get(self, "encryption")

    @encryption.setter
    def encryption(self, value: Optional[pulumi.Input['StreamPackagingConfigEncryptionArgs']]):
        pulumi.set(self, "encryption", value)

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @freeform_tags.setter
    def freeform_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "freeform_tags", value)

    @property
    @pulumi.getter(name="segmentTimeInSeconds")
    def segment_time_in_seconds(self) -> Optional[pulumi.Input[int]]:
        """
        The duration in seconds for each fragment.
        """
        return pulumi.get(self, "segment_time_in_seconds")

    @segment_time_in_seconds.setter
    def segment_time_in_seconds(self, value: Optional[pulumi.Input[int]]):
        pulumi.set(self, "segment_time_in_seconds", value)

    @property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[str]]:
        """
        The current state of the Packaging Configuration.
        """
        return pulumi.get(self, "state")

    @state.setter
    def state(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "state", value)

    @property
    @pulumi.getter(name="streamPackagingFormat")
    def stream_packaging_format(self) -> Optional[pulumi.Input[str]]:
        """
        The output format for the package.
        """
        return pulumi.get(self, "stream_packaging_format")

    @stream_packaging_format.setter
    def stream_packaging_format(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "stream_packaging_format", value)

    @property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @system_tags.setter
    def system_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "system_tags", value)

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[str]]:
        """
        The time when the Packaging Configuration was created. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_created", value)

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> Optional[pulumi.Input[str]]:
        """
        The time when the Packaging Configuration was updated. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_updated")

    @time_updated.setter
    def time_updated(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_updated", value)


class StreamPackagingConfig(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 distribution_channel_id: Optional[pulumi.Input[str]] = None,
                 encryption: Optional[pulumi.Input[pulumi.InputType['StreamPackagingConfigEncryptionArgs']]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 segment_time_in_seconds: Optional[pulumi.Input[int]] = None,
                 stream_packaging_format: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        """
        This resource provides the Stream Packaging Config resource in Oracle Cloud Infrastructure Media Services service.

        Creates a new Packaging Configuration.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_stream_packaging_config = oci.media_services.StreamPackagingConfig("testStreamPackagingConfig",
            display_name=var["stream_packaging_config_display_name"],
            distribution_channel_id=oci_mysql_channel["test_channel"]["id"],
            segment_time_in_seconds=var["stream_packaging_config_segment_time_in_seconds"],
            stream_packaging_format=var["stream_packaging_config_stream_packaging_format"],
            defined_tags={
                "foo-namespace.bar-key": "value",
            },
            encryption=oci.media_services.StreamPackagingConfigEncryptionArgs(
                algorithm=var["stream_packaging_config_encryption_algorithm"],
                kms_key_id=oci_kms_key["test_key"]["id"],
            ),
            freeform_tags={
                "bar-key": "value",
            })
        ```

        ## Import

        StreamPackagingConfigs can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:MediaServices/streamPackagingConfig:StreamPackagingConfig test_stream_packaging_config "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[str] display_name: (Updatable) The name of the stream Packaging Configuration. Avoid entering confidential information.
        :param pulumi.Input[str] distribution_channel_id: Unique identifier of the Distribution Channel that this stream packaging configuration belongs to.
        :param pulumi.Input[pulumi.InputType['StreamPackagingConfigEncryptionArgs']] encryption: The encryption used by the stream packaging configuration.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param pulumi.Input[int] segment_time_in_seconds: The duration in seconds for each fragment.
        :param pulumi.Input[str] stream_packaging_format: The output format for the package.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: StreamPackagingConfigArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Stream Packaging Config resource in Oracle Cloud Infrastructure Media Services service.

        Creates a new Packaging Configuration.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_stream_packaging_config = oci.media_services.StreamPackagingConfig("testStreamPackagingConfig",
            display_name=var["stream_packaging_config_display_name"],
            distribution_channel_id=oci_mysql_channel["test_channel"]["id"],
            segment_time_in_seconds=var["stream_packaging_config_segment_time_in_seconds"],
            stream_packaging_format=var["stream_packaging_config_stream_packaging_format"],
            defined_tags={
                "foo-namespace.bar-key": "value",
            },
            encryption=oci.media_services.StreamPackagingConfigEncryptionArgs(
                algorithm=var["stream_packaging_config_encryption_algorithm"],
                kms_key_id=oci_kms_key["test_key"]["id"],
            ),
            freeform_tags={
                "bar-key": "value",
            })
        ```

        ## Import

        StreamPackagingConfigs can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:MediaServices/streamPackagingConfig:StreamPackagingConfig test_stream_packaging_config "id"
        ```

        :param str resource_name: The name of the resource.
        :param StreamPackagingConfigArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(StreamPackagingConfigArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 distribution_channel_id: Optional[pulumi.Input[str]] = None,
                 encryption: Optional[pulumi.Input[pulumi.InputType['StreamPackagingConfigEncryptionArgs']]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 segment_time_in_seconds: Optional[pulumi.Input[int]] = None,
                 stream_packaging_format: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = StreamPackagingConfigArgs.__new__(StreamPackagingConfigArgs)

            __props__.__dict__["defined_tags"] = defined_tags
            if display_name is None and not opts.urn:
                raise TypeError("Missing required property 'display_name'")
            __props__.__dict__["display_name"] = display_name
            if distribution_channel_id is None and not opts.urn:
                raise TypeError("Missing required property 'distribution_channel_id'")
            __props__.__dict__["distribution_channel_id"] = distribution_channel_id
            __props__.__dict__["encryption"] = encryption
            __props__.__dict__["freeform_tags"] = freeform_tags
            if segment_time_in_seconds is None and not opts.urn:
                raise TypeError("Missing required property 'segment_time_in_seconds'")
            __props__.__dict__["segment_time_in_seconds"] = segment_time_in_seconds
            if stream_packaging_format is None and not opts.urn:
                raise TypeError("Missing required property 'stream_packaging_format'")
            __props__.__dict__["stream_packaging_format"] = stream_packaging_format
            __props__.__dict__["compartment_id"] = None
            __props__.__dict__["state"] = None
            __props__.__dict__["system_tags"] = None
            __props__.__dict__["time_created"] = None
            __props__.__dict__["time_updated"] = None
        super(StreamPackagingConfig, __self__).__init__(
            'oci:MediaServices/streamPackagingConfig:StreamPackagingConfig',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            compartment_id: Optional[pulumi.Input[str]] = None,
            defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            display_name: Optional[pulumi.Input[str]] = None,
            distribution_channel_id: Optional[pulumi.Input[str]] = None,
            encryption: Optional[pulumi.Input[pulumi.InputType['StreamPackagingConfigEncryptionArgs']]] = None,
            freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            segment_time_in_seconds: Optional[pulumi.Input[int]] = None,
            state: Optional[pulumi.Input[str]] = None,
            stream_packaging_format: Optional[pulumi.Input[str]] = None,
            system_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            time_created: Optional[pulumi.Input[str]] = None,
            time_updated: Optional[pulumi.Input[str]] = None) -> 'StreamPackagingConfig':
        """
        Get an existing StreamPackagingConfig resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] compartment_id: Compartment Identifier
        :param pulumi.Input[Mapping[str, Any]] defined_tags: (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[str] display_name: (Updatable) The name of the stream Packaging Configuration. Avoid entering confidential information.
        :param pulumi.Input[str] distribution_channel_id: Unique identifier of the Distribution Channel that this stream packaging configuration belongs to.
        :param pulumi.Input[pulumi.InputType['StreamPackagingConfigEncryptionArgs']] encryption: The encryption used by the stream packaging configuration.
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param pulumi.Input[int] segment_time_in_seconds: The duration in seconds for each fragment.
        :param pulumi.Input[str] state: The current state of the Packaging Configuration.
        :param pulumi.Input[str] stream_packaging_format: The output format for the package.
        :param pulumi.Input[Mapping[str, Any]] system_tags: Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        :param pulumi.Input[str] time_created: The time when the Packaging Configuration was created. An RFC3339 formatted datetime string.
        :param pulumi.Input[str] time_updated: The time when the Packaging Configuration was updated. An RFC3339 formatted datetime string.
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _StreamPackagingConfigState.__new__(_StreamPackagingConfigState)

        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["defined_tags"] = defined_tags
        __props__.__dict__["display_name"] = display_name
        __props__.__dict__["distribution_channel_id"] = distribution_channel_id
        __props__.__dict__["encryption"] = encryption
        __props__.__dict__["freeform_tags"] = freeform_tags
        __props__.__dict__["segment_time_in_seconds"] = segment_time_in_seconds
        __props__.__dict__["state"] = state
        __props__.__dict__["stream_packaging_format"] = stream_packaging_format
        __props__.__dict__["system_tags"] = system_tags
        __props__.__dict__["time_created"] = time_created
        __props__.__dict__["time_updated"] = time_updated
        return StreamPackagingConfig(resource_name, opts=opts, __props__=__props__)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Output[str]:
        """
        Compartment Identifier
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> pulumi.Output[Mapping[str, Any]]:
        """
        (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> pulumi.Output[str]:
        """
        (Updatable) The name of the stream Packaging Configuration. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="distributionChannelId")
    def distribution_channel_id(self) -> pulumi.Output[str]:
        """
        Unique identifier of the Distribution Channel that this stream packaging configuration belongs to.
        """
        return pulumi.get(self, "distribution_channel_id")

    @property
    @pulumi.getter
    def encryption(self) -> pulumi.Output['outputs.StreamPackagingConfigEncryption']:
        """
        The encryption used by the stream packaging configuration.
        """
        return pulumi.get(self, "encryption")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> pulumi.Output[Mapping[str, Any]]:
        """
        (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter(name="segmentTimeInSeconds")
    def segment_time_in_seconds(self) -> pulumi.Output[int]:
        """
        The duration in seconds for each fragment.
        """
        return pulumi.get(self, "segment_time_in_seconds")

    @property
    @pulumi.getter
    def state(self) -> pulumi.Output[str]:
        """
        The current state of the Packaging Configuration.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="streamPackagingFormat")
    def stream_packaging_format(self) -> pulumi.Output[str]:
        """
        The output format for the package.
        """
        return pulumi.get(self, "stream_packaging_format")

    @property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> pulumi.Output[Mapping[str, Any]]:
        """
        Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> pulumi.Output[str]:
        """
        The time when the Packaging Configuration was created. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> pulumi.Output[str]:
        """
        The time when the Packaging Configuration was updated. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_updated")
