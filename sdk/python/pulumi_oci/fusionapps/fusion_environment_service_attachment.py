# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = ['FusionEnvironmentServiceAttachmentArgs', 'FusionEnvironmentServiceAttachment']

@pulumi.input_type
class FusionEnvironmentServiceAttachmentArgs:
    def __init__(__self__, *,
                 fusion_environment_id: pulumi.Input[str],
                 service_instance_id: pulumi.Input[str],
                 service_instance_type: pulumi.Input[str],
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None):
        """
        The set of arguments for constructing a FusionEnvironmentServiceAttachment resource.
        :param pulumi.Input[str] fusion_environment_id: unique FusionEnvironment identifier
        :param pulumi.Input[str] service_instance_id: The service instance OCID of the instance being attached
        :param pulumi.Input[str] service_instance_type: Type of the ServiceInstance being attached.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[Mapping[str, Any]] defined_tags: Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        pulumi.set(__self__, "fusion_environment_id", fusion_environment_id)
        pulumi.set(__self__, "service_instance_id", service_instance_id)
        pulumi.set(__self__, "service_instance_type", service_instance_type)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)

    @property
    @pulumi.getter(name="fusionEnvironmentId")
    def fusion_environment_id(self) -> pulumi.Input[str]:
        """
        unique FusionEnvironment identifier
        """
        return pulumi.get(self, "fusion_environment_id")

    @fusion_environment_id.setter
    def fusion_environment_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "fusion_environment_id", value)

    @property
    @pulumi.getter(name="serviceInstanceId")
    def service_instance_id(self) -> pulumi.Input[str]:
        """
        The service instance OCID of the instance being attached
        """
        return pulumi.get(self, "service_instance_id")

    @service_instance_id.setter
    def service_instance_id(self, value: pulumi.Input[str]):
        pulumi.set(self, "service_instance_id", value)

    @property
    @pulumi.getter(name="serviceInstanceType")
    def service_instance_type(self) -> pulumi.Input[str]:
        """
        Type of the ServiceInstance being attached.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "service_instance_type")

    @service_instance_type.setter
    def service_instance_type(self, value: pulumi.Input[str]):
        pulumi.set(self, "service_instance_type", value)

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @defined_tags.setter
    def defined_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "defined_tags", value)


@pulumi.input_type
class _FusionEnvironmentServiceAttachmentState:
    def __init__(__self__, *,
                 compartment_id: Optional[pulumi.Input[str]] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 display_name: Optional[pulumi.Input[str]] = None,
                 freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 fusion_environment_id: Optional[pulumi.Input[str]] = None,
                 is_sku_based: Optional[pulumi.Input[bool]] = None,
                 service_instance_id: Optional[pulumi.Input[str]] = None,
                 service_instance_type: Optional[pulumi.Input[str]] = None,
                 service_url: Optional[pulumi.Input[str]] = None,
                 state: Optional[pulumi.Input[str]] = None,
                 time_created: Optional[pulumi.Input[str]] = None,
                 time_updated: Optional[pulumi.Input[str]] = None):
        """
        Input properties used for looking up and filtering FusionEnvironmentServiceAttachment resources.
        :param pulumi.Input[str] compartment_id: Compartment Identifier
        :param pulumi.Input[Mapping[str, Any]] defined_tags: Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[str] display_name: Service Attachment Display name, can be renamed
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param pulumi.Input[str] fusion_environment_id: unique FusionEnvironment identifier
        :param pulumi.Input[bool] is_sku_based: Whether this service is provisioned due to the customer being subscribed to a specific SKU
        :param pulumi.Input[str] service_instance_id: The service instance OCID of the instance being attached
        :param pulumi.Input[str] service_instance_type: Type of the ServiceInstance being attached.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[str] service_url: Public URL
        :param pulumi.Input[str] state: The current state of the ServiceInstance.
        :param pulumi.Input[str] time_created: The time the the ServiceInstance was created. An RFC3339 formatted datetime string
        :param pulumi.Input[str] time_updated: The time the ServiceInstance was updated. An RFC3339 formatted datetime string
        """
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags is not None:
            pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name is not None:
            pulumi.set(__self__, "display_name", display_name)
        if freeform_tags is not None:
            pulumi.set(__self__, "freeform_tags", freeform_tags)
        if fusion_environment_id is not None:
            pulumi.set(__self__, "fusion_environment_id", fusion_environment_id)
        if is_sku_based is not None:
            pulumi.set(__self__, "is_sku_based", is_sku_based)
        if service_instance_id is not None:
            pulumi.set(__self__, "service_instance_id", service_instance_id)
        if service_instance_type is not None:
            pulumi.set(__self__, "service_instance_type", service_instance_type)
        if service_url is not None:
            pulumi.set(__self__, "service_url", service_url)
        if state is not None:
            pulumi.set(__self__, "state", state)
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
        Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @defined_tags.setter
    def defined_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "defined_tags", value)

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[pulumi.Input[str]]:
        """
        Service Attachment Display name, can be renamed
        """
        return pulumi.get(self, "display_name")

    @display_name.setter
    def display_name(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "display_name", value)

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Optional[pulumi.Input[Mapping[str, Any]]]:
        """
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @freeform_tags.setter
    def freeform_tags(self, value: Optional[pulumi.Input[Mapping[str, Any]]]):
        pulumi.set(self, "freeform_tags", value)

    @property
    @pulumi.getter(name="fusionEnvironmentId")
    def fusion_environment_id(self) -> Optional[pulumi.Input[str]]:
        """
        unique FusionEnvironment identifier
        """
        return pulumi.get(self, "fusion_environment_id")

    @fusion_environment_id.setter
    def fusion_environment_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "fusion_environment_id", value)

    @property
    @pulumi.getter(name="isSkuBased")
    def is_sku_based(self) -> Optional[pulumi.Input[bool]]:
        """
        Whether this service is provisioned due to the customer being subscribed to a specific SKU
        """
        return pulumi.get(self, "is_sku_based")

    @is_sku_based.setter
    def is_sku_based(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "is_sku_based", value)

    @property
    @pulumi.getter(name="serviceInstanceId")
    def service_instance_id(self) -> Optional[pulumi.Input[str]]:
        """
        The service instance OCID of the instance being attached
        """
        return pulumi.get(self, "service_instance_id")

    @service_instance_id.setter
    def service_instance_id(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "service_instance_id", value)

    @property
    @pulumi.getter(name="serviceInstanceType")
    def service_instance_type(self) -> Optional[pulumi.Input[str]]:
        """
        Type of the ServiceInstance being attached.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "service_instance_type")

    @service_instance_type.setter
    def service_instance_type(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "service_instance_type", value)

    @property
    @pulumi.getter(name="serviceUrl")
    def service_url(self) -> Optional[pulumi.Input[str]]:
        """
        Public URL
        """
        return pulumi.get(self, "service_url")

    @service_url.setter
    def service_url(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "service_url", value)

    @property
    @pulumi.getter
    def state(self) -> Optional[pulumi.Input[str]]:
        """
        The current state of the ServiceInstance.
        """
        return pulumi.get(self, "state")

    @state.setter
    def state(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "state", value)

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> Optional[pulumi.Input[str]]:
        """
        The time the the ServiceInstance was created. An RFC3339 formatted datetime string
        """
        return pulumi.get(self, "time_created")

    @time_created.setter
    def time_created(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_created", value)

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> Optional[pulumi.Input[str]]:
        """
        The time the ServiceInstance was updated. An RFC3339 formatted datetime string
        """
        return pulumi.get(self, "time_updated")

    @time_updated.setter
    def time_updated(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "time_updated", value)


class FusionEnvironmentServiceAttachment(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 fusion_environment_id: Optional[pulumi.Input[str]] = None,
                 service_instance_id: Optional[pulumi.Input[str]] = None,
                 service_instance_type: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        """
        This resource provides the Fusion Environment Service Attachment resource in Oracle Cloud Infrastructure Fusion Apps service.

        Attaches a service instance to the fusion pod.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_fusion_environment_service_attachment = oci.fusion_apps.FusionEnvironmentServiceAttachment("testFusionEnvironmentServiceAttachment",
            fusion_environment_id=oci_fusion_apps_fusion_environment["test_fusion_environment"]["id"],
            service_instance_id=oci_core_instance["test_instance"]["id"],
            service_instance_type=var["fusion_environment_service_attachment_service_instance_type"])
        ```

        ## Import

        FusionEnvironmentServiceAttachments can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:FusionApps/fusionEnvironmentServiceAttachment:FusionEnvironmentServiceAttachment test_fusion_environment_service_attachment "fusionEnvironments/{fusionEnvironmentId}/serviceAttachments/{serviceAttachmentId}"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[Mapping[str, Any]] defined_tags: Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[str] fusion_environment_id: unique FusionEnvironment identifier
        :param pulumi.Input[str] service_instance_id: The service instance OCID of the instance being attached
        :param pulumi.Input[str] service_instance_type: Type of the ServiceInstance being attached.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: FusionEnvironmentServiceAttachmentArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Fusion Environment Service Attachment resource in Oracle Cloud Infrastructure Fusion Apps service.

        Attaches a service instance to the fusion pod.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_fusion_environment_service_attachment = oci.fusion_apps.FusionEnvironmentServiceAttachment("testFusionEnvironmentServiceAttachment",
            fusion_environment_id=oci_fusion_apps_fusion_environment["test_fusion_environment"]["id"],
            service_instance_id=oci_core_instance["test_instance"]["id"],
            service_instance_type=var["fusion_environment_service_attachment_service_instance_type"])
        ```

        ## Import

        FusionEnvironmentServiceAttachments can be imported using the `id`, e.g.

        ```sh
         $ pulumi import oci:FusionApps/fusionEnvironmentServiceAttachment:FusionEnvironmentServiceAttachment test_fusion_environment_service_attachment "fusionEnvironments/{fusionEnvironmentId}/serviceAttachments/{serviceAttachmentId}"
        ```

        :param str resource_name: The name of the resource.
        :param FusionEnvironmentServiceAttachmentArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(FusionEnvironmentServiceAttachmentArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 defined_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
                 fusion_environment_id: Optional[pulumi.Input[str]] = None,
                 service_instance_id: Optional[pulumi.Input[str]] = None,
                 service_instance_type: Optional[pulumi.Input[str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = FusionEnvironmentServiceAttachmentArgs.__new__(FusionEnvironmentServiceAttachmentArgs)

            __props__.__dict__["defined_tags"] = defined_tags
            if fusion_environment_id is None and not opts.urn:
                raise TypeError("Missing required property 'fusion_environment_id'")
            __props__.__dict__["fusion_environment_id"] = fusion_environment_id
            if service_instance_id is None and not opts.urn:
                raise TypeError("Missing required property 'service_instance_id'")
            __props__.__dict__["service_instance_id"] = service_instance_id
            if service_instance_type is None and not opts.urn:
                raise TypeError("Missing required property 'service_instance_type'")
            __props__.__dict__["service_instance_type"] = service_instance_type
            __props__.__dict__["compartment_id"] = None
            __props__.__dict__["display_name"] = None
            __props__.__dict__["freeform_tags"] = None
            __props__.__dict__["is_sku_based"] = None
            __props__.__dict__["service_url"] = None
            __props__.__dict__["state"] = None
            __props__.__dict__["time_created"] = None
            __props__.__dict__["time_updated"] = None
        super(FusionEnvironmentServiceAttachment, __self__).__init__(
            'oci:FusionApps/fusionEnvironmentServiceAttachment:FusionEnvironmentServiceAttachment',
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
            freeform_tags: Optional[pulumi.Input[Mapping[str, Any]]] = None,
            fusion_environment_id: Optional[pulumi.Input[str]] = None,
            is_sku_based: Optional[pulumi.Input[bool]] = None,
            service_instance_id: Optional[pulumi.Input[str]] = None,
            service_instance_type: Optional[pulumi.Input[str]] = None,
            service_url: Optional[pulumi.Input[str]] = None,
            state: Optional[pulumi.Input[str]] = None,
            time_created: Optional[pulumi.Input[str]] = None,
            time_updated: Optional[pulumi.Input[str]] = None) -> 'FusionEnvironmentServiceAttachment':
        """
        Get an existing FusionEnvironmentServiceAttachment resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] compartment_id: Compartment Identifier
        :param pulumi.Input[Mapping[str, Any]] defined_tags: Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        :param pulumi.Input[str] display_name: Service Attachment Display name, can be renamed
        :param pulumi.Input[Mapping[str, Any]] freeform_tags: Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        :param pulumi.Input[str] fusion_environment_id: unique FusionEnvironment identifier
        :param pulumi.Input[bool] is_sku_based: Whether this service is provisioned due to the customer being subscribed to a specific SKU
        :param pulumi.Input[str] service_instance_id: The service instance OCID of the instance being attached
        :param pulumi.Input[str] service_instance_type: Type of the ServiceInstance being attached.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[str] service_url: Public URL
        :param pulumi.Input[str] state: The current state of the ServiceInstance.
        :param pulumi.Input[str] time_created: The time the the ServiceInstance was created. An RFC3339 formatted datetime string
        :param pulumi.Input[str] time_updated: The time the ServiceInstance was updated. An RFC3339 formatted datetime string
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _FusionEnvironmentServiceAttachmentState.__new__(_FusionEnvironmentServiceAttachmentState)

        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["defined_tags"] = defined_tags
        __props__.__dict__["display_name"] = display_name
        __props__.__dict__["freeform_tags"] = freeform_tags
        __props__.__dict__["fusion_environment_id"] = fusion_environment_id
        __props__.__dict__["is_sku_based"] = is_sku_based
        __props__.__dict__["service_instance_id"] = service_instance_id
        __props__.__dict__["service_instance_type"] = service_instance_type
        __props__.__dict__["service_url"] = service_url
        __props__.__dict__["state"] = state
        __props__.__dict__["time_created"] = time_created
        __props__.__dict__["time_updated"] = time_updated
        return FusionEnvironmentServiceAttachment(resource_name, opts=opts, __props__=__props__)

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
        Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> pulumi.Output[str]:
        """
        Service Attachment Display name, can be renamed
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> pulumi.Output[Mapping[str, Any]]:
        """
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter(name="fusionEnvironmentId")
    def fusion_environment_id(self) -> pulumi.Output[str]:
        """
        unique FusionEnvironment identifier
        """
        return pulumi.get(self, "fusion_environment_id")

    @property
    @pulumi.getter(name="isSkuBased")
    def is_sku_based(self) -> pulumi.Output[bool]:
        """
        Whether this service is provisioned due to the customer being subscribed to a specific SKU
        """
        return pulumi.get(self, "is_sku_based")

    @property
    @pulumi.getter(name="serviceInstanceId")
    def service_instance_id(self) -> pulumi.Output[str]:
        """
        The service instance OCID of the instance being attached
        """
        return pulumi.get(self, "service_instance_id")

    @property
    @pulumi.getter(name="serviceInstanceType")
    def service_instance_type(self) -> pulumi.Output[str]:
        """
        Type of the ServiceInstance being attached.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "service_instance_type")

    @property
    @pulumi.getter(name="serviceUrl")
    def service_url(self) -> pulumi.Output[str]:
        """
        Public URL
        """
        return pulumi.get(self, "service_url")

    @property
    @pulumi.getter
    def state(self) -> pulumi.Output[str]:
        """
        The current state of the ServiceInstance.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> pulumi.Output[str]:
        """
        The time the the ServiceInstance was created. An RFC3339 formatted datetime string
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> pulumi.Output[str]:
        """
        The time the ServiceInstance was updated. An RFC3339 formatted datetime string
        """
        return pulumi.get(self, "time_updated")
