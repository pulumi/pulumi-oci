# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'GetFusionEnvironmentServiceAttachmentResult',
    'AwaitableGetFusionEnvironmentServiceAttachmentResult',
    'get_fusion_environment_service_attachment',
    'get_fusion_environment_service_attachment_output',
]

@pulumi.output_type
class GetFusionEnvironmentServiceAttachmentResult:
    """
    A collection of values returned by getFusionEnvironmentServiceAttachment.
    """
    def __init__(__self__, action=None, compartment_id=None, defined_tags=None, display_name=None, freeform_tags=None, fusion_environment_id=None, id=None, is_sku_based=None, service_attachment_id=None, service_instance_id=None, service_instance_type=None, service_url=None, state=None, time_created=None, time_updated=None):
        if action and not isinstance(action, str):
            raise TypeError("Expected argument 'action' to be a str")
        pulumi.set(__self__, "action", action)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if fusion_environment_id and not isinstance(fusion_environment_id, str):
            raise TypeError("Expected argument 'fusion_environment_id' to be a str")
        pulumi.set(__self__, "fusion_environment_id", fusion_environment_id)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if is_sku_based and not isinstance(is_sku_based, bool):
            raise TypeError("Expected argument 'is_sku_based' to be a bool")
        pulumi.set(__self__, "is_sku_based", is_sku_based)
        if service_attachment_id and not isinstance(service_attachment_id, str):
            raise TypeError("Expected argument 'service_attachment_id' to be a str")
        pulumi.set(__self__, "service_attachment_id", service_attachment_id)
        if service_instance_id and not isinstance(service_instance_id, str):
            raise TypeError("Expected argument 'service_instance_id' to be a str")
        pulumi.set(__self__, "service_instance_id", service_instance_id)
        if service_instance_type and not isinstance(service_instance_type, str):
            raise TypeError("Expected argument 'service_instance_type' to be a str")
        pulumi.set(__self__, "service_instance_type", service_instance_type)
        if service_url and not isinstance(service_url, str):
            raise TypeError("Expected argument 'service_url' to be a str")
        pulumi.set(__self__, "service_url", service_url)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)

    @property
    @pulumi.getter
    def action(self) -> str:
        """
        Action
        """
        return pulumi.get(self, "action")

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
        Service Attachment Display name, can be renamed
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter(name="fusionEnvironmentId")
    def fusion_environment_id(self) -> str:
        return pulumi.get(self, "fusion_environment_id")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="isSkuBased")
    def is_sku_based(self) -> bool:
        """
        Whether this service is provisioned due to the customer being subscribed to a specific SKU
        """
        return pulumi.get(self, "is_sku_based")

    @property
    @pulumi.getter(name="serviceAttachmentId")
    def service_attachment_id(self) -> str:
        return pulumi.get(self, "service_attachment_id")

    @property
    @pulumi.getter(name="serviceInstanceId")
    def service_instance_id(self) -> str:
        """
        The ID of the service instance created that can be used to identify this on the service control plane
        """
        return pulumi.get(self, "service_instance_id")

    @property
    @pulumi.getter(name="serviceInstanceType")
    def service_instance_type(self) -> str:
        """
        Type of the serviceInstance.
        """
        return pulumi.get(self, "service_instance_type")

    @property
    @pulumi.getter(name="serviceUrl")
    def service_url(self) -> str:
        """
        Public URL
        """
        return pulumi.get(self, "service_url")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The current state of the ServiceInstance.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The time the the ServiceInstance was created. An RFC3339 formatted datetime string
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        The time the ServiceInstance was updated. An RFC3339 formatted datetime string
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetFusionEnvironmentServiceAttachmentResult(GetFusionEnvironmentServiceAttachmentResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetFusionEnvironmentServiceAttachmentResult(
            action=self.action,
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            fusion_environment_id=self.fusion_environment_id,
            id=self.id,
            is_sku_based=self.is_sku_based,
            service_attachment_id=self.service_attachment_id,
            service_instance_id=self.service_instance_id,
            service_instance_type=self.service_instance_type,
            service_url=self.service_url,
            state=self.state,
            time_created=self.time_created,
            time_updated=self.time_updated)


def get_fusion_environment_service_attachment(fusion_environment_id: Optional[str] = None,
                                              service_attachment_id: Optional[str] = None,
                                              opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetFusionEnvironmentServiceAttachmentResult:
    """
    This data source provides details about a specific Fusion Environment Service Attachment resource in Oracle Cloud Infrastructure Fusion Apps service.

    Gets a Service Attachment by identifier

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_fusion_environment_service_attachment = oci.Functions.get_fusion_environment_service_attachment(fusion_environment_id=oci_fusion_apps_fusion_environment["test_fusion_environment"]["id"],
        service_attachment_id=oci_fusion_apps_service_attachment["test_service_attachment"]["id"])
    ```


    :param str fusion_environment_id: unique FusionEnvironment identifier
    :param str service_attachment_id: OCID of the Service Attachment
    """
    __args__ = dict()
    __args__['fusionEnvironmentId'] = fusion_environment_id
    __args__['serviceAttachmentId'] = service_attachment_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Functions/getFusionEnvironmentServiceAttachment:getFusionEnvironmentServiceAttachment', __args__, opts=opts, typ=GetFusionEnvironmentServiceAttachmentResult).value

    return AwaitableGetFusionEnvironmentServiceAttachmentResult(
        action=__ret__.action,
        compartment_id=__ret__.compartment_id,
        defined_tags=__ret__.defined_tags,
        display_name=__ret__.display_name,
        freeform_tags=__ret__.freeform_tags,
        fusion_environment_id=__ret__.fusion_environment_id,
        id=__ret__.id,
        is_sku_based=__ret__.is_sku_based,
        service_attachment_id=__ret__.service_attachment_id,
        service_instance_id=__ret__.service_instance_id,
        service_instance_type=__ret__.service_instance_type,
        service_url=__ret__.service_url,
        state=__ret__.state,
        time_created=__ret__.time_created,
        time_updated=__ret__.time_updated)


@_utilities.lift_output_func(get_fusion_environment_service_attachment)
def get_fusion_environment_service_attachment_output(fusion_environment_id: Optional[pulumi.Input[str]] = None,
                                                     service_attachment_id: Optional[pulumi.Input[str]] = None,
                                                     opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetFusionEnvironmentServiceAttachmentResult]:
    """
    This data source provides details about a specific Fusion Environment Service Attachment resource in Oracle Cloud Infrastructure Fusion Apps service.

    Gets a Service Attachment by identifier

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_fusion_environment_service_attachment = oci.Functions.get_fusion_environment_service_attachment(fusion_environment_id=oci_fusion_apps_fusion_environment["test_fusion_environment"]["id"],
        service_attachment_id=oci_fusion_apps_service_attachment["test_service_attachment"]["id"])
    ```


    :param str fusion_environment_id: unique FusionEnvironment identifier
    :param str service_attachment_id: OCID of the Service Attachment
    """
    ...