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
    'GetApplianceImageResult',
    'AwaitableGetApplianceImageResult',
    'get_appliance_image',
    'get_appliance_image_output',
]

@pulumi.output_type
class GetApplianceImageResult:
    """
    A collection of values returned by getApplianceImage.
    """
    def __init__(__self__, compartment_id=None, display_name=None, id=None, items=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if items and not isinstance(items, list):
            raise TypeError("Expected argument 'items' to be a list")
        pulumi.set(__self__, "items", items)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[str]:
        """
        The name of the image to be displayed.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def items(self) -> Sequence['outputs.GetApplianceImageItemResult']:
        """
        List of appliance images.
        """
        return pulumi.get(self, "items")


class AwaitableGetApplianceImageResult(GetApplianceImageResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetApplianceImageResult(
            compartment_id=self.compartment_id,
            display_name=self.display_name,
            id=self.id,
            items=self.items)


def get_appliance_image(compartment_id: Optional[str] = None,
                        display_name: Optional[str] = None,
                        opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetApplianceImageResult:
    """
    This data source provides details about a specific Appliance Image resource in Oracle Cloud Infrastructure Cloud Bridge service.

    Returns a list of Appliance Images.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_appliance_image = oci.CloudBridge.get_appliance_image(compartment_id=var["compartment_id"],
        display_name=var["appliance_image_display_name"])
    ```


    :param str compartment_id: The ID of the compartment in which to list resources.
    :param str display_name: A filter to return only resources that match the entire display name given.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:CloudBridge/getApplianceImage:getApplianceImage', __args__, opts=opts, typ=GetApplianceImageResult).value

    return AwaitableGetApplianceImageResult(
        compartment_id=__ret__.compartment_id,
        display_name=__ret__.display_name,
        id=__ret__.id,
        items=__ret__.items)


@_utilities.lift_output_func(get_appliance_image)
def get_appliance_image_output(compartment_id: Optional[pulumi.Input[str]] = None,
                               display_name: Optional[pulumi.Input[Optional[str]]] = None,
                               opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetApplianceImageResult]:
    """
    This data source provides details about a specific Appliance Image resource in Oracle Cloud Infrastructure Cloud Bridge service.

    Returns a list of Appliance Images.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_appliance_image = oci.CloudBridge.get_appliance_image(compartment_id=var["compartment_id"],
        display_name=var["appliance_image_display_name"])
    ```


    :param str compartment_id: The ID of the compartment in which to list resources.
    :param str display_name: A filter to return only resources that match the entire display name given.
    """
    ...