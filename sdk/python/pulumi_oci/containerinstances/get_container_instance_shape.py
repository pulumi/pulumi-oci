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
    'GetContainerInstanceShapeResult',
    'AwaitableGetContainerInstanceShapeResult',
    'get_container_instance_shape',
    'get_container_instance_shape_output',
]

@pulumi.output_type
class GetContainerInstanceShapeResult:
    """
    A collection of values returned by getContainerInstanceShape.
    """
    def __init__(__self__, availability_domain=None, compartment_id=None, id=None, items=None):
        if availability_domain and not isinstance(availability_domain, str):
            raise TypeError("Expected argument 'availability_domain' to be a str")
        pulumi.set(__self__, "availability_domain", availability_domain)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if items and not isinstance(items, list):
            raise TypeError("Expected argument 'items' to be a list")
        pulumi.set(__self__, "items", items)

    @_builtins.property
    @pulumi.getter(name="availabilityDomain")
    def availability_domain(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "availability_domain")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter
    def items(self) -> Sequence['outputs.GetContainerInstanceShapeItemResult']:
        """
        List of shapes.
        """
        return pulumi.get(self, "items")


class AwaitableGetContainerInstanceShapeResult(GetContainerInstanceShapeResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetContainerInstanceShapeResult(
            availability_domain=self.availability_domain,
            compartment_id=self.compartment_id,
            id=self.id,
            items=self.items)


def get_container_instance_shape(availability_domain: Optional[_builtins.str] = None,
                                 compartment_id: Optional[_builtins.str] = None,
                                 opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetContainerInstanceShapeResult:
    """
    This data source provides details about a specific Container Instance Shape resource in Oracle Cloud Infrastructure Container Instances service.

    Get a list of shapes for creating Container Instances and their details.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_container_instance_shape = oci.ContainerInstances.get_container_instance_shape(compartment_id=compartment_id,
        availability_domain=container_instance_shape_availability_domain)
    ```


    :param _builtins.str availability_domain: The name of the availability domain.  Example: `Uocm:PHX-AD-1`
    :param _builtins.str compartment_id: The ID of the compartment in which to list resources.
    """
    __args__ = dict()
    __args__['availabilityDomain'] = availability_domain
    __args__['compartmentId'] = compartment_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:ContainerInstances/getContainerInstanceShape:getContainerInstanceShape', __args__, opts=opts, typ=GetContainerInstanceShapeResult).value

    return AwaitableGetContainerInstanceShapeResult(
        availability_domain=pulumi.get(__ret__, 'availability_domain'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        id=pulumi.get(__ret__, 'id'),
        items=pulumi.get(__ret__, 'items'))
def get_container_instance_shape_output(availability_domain: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                        compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                                        opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetContainerInstanceShapeResult]:
    """
    This data source provides details about a specific Container Instance Shape resource in Oracle Cloud Infrastructure Container Instances service.

    Get a list of shapes for creating Container Instances and their details.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_container_instance_shape = oci.ContainerInstances.get_container_instance_shape(compartment_id=compartment_id,
        availability_domain=container_instance_shape_availability_domain)
    ```


    :param _builtins.str availability_domain: The name of the availability domain.  Example: `Uocm:PHX-AD-1`
    :param _builtins.str compartment_id: The ID of the compartment in which to list resources.
    """
    __args__ = dict()
    __args__['availabilityDomain'] = availability_domain
    __args__['compartmentId'] = compartment_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:ContainerInstances/getContainerInstanceShape:getContainerInstanceShape', __args__, opts=opts, typ=GetContainerInstanceShapeResult)
    return __ret__.apply(lambda __response__: GetContainerInstanceShapeResult(
        availability_domain=pulumi.get(__response__, 'availability_domain'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        id=pulumi.get(__response__, 'id'),
        items=pulumi.get(__response__, 'items')))
