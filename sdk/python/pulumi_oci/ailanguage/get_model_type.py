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
    'GetModelTypeResult',
    'AwaitableGetModelTypeResult',
    'get_model_type',
    'get_model_type_output',
]

@pulumi.output_type
class GetModelTypeResult:
    """
    A collection of values returned by getModelType.
    """
    def __init__(__self__, capabilities=None, id=None, model_type=None, versions=None):
        if capabilities and not isinstance(capabilities, str):
            raise TypeError("Expected argument 'capabilities' to be a str")
        pulumi.set(__self__, "capabilities", capabilities)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if model_type and not isinstance(model_type, str):
            raise TypeError("Expected argument 'model_type' to be a str")
        pulumi.set(__self__, "model_type", model_type)
        if versions and not isinstance(versions, list):
            raise TypeError("Expected argument 'versions' to be a list")
        pulumi.set(__self__, "versions", versions)

    @property
    @pulumi.getter
    def capabilities(self) -> str:
        """
        Model information capabilities related to version
        """
        return pulumi.get(self, "capabilities")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="modelType")
    def model_type(self) -> str:
        return pulumi.get(self, "model_type")

    @property
    @pulumi.getter
    def versions(self) -> Sequence[str]:
        """
        Model versions available for this model type
        """
        return pulumi.get(self, "versions")


class AwaitableGetModelTypeResult(GetModelTypeResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetModelTypeResult(
            capabilities=self.capabilities,
            id=self.id,
            model_type=self.model_type,
            versions=self.versions)


def get_model_type(model_type: Optional[str] = None,
                   opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetModelTypeResult:
    """
    This data source provides details about a specific Model Type resource in Oracle Cloud Infrastructure Ai Language service.

    Gets model capabilities

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_model_type = oci.AiLanguage.get_model_type(model_type=var["model_type_model_type"])
    ```


    :param str model_type: Results like version and model supported info by specifying model type
    """
    __args__ = dict()
    __args__['modelType'] = model_type
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:AiLanguage/getModelType:getModelType', __args__, opts=opts, typ=GetModelTypeResult).value

    return AwaitableGetModelTypeResult(
        capabilities=pulumi.get(__ret__, 'capabilities'),
        id=pulumi.get(__ret__, 'id'),
        model_type=pulumi.get(__ret__, 'model_type'),
        versions=pulumi.get(__ret__, 'versions'))


@_utilities.lift_output_func(get_model_type)
def get_model_type_output(model_type: Optional[pulumi.Input[str]] = None,
                          opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetModelTypeResult]:
    """
    This data source provides details about a specific Model Type resource in Oracle Cloud Infrastructure Ai Language service.

    Gets model capabilities

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_model_type = oci.AiLanguage.get_model_type(model_type=var["model_type_model_type"])
    ```


    :param str model_type: Results like version and model supported info by specifying model type
    """
    ...