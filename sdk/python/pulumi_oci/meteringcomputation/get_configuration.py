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
    'GetConfigurationResult',
    'AwaitableGetConfigurationResult',
    'get_configuration',
    'get_configuration_output',
]

@pulumi.output_type
class GetConfigurationResult:
    """
    A collection of values returned by getConfiguration.
    """
    def __init__(__self__, id=None, items=None, tenant_id=None):
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if items and not isinstance(items, list):
            raise TypeError("Expected argument 'items' to be a list")
        pulumi.set(__self__, "items", items)
        if tenant_id and not isinstance(tenant_id, str):
            raise TypeError("Expected argument 'tenant_id' to be a str")
        pulumi.set(__self__, "tenant_id", tenant_id)

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter
    def items(self) -> Sequence['outputs.GetConfigurationItemResult']:
        """
        The list of available configurations.
        """
        return pulumi.get(self, "items")

    @_builtins.property
    @pulumi.getter(name="tenantId")
    def tenant_id(self) -> _builtins.str:
        return pulumi.get(self, "tenant_id")


class AwaitableGetConfigurationResult(GetConfigurationResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetConfigurationResult(
            id=self.id,
            items=self.items,
            tenant_id=self.tenant_id)


def get_configuration(tenant_id: Optional[_builtins.str] = None,
                      opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetConfigurationResult:
    """
    This data source provides details about a specific Configuration resource in Oracle Cloud Infrastructure Metering Computation service.

    Returns the configurations list for the UI drop-down list.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_configuration = oci.MeteringComputation.get_configuration(tenant_id=test_tenant["id"])
    ```


    :param _builtins.str tenant_id: tenant id
    """
    __args__ = dict()
    __args__['tenantId'] = tenant_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:MeteringComputation/getConfiguration:getConfiguration', __args__, opts=opts, typ=GetConfigurationResult).value

    return AwaitableGetConfigurationResult(
        id=pulumi.get(__ret__, 'id'),
        items=pulumi.get(__ret__, 'items'),
        tenant_id=pulumi.get(__ret__, 'tenant_id'))
def get_configuration_output(tenant_id: Optional[pulumi.Input[_builtins.str]] = None,
                             opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetConfigurationResult]:
    """
    This data source provides details about a specific Configuration resource in Oracle Cloud Infrastructure Metering Computation service.

    Returns the configurations list for the UI drop-down list.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_configuration = oci.MeteringComputation.get_configuration(tenant_id=test_tenant["id"])
    ```


    :param _builtins.str tenant_id: tenant id
    """
    __args__ = dict()
    __args__['tenantId'] = tenant_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:MeteringComputation/getConfiguration:getConfiguration', __args__, opts=opts, typ=GetConfigurationResult)
    return __ret__.apply(lambda __response__: GetConfigurationResult(
        id=pulumi.get(__response__, 'id'),
        items=pulumi.get(__response__, 'items'),
        tenant_id=pulumi.get(__response__, 'tenant_id')))
