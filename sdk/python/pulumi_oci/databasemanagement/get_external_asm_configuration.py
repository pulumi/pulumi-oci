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
    'GetExternalAsmConfigurationResult',
    'AwaitableGetExternalAsmConfigurationResult',
    'get_external_asm_configuration',
    'get_external_asm_configuration_output',
]

@pulumi.output_type
class GetExternalAsmConfigurationResult:
    """
    A collection of values returned by getExternalAsmConfiguration.
    """
    def __init__(__self__, external_asm_id=None, id=None, init_parameters=None):
        if external_asm_id and not isinstance(external_asm_id, str):
            raise TypeError("Expected argument 'external_asm_id' to be a str")
        pulumi.set(__self__, "external_asm_id", external_asm_id)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if init_parameters and not isinstance(init_parameters, list):
            raise TypeError("Expected argument 'init_parameters' to be a list")
        pulumi.set(__self__, "init_parameters", init_parameters)

    @property
    @pulumi.getter(name="externalAsmId")
    def external_asm_id(self) -> str:
        return pulumi.get(self, "external_asm_id")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="initParameters")
    def init_parameters(self) -> Sequence['outputs.GetExternalAsmConfigurationInitParameterResult']:
        """
        An array of initialization parameters for the external ASM instances.
        """
        return pulumi.get(self, "init_parameters")


class AwaitableGetExternalAsmConfigurationResult(GetExternalAsmConfigurationResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetExternalAsmConfigurationResult(
            external_asm_id=self.external_asm_id,
            id=self.id,
            init_parameters=self.init_parameters)


def get_external_asm_configuration(external_asm_id: Optional[str] = None,
                                   opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetExternalAsmConfigurationResult:
    """
    This data source provides details about a specific External Asm Configuration resource in Oracle Cloud Infrastructure Database Management service.

    Gets configuration details including disk groups for the external ASM specified by `externalAsmId`.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_external_asm_configuration = oci.DatabaseManagement.get_external_asm_configuration(external_asm_id=oci_database_management_external_asm["test_external_asm"]["id"])
    ```


    :param str external_asm_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external ASM.
    """
    __args__ = dict()
    __args__['externalAsmId'] = external_asm_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DatabaseManagement/getExternalAsmConfiguration:getExternalAsmConfiguration', __args__, opts=opts, typ=GetExternalAsmConfigurationResult).value

    return AwaitableGetExternalAsmConfigurationResult(
        external_asm_id=__ret__.external_asm_id,
        id=__ret__.id,
        init_parameters=__ret__.init_parameters)


@_utilities.lift_output_func(get_external_asm_configuration)
def get_external_asm_configuration_output(external_asm_id: Optional[pulumi.Input[str]] = None,
                                          opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetExternalAsmConfigurationResult]:
    """
    This data source provides details about a specific External Asm Configuration resource in Oracle Cloud Infrastructure Database Management service.

    Gets configuration details including disk groups for the external ASM specified by `externalAsmId`.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_external_asm_configuration = oci.DatabaseManagement.get_external_asm_configuration(external_asm_id=oci_database_management_external_asm["test_external_asm"]["id"])
    ```


    :param str external_asm_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external ASM.
    """
    ...