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
    'GetIpsecAlgorithmResult',
    'AwaitableGetIpsecAlgorithmResult',
    'get_ipsec_algorithm',
    'get_ipsec_algorithm_output',
]

@pulumi.output_type
class GetIpsecAlgorithmResult:
    """
    A collection of values returned by getIpsecAlgorithm.
    """
    def __init__(__self__, allowed_phase_one_parameters=None, allowed_phase_two_parameters=None, default_phase_one_parameters=None, default_phase_two_parameters=None, id=None):
        if allowed_phase_one_parameters and not isinstance(allowed_phase_one_parameters, list):
            raise TypeError("Expected argument 'allowed_phase_one_parameters' to be a list")
        pulumi.set(__self__, "allowed_phase_one_parameters", allowed_phase_one_parameters)
        if allowed_phase_two_parameters and not isinstance(allowed_phase_two_parameters, list):
            raise TypeError("Expected argument 'allowed_phase_two_parameters' to be a list")
        pulumi.set(__self__, "allowed_phase_two_parameters", allowed_phase_two_parameters)
        if default_phase_one_parameters and not isinstance(default_phase_one_parameters, list):
            raise TypeError("Expected argument 'default_phase_one_parameters' to be a list")
        pulumi.set(__self__, "default_phase_one_parameters", default_phase_one_parameters)
        if default_phase_two_parameters and not isinstance(default_phase_two_parameters, list):
            raise TypeError("Expected argument 'default_phase_two_parameters' to be a list")
        pulumi.set(__self__, "default_phase_two_parameters", default_phase_two_parameters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)

    @_builtins.property
    @pulumi.getter(name="allowedPhaseOneParameters")
    def allowed_phase_one_parameters(self) -> Sequence['outputs.GetIpsecAlgorithmAllowedPhaseOneParameterResult']:
        """
        Allowed phase one parameters.
        """
        return pulumi.get(self, "allowed_phase_one_parameters")

    @_builtins.property
    @pulumi.getter(name="allowedPhaseTwoParameters")
    def allowed_phase_two_parameters(self) -> Sequence['outputs.GetIpsecAlgorithmAllowedPhaseTwoParameterResult']:
        """
        Allowed phase two parameters.
        """
        return pulumi.get(self, "allowed_phase_two_parameters")

    @_builtins.property
    @pulumi.getter(name="defaultPhaseOneParameters")
    def default_phase_one_parameters(self) -> Sequence['outputs.GetIpsecAlgorithmDefaultPhaseOneParameterResult']:
        """
        Default phase one parameters.
        """
        return pulumi.get(self, "default_phase_one_parameters")

    @_builtins.property
    @pulumi.getter(name="defaultPhaseTwoParameters")
    def default_phase_two_parameters(self) -> Sequence['outputs.GetIpsecAlgorithmDefaultPhaseTwoParameterResult']:
        """
        Default phase two parameters.
        """
        return pulumi.get(self, "default_phase_two_parameters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")


class AwaitableGetIpsecAlgorithmResult(GetIpsecAlgorithmResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetIpsecAlgorithmResult(
            allowed_phase_one_parameters=self.allowed_phase_one_parameters,
            allowed_phase_two_parameters=self.allowed_phase_two_parameters,
            default_phase_one_parameters=self.default_phase_one_parameters,
            default_phase_two_parameters=self.default_phase_two_parameters,
            id=self.id)


def get_ipsec_algorithm(opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetIpsecAlgorithmResult:
    """
    This data source provides details about a specific Ipsec Algorithm resource in Oracle Cloud Infrastructure Core service.

    The parameters allowed for IKE IPSec tunnels.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_ipsec_algorithm = oci.Core.get_ipsec_algorithm()
    ```
    """
    __args__ = dict()
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Core/getIpsecAlgorithm:getIpsecAlgorithm', __args__, opts=opts, typ=GetIpsecAlgorithmResult).value

    return AwaitableGetIpsecAlgorithmResult(
        allowed_phase_one_parameters=pulumi.get(__ret__, 'allowed_phase_one_parameters'),
        allowed_phase_two_parameters=pulumi.get(__ret__, 'allowed_phase_two_parameters'),
        default_phase_one_parameters=pulumi.get(__ret__, 'default_phase_one_parameters'),
        default_phase_two_parameters=pulumi.get(__ret__, 'default_phase_two_parameters'),
        id=pulumi.get(__ret__, 'id'))
def get_ipsec_algorithm_output(opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetIpsecAlgorithmResult]:
    """
    This data source provides details about a specific Ipsec Algorithm resource in Oracle Cloud Infrastructure Core service.

    The parameters allowed for IKE IPSec tunnels.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_ipsec_algorithm = oci.Core.get_ipsec_algorithm()
    ```
    """
    __args__ = dict()
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Core/getIpsecAlgorithm:getIpsecAlgorithm', __args__, opts=opts, typ=GetIpsecAlgorithmResult)
    return __ret__.apply(lambda __response__: GetIpsecAlgorithmResult(
        allowed_phase_one_parameters=pulumi.get(__response__, 'allowed_phase_one_parameters'),
        allowed_phase_two_parameters=pulumi.get(__response__, 'allowed_phase_two_parameters'),
        default_phase_one_parameters=pulumi.get(__response__, 'default_phase_one_parameters'),
        default_phase_two_parameters=pulumi.get(__response__, 'default_phase_two_parameters'),
        id=pulumi.get(__response__, 'id')))
