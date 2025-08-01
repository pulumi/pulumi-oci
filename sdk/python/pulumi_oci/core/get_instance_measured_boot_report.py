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
    'GetInstanceMeasuredBootReportResult',
    'AwaitableGetInstanceMeasuredBootReportResult',
    'get_instance_measured_boot_report',
    'get_instance_measured_boot_report_output',
]

@pulumi.output_type
class GetInstanceMeasuredBootReportResult:
    """
    A collection of values returned by getInstanceMeasuredBootReport.
    """
    def __init__(__self__, id=None, instance_id=None, is_policy_verification_successful=None, measurements=None):
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if instance_id and not isinstance(instance_id, str):
            raise TypeError("Expected argument 'instance_id' to be a str")
        pulumi.set(__self__, "instance_id", instance_id)
        if is_policy_verification_successful and not isinstance(is_policy_verification_successful, bool):
            raise TypeError("Expected argument 'is_policy_verification_successful' to be a bool")
        pulumi.set(__self__, "is_policy_verification_successful", is_policy_verification_successful)
        if measurements and not isinstance(measurements, list):
            raise TypeError("Expected argument 'measurements' to be a list")
        pulumi.set(__self__, "measurements", measurements)

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="instanceId")
    def instance_id(self) -> _builtins.str:
        return pulumi.get(self, "instance_id")

    @_builtins.property
    @pulumi.getter(name="isPolicyVerificationSuccessful")
    def is_policy_verification_successful(self) -> _builtins.bool:
        """
        Whether the verification succeeded, and the new values match the expected values.
        """
        return pulumi.get(self, "is_policy_verification_successful")

    @_builtins.property
    @pulumi.getter
    def measurements(self) -> Sequence['outputs.GetInstanceMeasuredBootReportMeasurementResult']:
        """
        A list of Trusted Platform Module (TPM) Platform Configuration Register (PCR) entries.
        """
        return pulumi.get(self, "measurements")


class AwaitableGetInstanceMeasuredBootReportResult(GetInstanceMeasuredBootReportResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetInstanceMeasuredBootReportResult(
            id=self.id,
            instance_id=self.instance_id,
            is_policy_verification_successful=self.is_policy_verification_successful,
            measurements=self.measurements)


def get_instance_measured_boot_report(instance_id: Optional[_builtins.str] = None,
                                      opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetInstanceMeasuredBootReportResult:
    """
    This data source provides details about a specific Instance Measured Boot Report resource in Oracle Cloud Infrastructure Core service.

    Gets the measured boot report for this shielded instance.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_instance_measured_boot_report = oci.Core.get_instance_measured_boot_report(instance_id=test_instance["id"])
    ```


    :param _builtins.str instance_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance.
    """
    __args__ = dict()
    __args__['instanceId'] = instance_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Core/getInstanceMeasuredBootReport:getInstanceMeasuredBootReport', __args__, opts=opts, typ=GetInstanceMeasuredBootReportResult).value

    return AwaitableGetInstanceMeasuredBootReportResult(
        id=pulumi.get(__ret__, 'id'),
        instance_id=pulumi.get(__ret__, 'instance_id'),
        is_policy_verification_successful=pulumi.get(__ret__, 'is_policy_verification_successful'),
        measurements=pulumi.get(__ret__, 'measurements'))
def get_instance_measured_boot_report_output(instance_id: Optional[pulumi.Input[_builtins.str]] = None,
                                             opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetInstanceMeasuredBootReportResult]:
    """
    This data source provides details about a specific Instance Measured Boot Report resource in Oracle Cloud Infrastructure Core service.

    Gets the measured boot report for this shielded instance.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_instance_measured_boot_report = oci.Core.get_instance_measured_boot_report(instance_id=test_instance["id"])
    ```


    :param _builtins.str instance_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance.
    """
    __args__ = dict()
    __args__['instanceId'] = instance_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Core/getInstanceMeasuredBootReport:getInstanceMeasuredBootReport', __args__, opts=opts, typ=GetInstanceMeasuredBootReportResult)
    return __ret__.apply(lambda __response__: GetInstanceMeasuredBootReportResult(
        id=pulumi.get(__response__, 'id'),
        instance_id=pulumi.get(__response__, 'instance_id'),
        is_policy_verification_successful=pulumi.get(__response__, 'is_policy_verification_successful'),
        measurements=pulumi.get(__response__, 'measurements')))
