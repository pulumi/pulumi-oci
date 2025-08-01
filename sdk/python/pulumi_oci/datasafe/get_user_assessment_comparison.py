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
    'GetUserAssessmentComparisonResult',
    'AwaitableGetUserAssessmentComparisonResult',
    'get_user_assessment_comparison',
    'get_user_assessment_comparison_output',
]

@pulumi.output_type
class GetUserAssessmentComparisonResult:
    """
    A collection of values returned by getUserAssessmentComparison.
    """
    def __init__(__self__, comparison_user_assessment_id=None, id=None, state=None, summaries=None, time_created=None, user_assessment_id=None):
        if comparison_user_assessment_id and not isinstance(comparison_user_assessment_id, str):
            raise TypeError("Expected argument 'comparison_user_assessment_id' to be a str")
        pulumi.set(__self__, "comparison_user_assessment_id", comparison_user_assessment_id)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if summaries and not isinstance(summaries, list):
            raise TypeError("Expected argument 'summaries' to be a list")
        pulumi.set(__self__, "summaries", summaries)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if user_assessment_id and not isinstance(user_assessment_id, str):
            raise TypeError("Expected argument 'user_assessment_id' to be a str")
        pulumi.set(__self__, "user_assessment_id", user_assessment_id)

    @_builtins.property
    @pulumi.getter(name="comparisonUserAssessmentId")
    def comparison_user_assessment_id(self) -> _builtins.str:
        return pulumi.get(self, "comparison_user_assessment_id")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current state of the user assessment comparison.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter
    def summaries(self) -> Sequence['outputs.GetUserAssessmentComparisonSummaryResult']:
        """
        List containing maps as values. Example: `{"Operations": [ {"CostCenter": "42"} ] }`
        """
        return pulumi.get(self, "summaries")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        The date and time the user assessment comparison was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="userAssessmentId")
    def user_assessment_id(self) -> _builtins.str:
        return pulumi.get(self, "user_assessment_id")


class AwaitableGetUserAssessmentComparisonResult(GetUserAssessmentComparisonResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetUserAssessmentComparisonResult(
            comparison_user_assessment_id=self.comparison_user_assessment_id,
            id=self.id,
            state=self.state,
            summaries=self.summaries,
            time_created=self.time_created,
            user_assessment_id=self.user_assessment_id)


def get_user_assessment_comparison(comparison_user_assessment_id: Optional[_builtins.str] = None,
                                   user_assessment_id: Optional[_builtins.str] = None,
                                   opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetUserAssessmentComparisonResult:
    """
    This data source provides details about a specific User Assessment Comparison resource in Oracle Cloud Infrastructure Data Safe service.

    Gets the details of the comparison report for the user assessments submitted for comparison.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_user_assessment_comparison = oci.DataSafe.get_user_assessment_comparison(comparison_user_assessment_id=test_user_assessment["id"],
        user_assessment_id=test_user_assessment["id"])
    ```


    :param _builtins.str comparison_user_assessment_id: The OCID of the baseline user assessment.
    :param _builtins.str user_assessment_id: The OCID of the user assessment.
    """
    __args__ = dict()
    __args__['comparisonUserAssessmentId'] = comparison_user_assessment_id
    __args__['userAssessmentId'] = user_assessment_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DataSafe/getUserAssessmentComparison:getUserAssessmentComparison', __args__, opts=opts, typ=GetUserAssessmentComparisonResult).value

    return AwaitableGetUserAssessmentComparisonResult(
        comparison_user_assessment_id=pulumi.get(__ret__, 'comparison_user_assessment_id'),
        id=pulumi.get(__ret__, 'id'),
        state=pulumi.get(__ret__, 'state'),
        summaries=pulumi.get(__ret__, 'summaries'),
        time_created=pulumi.get(__ret__, 'time_created'),
        user_assessment_id=pulumi.get(__ret__, 'user_assessment_id'))
def get_user_assessment_comparison_output(comparison_user_assessment_id: Optional[pulumi.Input[_builtins.str]] = None,
                                          user_assessment_id: Optional[pulumi.Input[_builtins.str]] = None,
                                          opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetUserAssessmentComparisonResult]:
    """
    This data source provides details about a specific User Assessment Comparison resource in Oracle Cloud Infrastructure Data Safe service.

    Gets the details of the comparison report for the user assessments submitted for comparison.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_user_assessment_comparison = oci.DataSafe.get_user_assessment_comparison(comparison_user_assessment_id=test_user_assessment["id"],
        user_assessment_id=test_user_assessment["id"])
    ```


    :param _builtins.str comparison_user_assessment_id: The OCID of the baseline user assessment.
    :param _builtins.str user_assessment_id: The OCID of the user assessment.
    """
    __args__ = dict()
    __args__['comparisonUserAssessmentId'] = comparison_user_assessment_id
    __args__['userAssessmentId'] = user_assessment_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:DataSafe/getUserAssessmentComparison:getUserAssessmentComparison', __args__, opts=opts, typ=GetUserAssessmentComparisonResult)
    return __ret__.apply(lambda __response__: GetUserAssessmentComparisonResult(
        comparison_user_assessment_id=pulumi.get(__response__, 'comparison_user_assessment_id'),
        id=pulumi.get(__response__, 'id'),
        state=pulumi.get(__response__, 'state'),
        summaries=pulumi.get(__response__, 'summaries'),
        time_created=pulumi.get(__response__, 'time_created'),
        user_assessment_id=pulumi.get(__response__, 'user_assessment_id')))
