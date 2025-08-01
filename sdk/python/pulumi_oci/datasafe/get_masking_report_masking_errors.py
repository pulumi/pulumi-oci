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
from ._inputs import *

__all__ = [
    'GetMaskingReportMaskingErrorsResult',
    'AwaitableGetMaskingReportMaskingErrorsResult',
    'get_masking_report_masking_errors',
    'get_masking_report_masking_errors_output',
]

@pulumi.output_type
class GetMaskingReportMaskingErrorsResult:
    """
    A collection of values returned by getMaskingReportMaskingErrors.
    """
    def __init__(__self__, filters=None, id=None, masking_error_collections=None, masking_report_id=None, step_name=None):
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if masking_error_collections and not isinstance(masking_error_collections, list):
            raise TypeError("Expected argument 'masking_error_collections' to be a list")
        pulumi.set(__self__, "masking_error_collections", masking_error_collections)
        if masking_report_id and not isinstance(masking_report_id, str):
            raise TypeError("Expected argument 'masking_report_id' to be a str")
        pulumi.set(__self__, "masking_report_id", masking_report_id)
        if step_name and not isinstance(step_name, str):
            raise TypeError("Expected argument 'step_name' to be a str")
        pulumi.set(__self__, "step_name", step_name)

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetMaskingReportMaskingErrorsFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="maskingErrorCollections")
    def masking_error_collections(self) -> Sequence['outputs.GetMaskingReportMaskingErrorsMaskingErrorCollectionResult']:
        """
        The list of masking_error_collection.
        """
        return pulumi.get(self, "masking_error_collections")

    @_builtins.property
    @pulumi.getter(name="maskingReportId")
    def masking_report_id(self) -> _builtins.str:
        return pulumi.get(self, "masking_report_id")

    @_builtins.property
    @pulumi.getter(name="stepName")
    def step_name(self) -> Optional[_builtins.str]:
        """
        The stepName of the masking error.
        """
        return pulumi.get(self, "step_name")


class AwaitableGetMaskingReportMaskingErrorsResult(GetMaskingReportMaskingErrorsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetMaskingReportMaskingErrorsResult(
            filters=self.filters,
            id=self.id,
            masking_error_collections=self.masking_error_collections,
            masking_report_id=self.masking_report_id,
            step_name=self.step_name)


def get_masking_report_masking_errors(filters: Optional[Sequence[Union['GetMaskingReportMaskingErrorsFilterArgs', 'GetMaskingReportMaskingErrorsFilterArgsDict']]] = None,
                                      masking_report_id: Optional[_builtins.str] = None,
                                      step_name: Optional[_builtins.str] = None,
                                      opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetMaskingReportMaskingErrorsResult:
    """
    This data source provides the list of Masking Report Masking Errors in Oracle Cloud Infrastructure Data Safe service.

    Gets a list of masking errors in a masking run based on the specified query parameters.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_masking_report_masking_errors = oci.DataSafe.get_masking_report_masking_errors(masking_report_id=test_masking_report["id"],
        step_name=masking_report_masking_error_step_name)
    ```


    :param _builtins.str masking_report_id: The OCID of the masking report.
    :param _builtins.str step_name: A filter to return only masking errors that match the specified step name.
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['maskingReportId'] = masking_report_id
    __args__['stepName'] = step_name
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DataSafe/getMaskingReportMaskingErrors:getMaskingReportMaskingErrors', __args__, opts=opts, typ=GetMaskingReportMaskingErrorsResult).value

    return AwaitableGetMaskingReportMaskingErrorsResult(
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        masking_error_collections=pulumi.get(__ret__, 'masking_error_collections'),
        masking_report_id=pulumi.get(__ret__, 'masking_report_id'),
        step_name=pulumi.get(__ret__, 'step_name'))
def get_masking_report_masking_errors_output(filters: Optional[pulumi.Input[Optional[Sequence[Union['GetMaskingReportMaskingErrorsFilterArgs', 'GetMaskingReportMaskingErrorsFilterArgsDict']]]]] = None,
                                             masking_report_id: Optional[pulumi.Input[_builtins.str]] = None,
                                             step_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                             opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetMaskingReportMaskingErrorsResult]:
    """
    This data source provides the list of Masking Report Masking Errors in Oracle Cloud Infrastructure Data Safe service.

    Gets a list of masking errors in a masking run based on the specified query parameters.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_masking_report_masking_errors = oci.DataSafe.get_masking_report_masking_errors(masking_report_id=test_masking_report["id"],
        step_name=masking_report_masking_error_step_name)
    ```


    :param _builtins.str masking_report_id: The OCID of the masking report.
    :param _builtins.str step_name: A filter to return only masking errors that match the specified step name.
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['maskingReportId'] = masking_report_id
    __args__['stepName'] = step_name
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:DataSafe/getMaskingReportMaskingErrors:getMaskingReportMaskingErrors', __args__, opts=opts, typ=GetMaskingReportMaskingErrorsResult)
    return __ret__.apply(lambda __response__: GetMaskingReportMaskingErrorsResult(
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        masking_error_collections=pulumi.get(__response__, 'masking_error_collections'),
        masking_report_id=pulumi.get(__response__, 'masking_report_id'),
        step_name=pulumi.get(__response__, 'step_name')))
