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
    'GetJobShapesResult',
    'AwaitableGetJobShapesResult',
    'get_job_shapes',
    'get_job_shapes_output',
]

@pulumi.output_type
class GetJobShapesResult:
    """
    A collection of values returned by getJobShapes.
    """
    def __init__(__self__, compartment_id=None, filters=None, id=None, job_shapes=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if job_shapes and not isinstance(job_shapes, list):
            raise TypeError("Expected argument 'job_shapes' to be a list")
        pulumi.set(__self__, "job_shapes", job_shapes)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetJobShapesFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="jobShapes")
    def job_shapes(self) -> Sequence['outputs.GetJobShapesJobShapeResult']:
        """
        The list of job_shapes.
        """
        return pulumi.get(self, "job_shapes")


class AwaitableGetJobShapesResult(GetJobShapesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetJobShapesResult(
            compartment_id=self.compartment_id,
            filters=self.filters,
            id=self.id,
            job_shapes=self.job_shapes)


def get_job_shapes(compartment_id: Optional[_builtins.str] = None,
                   filters: Optional[Sequence[Union['GetJobShapesFilterArgs', 'GetJobShapesFilterArgsDict']]] = None,
                   opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetJobShapesResult:
    """
    This data source provides the list of Job Shapes in Oracle Cloud Infrastructure Data Science service.

    List job shapes available in the specified compartment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_job_shapes = oci.DataScience.get_job_shapes(compartment_id=compartment_id)
    ```


    :param _builtins.str compartment_id: <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DataScience/getJobShapes:getJobShapes', __args__, opts=opts, typ=GetJobShapesResult).value

    return AwaitableGetJobShapesResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        job_shapes=pulumi.get(__ret__, 'job_shapes'))
def get_job_shapes_output(compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                          filters: Optional[pulumi.Input[Optional[Sequence[Union['GetJobShapesFilterArgs', 'GetJobShapesFilterArgsDict']]]]] = None,
                          opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetJobShapesResult]:
    """
    This data source provides the list of Job Shapes in Oracle Cloud Infrastructure Data Science service.

    List job shapes available in the specified compartment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_job_shapes = oci.DataScience.get_job_shapes(compartment_id=compartment_id)
    ```


    :param _builtins.str compartment_id: <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:DataScience/getJobShapes:getJobShapes', __args__, opts=opts, typ=GetJobShapesResult)
    return __ret__.apply(lambda __response__: GetJobShapesResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        job_shapes=pulumi.get(__response__, 'job_shapes')))
