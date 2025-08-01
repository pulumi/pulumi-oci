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
    'GetJobRunsResult',
    'AwaitableGetJobRunsResult',
    'get_job_runs',
    'get_job_runs_output',
]

@pulumi.output_type
class GetJobRunsResult:
    """
    A collection of values returned by getJobRuns.
    """
    def __init__(__self__, compartment_id=None, created_by=None, display_name=None, filters=None, id=None, job_id=None, job_runs=None, state=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if created_by and not isinstance(created_by, str):
            raise TypeError("Expected argument 'created_by' to be a str")
        pulumi.set(__self__, "created_by", created_by)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if job_id and not isinstance(job_id, str):
            raise TypeError("Expected argument 'job_id' to be a str")
        pulumi.set(__self__, "job_id", job_id)
        if job_runs and not isinstance(job_runs, list):
            raise TypeError("Expected argument 'job_runs' to be a list")
        pulumi.set(__self__, "job_runs", job_runs)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the job run.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="createdBy")
    def created_by(self) -> Optional[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the job run.
        """
        return pulumi.get(self, "created_by")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[_builtins.str]:
        """
        A user-friendly display name for the resource.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetJobRunsFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> Optional[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the job run.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="jobId")
    def job_id(self) -> Optional[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the job.
        """
        return pulumi.get(self, "job_id")

    @_builtins.property
    @pulumi.getter(name="jobRuns")
    def job_runs(self) -> Sequence['outputs.GetJobRunsJobRunResult']:
        """
        The list of job_runs.
        """
        return pulumi.get(self, "job_runs")

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[_builtins.str]:
        """
        The state of the job run.
        """
        return pulumi.get(self, "state")


class AwaitableGetJobRunsResult(GetJobRunsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetJobRunsResult(
            compartment_id=self.compartment_id,
            created_by=self.created_by,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            job_id=self.job_id,
            job_runs=self.job_runs,
            state=self.state)


def get_job_runs(compartment_id: Optional[_builtins.str] = None,
                 created_by: Optional[_builtins.str] = None,
                 display_name: Optional[_builtins.str] = None,
                 filters: Optional[Sequence[Union['GetJobRunsFilterArgs', 'GetJobRunsFilterArgsDict']]] = None,
                 id: Optional[_builtins.str] = None,
                 job_id: Optional[_builtins.str] = None,
                 state: Optional[_builtins.str] = None,
                 opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetJobRunsResult:
    """
    This data source provides the list of Job Runs in Oracle Cloud Infrastructure Data Science service.

    List out job runs.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_job_runs = oci.DataScience.get_job_runs(compartment_id=compartment_id,
        created_by=job_run_created_by,
        display_name=job_run_display_name,
        id=job_run_id,
        job_id=test_job["id"],
        state=job_run_state)
    ```


    :param _builtins.str compartment_id: <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param _builtins.str created_by: <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the resource.
    :param _builtins.str display_name: <b>Filter</b> results by its user-friendly name.
    :param _builtins.str id: <b>Filter</b> results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resource type.
    :param _builtins.str job_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the job.
    :param _builtins.str state: <b>Filter</b> results by the specified lifecycle state. Must be a valid state for the resource type.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['createdBy'] = created_by
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['id'] = id
    __args__['jobId'] = job_id
    __args__['state'] = state
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DataScience/getJobRuns:getJobRuns', __args__, opts=opts, typ=GetJobRunsResult).value

    return AwaitableGetJobRunsResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        created_by=pulumi.get(__ret__, 'created_by'),
        display_name=pulumi.get(__ret__, 'display_name'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        job_id=pulumi.get(__ret__, 'job_id'),
        job_runs=pulumi.get(__ret__, 'job_runs'),
        state=pulumi.get(__ret__, 'state'))
def get_job_runs_output(compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                        created_by: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                        display_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                        filters: Optional[pulumi.Input[Optional[Sequence[Union['GetJobRunsFilterArgs', 'GetJobRunsFilterArgsDict']]]]] = None,
                        id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                        job_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                        state: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                        opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetJobRunsResult]:
    """
    This data source provides the list of Job Runs in Oracle Cloud Infrastructure Data Science service.

    List out job runs.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_job_runs = oci.DataScience.get_job_runs(compartment_id=compartment_id,
        created_by=job_run_created_by,
        display_name=job_run_display_name,
        id=job_run_id,
        job_id=test_job["id"],
        state=job_run_state)
    ```


    :param _builtins.str compartment_id: <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param _builtins.str created_by: <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the resource.
    :param _builtins.str display_name: <b>Filter</b> results by its user-friendly name.
    :param _builtins.str id: <b>Filter</b> results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resource type.
    :param _builtins.str job_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the job.
    :param _builtins.str state: <b>Filter</b> results by the specified lifecycle state. Must be a valid state for the resource type.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['createdBy'] = created_by
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['id'] = id
    __args__['jobId'] = job_id
    __args__['state'] = state
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:DataScience/getJobRuns:getJobRuns', __args__, opts=opts, typ=GetJobRunsResult)
    return __ret__.apply(lambda __response__: GetJobRunsResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        created_by=pulumi.get(__response__, 'created_by'),
        display_name=pulumi.get(__response__, 'display_name'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        job_id=pulumi.get(__response__, 'job_id'),
        job_runs=pulumi.get(__response__, 'job_runs'),
        state=pulumi.get(__response__, 'state')))
