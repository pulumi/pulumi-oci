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
from ._inputs import *

__all__ = [
    'GetPipelineRunsResult',
    'AwaitableGetPipelineRunsResult',
    'get_pipeline_runs',
    'get_pipeline_runs_output',
]

@pulumi.output_type
class GetPipelineRunsResult:
    """
    A collection of values returned by getPipelineRuns.
    """
    def __init__(__self__, compartment_id=None, created_by=None, display_name=None, filters=None, id=None, pipeline_id=None, pipeline_runs=None, state=None):
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
        if pipeline_id and not isinstance(pipeline_id, str):
            raise TypeError("Expected argument 'pipeline_id' to be a str")
        pulumi.set(__self__, "pipeline_id", pipeline_id)
        if pipeline_runs and not isinstance(pipeline_runs, list):
            raise TypeError("Expected argument 'pipeline_runs' to be a list")
        pulumi.set(__self__, "pipeline_runs", pipeline_runs)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the pipeline run.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="createdBy")
    def created_by(self) -> Optional[str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the pipeline run.
        """
        return pulumi.get(self, "created_by")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[str]:
        """
        A user-friendly display name for the resource.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetPipelineRunsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> Optional[str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the pipeline run.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="pipelineId")
    def pipeline_id(self) -> Optional[str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the pipeline for which pipeline run is created.
        """
        return pulumi.get(self, "pipeline_id")

    @property
    @pulumi.getter(name="pipelineRuns")
    def pipeline_runs(self) -> Sequence['outputs.GetPipelineRunsPipelineRunResult']:
        """
        The list of pipeline_runs.
        """
        return pulumi.get(self, "pipeline_runs")

    @property
    @pulumi.getter
    def state(self) -> Optional[str]:
        """
        The state of the step run.
        """
        return pulumi.get(self, "state")


class AwaitableGetPipelineRunsResult(GetPipelineRunsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetPipelineRunsResult(
            compartment_id=self.compartment_id,
            created_by=self.created_by,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            pipeline_id=self.pipeline_id,
            pipeline_runs=self.pipeline_runs,
            state=self.state)


def get_pipeline_runs(compartment_id: Optional[str] = None,
                      created_by: Optional[str] = None,
                      display_name: Optional[str] = None,
                      filters: Optional[Sequence[pulumi.InputType['GetPipelineRunsFilterArgs']]] = None,
                      id: Optional[str] = None,
                      pipeline_id: Optional[str] = None,
                      state: Optional[str] = None,
                      opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetPipelineRunsResult:
    """
    This data source provides the list of Pipeline Runs in Oracle Cloud Infrastructure Data Science service.

    Returns a list of PipelineRuns.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_pipeline_runs = oci.DataScience.get_pipeline_runs(compartment_id=var["compartment_id"],
        created_by=var["pipeline_run_created_by"],
        display_name=var["pipeline_run_display_name"],
        id=var["pipeline_run_id"],
        pipeline_id=oci_datascience_pipeline["test_pipeline"]["id"],
        state=var["pipeline_run_state"])
    ```


    :param str compartment_id: <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param str created_by: <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the resource.
    :param str display_name: <b>Filter</b> results by its user-friendly name.
    :param str id: <b>Filter</b> results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resource type.
    :param str pipeline_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the pipeline.
    :param str state: The current state of the PipelineRun.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['createdBy'] = created_by
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['id'] = id
    __args__['pipelineId'] = pipeline_id
    __args__['state'] = state
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DataScience/getPipelineRuns:getPipelineRuns', __args__, opts=opts, typ=GetPipelineRunsResult).value

    return AwaitableGetPipelineRunsResult(
        compartment_id=__ret__.compartment_id,
        created_by=__ret__.created_by,
        display_name=__ret__.display_name,
        filters=__ret__.filters,
        id=__ret__.id,
        pipeline_id=__ret__.pipeline_id,
        pipeline_runs=__ret__.pipeline_runs,
        state=__ret__.state)


@_utilities.lift_output_func(get_pipeline_runs)
def get_pipeline_runs_output(compartment_id: Optional[pulumi.Input[str]] = None,
                             created_by: Optional[pulumi.Input[Optional[str]]] = None,
                             display_name: Optional[pulumi.Input[Optional[str]]] = None,
                             filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetPipelineRunsFilterArgs']]]]] = None,
                             id: Optional[pulumi.Input[Optional[str]]] = None,
                             pipeline_id: Optional[pulumi.Input[Optional[str]]] = None,
                             state: Optional[pulumi.Input[Optional[str]]] = None,
                             opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetPipelineRunsResult]:
    """
    This data source provides the list of Pipeline Runs in Oracle Cloud Infrastructure Data Science service.

    Returns a list of PipelineRuns.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_pipeline_runs = oci.DataScience.get_pipeline_runs(compartment_id=var["compartment_id"],
        created_by=var["pipeline_run_created_by"],
        display_name=var["pipeline_run_display_name"],
        id=var["pipeline_run_id"],
        pipeline_id=oci_datascience_pipeline["test_pipeline"]["id"],
        state=var["pipeline_run_state"])
    ```


    :param str compartment_id: <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param str created_by: <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the resource.
    :param str display_name: <b>Filter</b> results by its user-friendly name.
    :param str id: <b>Filter</b> results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resource type.
    :param str pipeline_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the pipeline.
    :param str state: The current state of the PipelineRun.
    """
    ...