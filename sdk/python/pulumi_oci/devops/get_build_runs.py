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
    'GetBuildRunsResult',
    'AwaitableGetBuildRunsResult',
    'get_build_runs',
    'get_build_runs_output',
]

@pulumi.output_type
class GetBuildRunsResult:
    """
    A collection of values returned by getBuildRuns.
    """
    def __init__(__self__, build_pipeline_id=None, build_run_summary_collections=None, compartment_id=None, display_name=None, filters=None, id=None, project_id=None, state=None):
        if build_pipeline_id and not isinstance(build_pipeline_id, str):
            raise TypeError("Expected argument 'build_pipeline_id' to be a str")
        pulumi.set(__self__, "build_pipeline_id", build_pipeline_id)
        if build_run_summary_collections and not isinstance(build_run_summary_collections, list):
            raise TypeError("Expected argument 'build_run_summary_collections' to be a list")
        pulumi.set(__self__, "build_run_summary_collections", build_run_summary_collections)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if project_id and not isinstance(project_id, str):
            raise TypeError("Expected argument 'project_id' to be a str")
        pulumi.set(__self__, "project_id", project_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @_builtins.property
    @pulumi.getter(name="buildPipelineId")
    def build_pipeline_id(self) -> Optional[_builtins.str]:
        """
        The OCID of the build pipeline to be triggered.
        """
        return pulumi.get(self, "build_pipeline_id")

    @_builtins.property
    @pulumi.getter(name="buildRunSummaryCollections")
    def build_run_summary_collections(self) -> Sequence['outputs.GetBuildRunsBuildRunSummaryCollectionResult']:
        """
        The list of build_run_summary_collection.
        """
        return pulumi.get(self, "build_run_summary_collections")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[_builtins.str]:
        """
        The OCID of the compartment where the build is running.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[_builtins.str]:
        """
        Build run display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetBuildRunsFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> Optional[_builtins.str]:
        """
        Unique identifier that is immutable on creation.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="projectId")
    def project_id(self) -> Optional[_builtins.str]:
        """
        The OCID of the DevOps project.
        """
        return pulumi.get(self, "project_id")

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[_builtins.str]:
        """
        The current state of the build run.
        """
        return pulumi.get(self, "state")


class AwaitableGetBuildRunsResult(GetBuildRunsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetBuildRunsResult(
            build_pipeline_id=self.build_pipeline_id,
            build_run_summary_collections=self.build_run_summary_collections,
            compartment_id=self.compartment_id,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            project_id=self.project_id,
            state=self.state)


def get_build_runs(build_pipeline_id: Optional[_builtins.str] = None,
                   compartment_id: Optional[_builtins.str] = None,
                   display_name: Optional[_builtins.str] = None,
                   filters: Optional[Sequence[Union['GetBuildRunsFilterArgs', 'GetBuildRunsFilterArgsDict']]] = None,
                   id: Optional[_builtins.str] = None,
                   project_id: Optional[_builtins.str] = None,
                   state: Optional[_builtins.str] = None,
                   opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetBuildRunsResult:
    """
    This data source provides the list of Build Runs in Oracle Cloud Infrastructure Devops service.

    Returns a list of build run summary.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_build_runs = oci.DevOps.get_build_runs(build_pipeline_id=test_build_pipeline["id"],
        compartment_id=compartment_id,
        display_name=build_run_display_name,
        id=build_run_id,
        project_id=test_project["id"],
        state=build_run_state)
    ```


    :param _builtins.str build_pipeline_id: Unique build pipeline identifier.
    :param _builtins.str compartment_id: The OCID of the compartment in which to list resources.
    :param _builtins.str display_name: A filter to return only resources that match the entire display name given.
    :param _builtins.str id: Unique identifier or OCID for listing a single resource by ID.
    :param _builtins.str project_id: unique project identifier
    :param _builtins.str state: A filter to return only build runs that matches the given lifecycle state.
    """
    __args__ = dict()
    __args__['buildPipelineId'] = build_pipeline_id
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['id'] = id
    __args__['projectId'] = project_id
    __args__['state'] = state
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DevOps/getBuildRuns:getBuildRuns', __args__, opts=opts, typ=GetBuildRunsResult).value

    return AwaitableGetBuildRunsResult(
        build_pipeline_id=pulumi.get(__ret__, 'build_pipeline_id'),
        build_run_summary_collections=pulumi.get(__ret__, 'build_run_summary_collections'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        display_name=pulumi.get(__ret__, 'display_name'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        project_id=pulumi.get(__ret__, 'project_id'),
        state=pulumi.get(__ret__, 'state'))
def get_build_runs_output(build_pipeline_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                          compartment_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                          display_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                          filters: Optional[pulumi.Input[Optional[Sequence[Union['GetBuildRunsFilterArgs', 'GetBuildRunsFilterArgsDict']]]]] = None,
                          id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                          project_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                          state: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                          opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetBuildRunsResult]:
    """
    This data source provides the list of Build Runs in Oracle Cloud Infrastructure Devops service.

    Returns a list of build run summary.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_build_runs = oci.DevOps.get_build_runs(build_pipeline_id=test_build_pipeline["id"],
        compartment_id=compartment_id,
        display_name=build_run_display_name,
        id=build_run_id,
        project_id=test_project["id"],
        state=build_run_state)
    ```


    :param _builtins.str build_pipeline_id: Unique build pipeline identifier.
    :param _builtins.str compartment_id: The OCID of the compartment in which to list resources.
    :param _builtins.str display_name: A filter to return only resources that match the entire display name given.
    :param _builtins.str id: Unique identifier or OCID for listing a single resource by ID.
    :param _builtins.str project_id: unique project identifier
    :param _builtins.str state: A filter to return only build runs that matches the given lifecycle state.
    """
    __args__ = dict()
    __args__['buildPipelineId'] = build_pipeline_id
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['id'] = id
    __args__['projectId'] = project_id
    __args__['state'] = state
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:DevOps/getBuildRuns:getBuildRuns', __args__, opts=opts, typ=GetBuildRunsResult)
    return __ret__.apply(lambda __response__: GetBuildRunsResult(
        build_pipeline_id=pulumi.get(__response__, 'build_pipeline_id'),
        build_run_summary_collections=pulumi.get(__response__, 'build_run_summary_collections'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        display_name=pulumi.get(__response__, 'display_name'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        project_id=pulumi.get(__response__, 'project_id'),
        state=pulumi.get(__response__, 'state')))
