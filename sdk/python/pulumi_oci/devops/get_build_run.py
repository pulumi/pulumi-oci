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
    'GetBuildRunResult',
    'AwaitableGetBuildRunResult',
    'get_build_run',
    'get_build_run_output',
]

@pulumi.output_type
class GetBuildRunResult:
    """
    A collection of values returned by getBuildRun.
    """
    def __init__(__self__, build_outputs=None, build_pipeline_id=None, build_run_arguments=None, build_run_id=None, build_run_progresses=None, build_run_sources=None, commit_infos=None, compartment_id=None, defined_tags=None, display_name=None, freeform_tags=None, id=None, lifecycle_details=None, project_id=None, state=None, system_tags=None, time_created=None, time_updated=None):
        if build_outputs and not isinstance(build_outputs, list):
            raise TypeError("Expected argument 'build_outputs' to be a list")
        pulumi.set(__self__, "build_outputs", build_outputs)
        if build_pipeline_id and not isinstance(build_pipeline_id, str):
            raise TypeError("Expected argument 'build_pipeline_id' to be a str")
        pulumi.set(__self__, "build_pipeline_id", build_pipeline_id)
        if build_run_arguments and not isinstance(build_run_arguments, list):
            raise TypeError("Expected argument 'build_run_arguments' to be a list")
        pulumi.set(__self__, "build_run_arguments", build_run_arguments)
        if build_run_id and not isinstance(build_run_id, str):
            raise TypeError("Expected argument 'build_run_id' to be a str")
        pulumi.set(__self__, "build_run_id", build_run_id)
        if build_run_progresses and not isinstance(build_run_progresses, list):
            raise TypeError("Expected argument 'build_run_progresses' to be a list")
        pulumi.set(__self__, "build_run_progresses", build_run_progresses)
        if build_run_sources and not isinstance(build_run_sources, list):
            raise TypeError("Expected argument 'build_run_sources' to be a list")
        pulumi.set(__self__, "build_run_sources", build_run_sources)
        if commit_infos and not isinstance(commit_infos, list):
            raise TypeError("Expected argument 'commit_infos' to be a list")
        pulumi.set(__self__, "commit_infos", commit_infos)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if project_id and not isinstance(project_id, str):
            raise TypeError("Expected argument 'project_id' to be a str")
        pulumi.set(__self__, "project_id", project_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if system_tags and not isinstance(system_tags, dict):
            raise TypeError("Expected argument 'system_tags' to be a dict")
        pulumi.set(__self__, "system_tags", system_tags)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)

    @property
    @pulumi.getter(name="buildOutputs")
    def build_outputs(self) -> Sequence['outputs.GetBuildRunBuildOutputResult']:
        """
        Outputs from the build.
        """
        return pulumi.get(self, "build_outputs")

    @property
    @pulumi.getter(name="buildPipelineId")
    def build_pipeline_id(self) -> str:
        """
        The OCID of the build pipeline to be triggered.
        """
        return pulumi.get(self, "build_pipeline_id")

    @property
    @pulumi.getter(name="buildRunArguments")
    def build_run_arguments(self) -> Sequence['outputs.GetBuildRunBuildRunArgumentResult']:
        """
        Specifies list of arguments passed along with the build run.
        """
        return pulumi.get(self, "build_run_arguments")

    @property
    @pulumi.getter(name="buildRunId")
    def build_run_id(self) -> str:
        return pulumi.get(self, "build_run_id")

    @property
    @pulumi.getter(name="buildRunProgresses")
    def build_run_progresses(self) -> Sequence['outputs.GetBuildRunBuildRunProgressResult']:
        """
        The run progress details of a build run.
        """
        return pulumi.get(self, "build_run_progresses")

    @property
    @pulumi.getter(name="buildRunSources")
    def build_run_sources(self) -> Sequence['outputs.GetBuildRunBuildRunSourceResult']:
        """
        The source from which the build run is triggered.
        """
        return pulumi.get(self, "build_run_sources")

    @property
    @pulumi.getter(name="commitInfos")
    def commit_infos(self) -> Sequence['outputs.GetBuildRunCommitInfoResult']:
        """
        Commit details that need to be used for the build run.
        """
        return pulumi.get(self, "commit_infos")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the compartment where the build is running.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        Build run display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        Unique identifier that is immutable on creation.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> str:
        """
        A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        """
        return pulumi.get(self, "lifecycle_details")

    @property
    @pulumi.getter(name="projectId")
    def project_id(self) -> str:
        """
        The OCID of the DevOps project.
        """
        return pulumi.get(self, "project_id")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The current state of the build run.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, Any]:
        """
        Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The time the build run was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        The time the build run was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetBuildRunResult(GetBuildRunResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetBuildRunResult(
            build_outputs=self.build_outputs,
            build_pipeline_id=self.build_pipeline_id,
            build_run_arguments=self.build_run_arguments,
            build_run_id=self.build_run_id,
            build_run_progresses=self.build_run_progresses,
            build_run_sources=self.build_run_sources,
            commit_infos=self.commit_infos,
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            lifecycle_details=self.lifecycle_details,
            project_id=self.project_id,
            state=self.state,
            system_tags=self.system_tags,
            time_created=self.time_created,
            time_updated=self.time_updated)


def get_build_run(build_run_id: Optional[str] = None,
                  opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetBuildRunResult:
    """
    This data source provides details about a specific Build Run resource in Oracle Cloud Infrastructure Devops service.

    Returns the details of a build run for a given build run ID.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_build_run = oci.DevOps.get_build_run(build_run_id=oci_devops_build_run["test_build_run"]["id"])
    ```


    :param str build_run_id: Unique build run identifier.
    """
    __args__ = dict()
    __args__['buildRunId'] = build_run_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DevOps/getBuildRun:getBuildRun', __args__, opts=opts, typ=GetBuildRunResult).value

    return AwaitableGetBuildRunResult(
        build_outputs=__ret__.build_outputs,
        build_pipeline_id=__ret__.build_pipeline_id,
        build_run_arguments=__ret__.build_run_arguments,
        build_run_id=__ret__.build_run_id,
        build_run_progresses=__ret__.build_run_progresses,
        build_run_sources=__ret__.build_run_sources,
        commit_infos=__ret__.commit_infos,
        compartment_id=__ret__.compartment_id,
        defined_tags=__ret__.defined_tags,
        display_name=__ret__.display_name,
        freeform_tags=__ret__.freeform_tags,
        id=__ret__.id,
        lifecycle_details=__ret__.lifecycle_details,
        project_id=__ret__.project_id,
        state=__ret__.state,
        system_tags=__ret__.system_tags,
        time_created=__ret__.time_created,
        time_updated=__ret__.time_updated)


@_utilities.lift_output_func(get_build_run)
def get_build_run_output(build_run_id: Optional[pulumi.Input[str]] = None,
                         opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetBuildRunResult]:
    """
    This data source provides details about a specific Build Run resource in Oracle Cloud Infrastructure Devops service.

    Returns the details of a build run for a given build run ID.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_build_run = oci.DevOps.get_build_run(build_run_id=oci_devops_build_run["test_build_run"]["id"])
    ```


    :param str build_run_id: Unique build run identifier.
    """
    ...