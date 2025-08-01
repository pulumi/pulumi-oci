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
    'GetDeployPipelineResult',
    'AwaitableGetDeployPipelineResult',
    'get_deploy_pipeline',
    'get_deploy_pipeline_output',
]

@pulumi.output_type
class GetDeployPipelineResult:
    """
    A collection of values returned by getDeployPipeline.
    """
    def __init__(__self__, compartment_id=None, defined_tags=None, deploy_pipeline_artifacts=None, deploy_pipeline_environments=None, deploy_pipeline_id=None, deploy_pipeline_parameters=None, description=None, display_name=None, freeform_tags=None, id=None, lifecycle_details=None, project_id=None, state=None, system_tags=None, time_created=None, time_updated=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if deploy_pipeline_artifacts and not isinstance(deploy_pipeline_artifacts, list):
            raise TypeError("Expected argument 'deploy_pipeline_artifacts' to be a list")
        pulumi.set(__self__, "deploy_pipeline_artifacts", deploy_pipeline_artifacts)
        if deploy_pipeline_environments and not isinstance(deploy_pipeline_environments, list):
            raise TypeError("Expected argument 'deploy_pipeline_environments' to be a list")
        pulumi.set(__self__, "deploy_pipeline_environments", deploy_pipeline_environments)
        if deploy_pipeline_id and not isinstance(deploy_pipeline_id, str):
            raise TypeError("Expected argument 'deploy_pipeline_id' to be a str")
        pulumi.set(__self__, "deploy_pipeline_id", deploy_pipeline_id)
        if deploy_pipeline_parameters and not isinstance(deploy_pipeline_parameters, list):
            raise TypeError("Expected argument 'deploy_pipeline_parameters' to be a list")
        pulumi.set(__self__, "deploy_pipeline_parameters", deploy_pipeline_parameters)
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        pulumi.set(__self__, "description", description)
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

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The OCID of the compartment where the pipeline is created.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, _builtins.str]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter(name="deployPipelineArtifacts")
    def deploy_pipeline_artifacts(self) -> Sequence['outputs.GetDeployPipelineDeployPipelineArtifactResult']:
        """
        List of all artifacts used in the pipeline.
        """
        return pulumi.get(self, "deploy_pipeline_artifacts")

    @_builtins.property
    @pulumi.getter(name="deployPipelineEnvironments")
    def deploy_pipeline_environments(self) -> Sequence['outputs.GetDeployPipelineDeployPipelineEnvironmentResult']:
        """
        List of all environments used in the pipeline.
        """
        return pulumi.get(self, "deploy_pipeline_environments")

    @_builtins.property
    @pulumi.getter(name="deployPipelineId")
    def deploy_pipeline_id(self) -> _builtins.str:
        return pulumi.get(self, "deploy_pipeline_id")

    @_builtins.property
    @pulumi.getter(name="deployPipelineParameters")
    def deploy_pipeline_parameters(self) -> Sequence['outputs.GetDeployPipelineDeployPipelineParameterResult']:
        """
        Specifies list of parameters present in the deployment pipeline. In case of Update operation, replaces existing parameters list. Merging with existing parameters is not supported.
        """
        return pulumi.get(self, "deploy_pipeline_parameters")

    @_builtins.property
    @pulumi.getter
    def description(self) -> _builtins.str:
        """
        Optional description about the deployment pipeline.
        """
        return pulumi.get(self, "description")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> _builtins.str:
        """
        Deployment pipeline display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, _builtins.str]:
        """
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        Unique identifier that is immutable on creation.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> _builtins.str:
        """
        A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        """
        return pulumi.get(self, "lifecycle_details")

    @_builtins.property
    @pulumi.getter(name="projectId")
    def project_id(self) -> _builtins.str:
        """
        The OCID of a project.
        """
        return pulumi.get(self, "project_id")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current state of the deployment pipeline.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, _builtins.str]:
        """
        Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        Time the deployment pipeline was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> _builtins.str:
        """
        Time the deployment pipeline was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetDeployPipelineResult(GetDeployPipelineResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDeployPipelineResult(
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            deploy_pipeline_artifacts=self.deploy_pipeline_artifacts,
            deploy_pipeline_environments=self.deploy_pipeline_environments,
            deploy_pipeline_id=self.deploy_pipeline_id,
            deploy_pipeline_parameters=self.deploy_pipeline_parameters,
            description=self.description,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            lifecycle_details=self.lifecycle_details,
            project_id=self.project_id,
            state=self.state,
            system_tags=self.system_tags,
            time_created=self.time_created,
            time_updated=self.time_updated)


def get_deploy_pipeline(deploy_pipeline_id: Optional[_builtins.str] = None,
                        opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDeployPipelineResult:
    """
    This data source provides details about a specific Deploy Pipeline resource in Oracle Cloud Infrastructure Devops service.

    Retrieves a deployment pipeline by identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_deploy_pipeline = oci.DevOps.get_deploy_pipeline(deploy_pipeline_id=test_deploy_pipeline_oci_devops_deploy_pipeline["id"])
    ```


    :param _builtins.str deploy_pipeline_id: Unique pipeline identifier.
    """
    __args__ = dict()
    __args__['deployPipelineId'] = deploy_pipeline_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DevOps/getDeployPipeline:getDeployPipeline', __args__, opts=opts, typ=GetDeployPipelineResult).value

    return AwaitableGetDeployPipelineResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        deploy_pipeline_artifacts=pulumi.get(__ret__, 'deploy_pipeline_artifacts'),
        deploy_pipeline_environments=pulumi.get(__ret__, 'deploy_pipeline_environments'),
        deploy_pipeline_id=pulumi.get(__ret__, 'deploy_pipeline_id'),
        deploy_pipeline_parameters=pulumi.get(__ret__, 'deploy_pipeline_parameters'),
        description=pulumi.get(__ret__, 'description'),
        display_name=pulumi.get(__ret__, 'display_name'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        id=pulumi.get(__ret__, 'id'),
        lifecycle_details=pulumi.get(__ret__, 'lifecycle_details'),
        project_id=pulumi.get(__ret__, 'project_id'),
        state=pulumi.get(__ret__, 'state'),
        system_tags=pulumi.get(__ret__, 'system_tags'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_updated=pulumi.get(__ret__, 'time_updated'))
def get_deploy_pipeline_output(deploy_pipeline_id: Optional[pulumi.Input[_builtins.str]] = None,
                               opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetDeployPipelineResult]:
    """
    This data source provides details about a specific Deploy Pipeline resource in Oracle Cloud Infrastructure Devops service.

    Retrieves a deployment pipeline by identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_deploy_pipeline = oci.DevOps.get_deploy_pipeline(deploy_pipeline_id=test_deploy_pipeline_oci_devops_deploy_pipeline["id"])
    ```


    :param _builtins.str deploy_pipeline_id: Unique pipeline identifier.
    """
    __args__ = dict()
    __args__['deployPipelineId'] = deploy_pipeline_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:DevOps/getDeployPipeline:getDeployPipeline', __args__, opts=opts, typ=GetDeployPipelineResult)
    return __ret__.apply(lambda __response__: GetDeployPipelineResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        deploy_pipeline_artifacts=pulumi.get(__response__, 'deploy_pipeline_artifacts'),
        deploy_pipeline_environments=pulumi.get(__response__, 'deploy_pipeline_environments'),
        deploy_pipeline_id=pulumi.get(__response__, 'deploy_pipeline_id'),
        deploy_pipeline_parameters=pulumi.get(__response__, 'deploy_pipeline_parameters'),
        description=pulumi.get(__response__, 'description'),
        display_name=pulumi.get(__response__, 'display_name'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        id=pulumi.get(__response__, 'id'),
        lifecycle_details=pulumi.get(__response__, 'lifecycle_details'),
        project_id=pulumi.get(__response__, 'project_id'),
        state=pulumi.get(__response__, 'state'),
        system_tags=pulumi.get(__response__, 'system_tags'),
        time_created=pulumi.get(__response__, 'time_created'),
        time_updated=pulumi.get(__response__, 'time_updated')))
