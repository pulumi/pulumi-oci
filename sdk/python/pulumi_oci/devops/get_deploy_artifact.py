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
    'GetDeployArtifactResult',
    'AwaitableGetDeployArtifactResult',
    'get_deploy_artifact',
    'get_deploy_artifact_output',
]

@pulumi.output_type
class GetDeployArtifactResult:
    """
    A collection of values returned by getDeployArtifact.
    """
    def __init__(__self__, argument_substitution_mode=None, compartment_id=None, defined_tags=None, deploy_artifact_id=None, deploy_artifact_sources=None, deploy_artifact_type=None, description=None, display_name=None, freeform_tags=None, id=None, lifecycle_details=None, project_id=None, state=None, system_tags=None, time_created=None, time_updated=None):
        if argument_substitution_mode and not isinstance(argument_substitution_mode, str):
            raise TypeError("Expected argument 'argument_substitution_mode' to be a str")
        pulumi.set(__self__, "argument_substitution_mode", argument_substitution_mode)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if deploy_artifact_id and not isinstance(deploy_artifact_id, str):
            raise TypeError("Expected argument 'deploy_artifact_id' to be a str")
        pulumi.set(__self__, "deploy_artifact_id", deploy_artifact_id)
        if deploy_artifact_sources and not isinstance(deploy_artifact_sources, list):
            raise TypeError("Expected argument 'deploy_artifact_sources' to be a list")
        pulumi.set(__self__, "deploy_artifact_sources", deploy_artifact_sources)
        if deploy_artifact_type and not isinstance(deploy_artifact_type, str):
            raise TypeError("Expected argument 'deploy_artifact_type' to be a str")
        pulumi.set(__self__, "deploy_artifact_type", deploy_artifact_type)
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

    @property
    @pulumi.getter(name="argumentSubstitutionMode")
    def argument_substitution_mode(self) -> str:
        """
        Mode for artifact parameter substitution.
        """
        return pulumi.get(self, "argument_substitution_mode")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of a compartment.
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
    @pulumi.getter(name="deployArtifactId")
    def deploy_artifact_id(self) -> str:
        return pulumi.get(self, "deploy_artifact_id")

    @property
    @pulumi.getter(name="deployArtifactSources")
    def deploy_artifact_sources(self) -> Sequence['outputs.GetDeployArtifactDeployArtifactSourceResult']:
        """
        Specifies source of an artifact.
        """
        return pulumi.get(self, "deploy_artifact_sources")

    @property
    @pulumi.getter(name="deployArtifactType")
    def deploy_artifact_type(self) -> str:
        """
        Type of the deployment artifact.
        """
        return pulumi.get(self, "deploy_artifact_type")

    @property
    @pulumi.getter
    def description(self) -> str:
        """
        Optional description about the artifact to be deployed.
        """
        return pulumi.get(self, "description")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        Deployment artifact identifier, which can be renamed and is not necessarily unique. Avoid entering confidential information.
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
        A detailed message describing the current state. For example, can be used to provide actionable information for a resource in Failed state.
        """
        return pulumi.get(self, "lifecycle_details")

    @property
    @pulumi.getter(name="projectId")
    def project_id(self) -> str:
        """
        The OCID of a project.
        """
        return pulumi.get(self, "project_id")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        Current state of the deployment artifact.
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
        Time the deployment artifact was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        Time the deployment artifact was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetDeployArtifactResult(GetDeployArtifactResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDeployArtifactResult(
            argument_substitution_mode=self.argument_substitution_mode,
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            deploy_artifact_id=self.deploy_artifact_id,
            deploy_artifact_sources=self.deploy_artifact_sources,
            deploy_artifact_type=self.deploy_artifact_type,
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


def get_deploy_artifact(deploy_artifact_id: Optional[str] = None,
                        opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDeployArtifactResult:
    """
    This data source provides details about a specific Deploy Artifact resource in Oracle Cloud Infrastructure Devops service.

    Retrieves a deployment artifact by identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_deploy_artifact = oci.DevOps.get_deploy_artifact(deploy_artifact_id=oci_devops_deploy_artifact["test_deploy_artifact"]["id"])
    ```


    :param str deploy_artifact_id: Unique artifact identifier.
    """
    __args__ = dict()
    __args__['deployArtifactId'] = deploy_artifact_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DevOps/getDeployArtifact:getDeployArtifact', __args__, opts=opts, typ=GetDeployArtifactResult).value

    return AwaitableGetDeployArtifactResult(
        argument_substitution_mode=__ret__.argument_substitution_mode,
        compartment_id=__ret__.compartment_id,
        defined_tags=__ret__.defined_tags,
        deploy_artifact_id=__ret__.deploy_artifact_id,
        deploy_artifact_sources=__ret__.deploy_artifact_sources,
        deploy_artifact_type=__ret__.deploy_artifact_type,
        description=__ret__.description,
        display_name=__ret__.display_name,
        freeform_tags=__ret__.freeform_tags,
        id=__ret__.id,
        lifecycle_details=__ret__.lifecycle_details,
        project_id=__ret__.project_id,
        state=__ret__.state,
        system_tags=__ret__.system_tags,
        time_created=__ret__.time_created,
        time_updated=__ret__.time_updated)


@_utilities.lift_output_func(get_deploy_artifact)
def get_deploy_artifact_output(deploy_artifact_id: Optional[pulumi.Input[str]] = None,
                               opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetDeployArtifactResult]:
    """
    This data source provides details about a specific Deploy Artifact resource in Oracle Cloud Infrastructure Devops service.

    Retrieves a deployment artifact by identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_deploy_artifact = oci.DevOps.get_deploy_artifact(deploy_artifact_id=oci_devops_deploy_artifact["test_deploy_artifact"]["id"])
    ```


    :param str deploy_artifact_id: Unique artifact identifier.
    """
    ...