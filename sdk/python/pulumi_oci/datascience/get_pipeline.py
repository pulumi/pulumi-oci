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
    'GetPipelineResult',
    'AwaitableGetPipelineResult',
    'get_pipeline',
    'get_pipeline_output',
]

@pulumi.output_type
class GetPipelineResult:
    """
    A collection of values returned by getPipeline.
    """
    def __init__(__self__, compartment_id=None, configuration_details=None, created_by=None, defined_tags=None, delete_related_pipeline_runs=None, description=None, display_name=None, freeform_tags=None, id=None, infrastructure_configuration_details=None, lifecycle_details=None, log_configuration_details=None, pipeline_id=None, project_id=None, state=None, step_artifacts=None, step_details=None, storage_mount_configuration_details_lists=None, system_tags=None, time_created=None, time_updated=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if configuration_details and not isinstance(configuration_details, list):
            raise TypeError("Expected argument 'configuration_details' to be a list")
        pulumi.set(__self__, "configuration_details", configuration_details)
        if created_by and not isinstance(created_by, str):
            raise TypeError("Expected argument 'created_by' to be a str")
        pulumi.set(__self__, "created_by", created_by)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if delete_related_pipeline_runs and not isinstance(delete_related_pipeline_runs, bool):
            raise TypeError("Expected argument 'delete_related_pipeline_runs' to be a bool")
        pulumi.set(__self__, "delete_related_pipeline_runs", delete_related_pipeline_runs)
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
        if infrastructure_configuration_details and not isinstance(infrastructure_configuration_details, list):
            raise TypeError("Expected argument 'infrastructure_configuration_details' to be a list")
        pulumi.set(__self__, "infrastructure_configuration_details", infrastructure_configuration_details)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if log_configuration_details and not isinstance(log_configuration_details, list):
            raise TypeError("Expected argument 'log_configuration_details' to be a list")
        pulumi.set(__self__, "log_configuration_details", log_configuration_details)
        if pipeline_id and not isinstance(pipeline_id, str):
            raise TypeError("Expected argument 'pipeline_id' to be a str")
        pulumi.set(__self__, "pipeline_id", pipeline_id)
        if project_id and not isinstance(project_id, str):
            raise TypeError("Expected argument 'project_id' to be a str")
        pulumi.set(__self__, "project_id", project_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if step_artifacts and not isinstance(step_artifacts, list):
            raise TypeError("Expected argument 'step_artifacts' to be a list")
        pulumi.set(__self__, "step_artifacts", step_artifacts)
        if step_details and not isinstance(step_details, list):
            raise TypeError("Expected argument 'step_details' to be a list")
        pulumi.set(__self__, "step_details", step_details)
        if storage_mount_configuration_details_lists and not isinstance(storage_mount_configuration_details_lists, list):
            raise TypeError("Expected argument 'storage_mount_configuration_details_lists' to be a list")
        pulumi.set(__self__, "storage_mount_configuration_details_lists", storage_mount_configuration_details_lists)
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
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the pipeline.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="configurationDetails")
    def configuration_details(self) -> Sequence['outputs.GetPipelineConfigurationDetailResult']:
        """
        The configuration details of a pipeline.
        """
        return pulumi.get(self, "configuration_details")

    @_builtins.property
    @pulumi.getter(name="createdBy")
    def created_by(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the pipeline.
        """
        return pulumi.get(self, "created_by")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, _builtins.str]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter(name="deleteRelatedPipelineRuns")
    def delete_related_pipeline_runs(self) -> _builtins.bool:
        """
        If set to true will delete pipeline runs which are in a terminal state.
        """
        return pulumi.get(self, "delete_related_pipeline_runs")

    @_builtins.property
    @pulumi.getter
    def description(self) -> _builtins.str:
        """
        A short description of the step.
        """
        return pulumi.get(self, "description")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> _builtins.str:
        """
        A user-friendly display name for the resource.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, _builtins.str]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the pipeline.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="infrastructureConfigurationDetails")
    def infrastructure_configuration_details(self) -> Sequence['outputs.GetPipelineInfrastructureConfigurationDetailResult']:
        """
        The infrastructure configuration details of a pipeline or a step.
        """
        return pulumi.get(self, "infrastructure_configuration_details")

    @_builtins.property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> _builtins.str:
        """
        A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in 'Failed' state.
        """
        return pulumi.get(self, "lifecycle_details")

    @_builtins.property
    @pulumi.getter(name="logConfigurationDetails")
    def log_configuration_details(self) -> Sequence['outputs.GetPipelineLogConfigurationDetailResult']:
        """
        The pipeline log configuration details.
        """
        return pulumi.get(self, "log_configuration_details")

    @_builtins.property
    @pulumi.getter(name="pipelineId")
    def pipeline_id(self) -> _builtins.str:
        return pulumi.get(self, "pipeline_id")

    @_builtins.property
    @pulumi.getter(name="projectId")
    def project_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate the pipeline with.
        """
        return pulumi.get(self, "project_id")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current state of the pipeline.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="stepArtifacts")
    def step_artifacts(self) -> Sequence['outputs.GetPipelineStepArtifactResult']:
        return pulumi.get(self, "step_artifacts")

    @_builtins.property
    @pulumi.getter(name="stepDetails")
    def step_details(self) -> Sequence['outputs.GetPipelineStepDetailResult']:
        """
        Array of step details for each step.
        """
        return pulumi.get(self, "step_details")

    @_builtins.property
    @pulumi.getter(name="storageMountConfigurationDetailsLists")
    def storage_mount_configuration_details_lists(self) -> Sequence['outputs.GetPipelineStorageMountConfigurationDetailsListResult']:
        """
        The storage mount details to mount to the instance running the pipeline step.
        """
        return pulumi.get(self, "storage_mount_configuration_details_lists")

    @_builtins.property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, _builtins.str]:
        """
        Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        The date and time the resource was created in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2020-08-06T21:10:29.41Z
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> _builtins.str:
        """
        The date and time the resource was updated in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2020-08-06T21:10:29.41Z
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetPipelineResult(GetPipelineResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetPipelineResult(
            compartment_id=self.compartment_id,
            configuration_details=self.configuration_details,
            created_by=self.created_by,
            defined_tags=self.defined_tags,
            delete_related_pipeline_runs=self.delete_related_pipeline_runs,
            description=self.description,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            infrastructure_configuration_details=self.infrastructure_configuration_details,
            lifecycle_details=self.lifecycle_details,
            log_configuration_details=self.log_configuration_details,
            pipeline_id=self.pipeline_id,
            project_id=self.project_id,
            state=self.state,
            step_artifacts=self.step_artifacts,
            step_details=self.step_details,
            storage_mount_configuration_details_lists=self.storage_mount_configuration_details_lists,
            system_tags=self.system_tags,
            time_created=self.time_created,
            time_updated=self.time_updated)


def get_pipeline(pipeline_id: Optional[_builtins.str] = None,
                 opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetPipelineResult:
    """
    This data source provides details about a specific Pipeline resource in Oracle Cloud Infrastructure Data Science service.

    Gets a Pipeline by identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_pipeline = oci.DataScience.get_pipeline(pipeline_id=test_pipeline_oci_datascience_pipeline["id"])
    ```


    :param _builtins.str pipeline_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the pipeline.
    """
    __args__ = dict()
    __args__['pipelineId'] = pipeline_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DataScience/getPipeline:getPipeline', __args__, opts=opts, typ=GetPipelineResult).value

    return AwaitableGetPipelineResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        configuration_details=pulumi.get(__ret__, 'configuration_details'),
        created_by=pulumi.get(__ret__, 'created_by'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        delete_related_pipeline_runs=pulumi.get(__ret__, 'delete_related_pipeline_runs'),
        description=pulumi.get(__ret__, 'description'),
        display_name=pulumi.get(__ret__, 'display_name'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        id=pulumi.get(__ret__, 'id'),
        infrastructure_configuration_details=pulumi.get(__ret__, 'infrastructure_configuration_details'),
        lifecycle_details=pulumi.get(__ret__, 'lifecycle_details'),
        log_configuration_details=pulumi.get(__ret__, 'log_configuration_details'),
        pipeline_id=pulumi.get(__ret__, 'pipeline_id'),
        project_id=pulumi.get(__ret__, 'project_id'),
        state=pulumi.get(__ret__, 'state'),
        step_artifacts=pulumi.get(__ret__, 'step_artifacts'),
        step_details=pulumi.get(__ret__, 'step_details'),
        storage_mount_configuration_details_lists=pulumi.get(__ret__, 'storage_mount_configuration_details_lists'),
        system_tags=pulumi.get(__ret__, 'system_tags'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_updated=pulumi.get(__ret__, 'time_updated'))
def get_pipeline_output(pipeline_id: Optional[pulumi.Input[_builtins.str]] = None,
                        opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetPipelineResult]:
    """
    This data source provides details about a specific Pipeline resource in Oracle Cloud Infrastructure Data Science service.

    Gets a Pipeline by identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_pipeline = oci.DataScience.get_pipeline(pipeline_id=test_pipeline_oci_datascience_pipeline["id"])
    ```


    :param _builtins.str pipeline_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the pipeline.
    """
    __args__ = dict()
    __args__['pipelineId'] = pipeline_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:DataScience/getPipeline:getPipeline', __args__, opts=opts, typ=GetPipelineResult)
    return __ret__.apply(lambda __response__: GetPipelineResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        configuration_details=pulumi.get(__response__, 'configuration_details'),
        created_by=pulumi.get(__response__, 'created_by'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        delete_related_pipeline_runs=pulumi.get(__response__, 'delete_related_pipeline_runs'),
        description=pulumi.get(__response__, 'description'),
        display_name=pulumi.get(__response__, 'display_name'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        id=pulumi.get(__response__, 'id'),
        infrastructure_configuration_details=pulumi.get(__response__, 'infrastructure_configuration_details'),
        lifecycle_details=pulumi.get(__response__, 'lifecycle_details'),
        log_configuration_details=pulumi.get(__response__, 'log_configuration_details'),
        pipeline_id=pulumi.get(__response__, 'pipeline_id'),
        project_id=pulumi.get(__response__, 'project_id'),
        state=pulumi.get(__response__, 'state'),
        step_artifacts=pulumi.get(__response__, 'step_artifacts'),
        step_details=pulumi.get(__response__, 'step_details'),
        storage_mount_configuration_details_lists=pulumi.get(__response__, 'storage_mount_configuration_details_lists'),
        system_tags=pulumi.get(__response__, 'system_tags'),
        time_created=pulumi.get(__response__, 'time_created'),
        time_updated=pulumi.get(__response__, 'time_updated')))
