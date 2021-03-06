# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities
from . import outputs

__all__ = [
    'GetJobRunResult',
    'AwaitableGetJobRunResult',
    'get_job_run',
    'get_job_run_output',
]

@pulumi.output_type
class GetJobRunResult:
    """
    A collection of values returned by getJobRun.
    """
    def __init__(__self__, asynchronous=None, compartment_id=None, created_by=None, defined_tags=None, display_name=None, freeform_tags=None, id=None, job_configuration_override_details=None, job_id=None, job_infrastructure_configuration_details=None, job_log_configuration_override_details=None, job_run_id=None, lifecycle_details=None, log_details=None, project_id=None, state=None, time_accepted=None, time_finished=None, time_started=None):
        if asynchronous and not isinstance(asynchronous, bool):
            raise TypeError("Expected argument 'asynchronous' to be a bool")
        pulumi.set(__self__, "asynchronous", asynchronous)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if created_by and not isinstance(created_by, str):
            raise TypeError("Expected argument 'created_by' to be a str")
        pulumi.set(__self__, "created_by", created_by)
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
        if job_configuration_override_details and not isinstance(job_configuration_override_details, list):
            raise TypeError("Expected argument 'job_configuration_override_details' to be a list")
        pulumi.set(__self__, "job_configuration_override_details", job_configuration_override_details)
        if job_id and not isinstance(job_id, str):
            raise TypeError("Expected argument 'job_id' to be a str")
        pulumi.set(__self__, "job_id", job_id)
        if job_infrastructure_configuration_details and not isinstance(job_infrastructure_configuration_details, list):
            raise TypeError("Expected argument 'job_infrastructure_configuration_details' to be a list")
        pulumi.set(__self__, "job_infrastructure_configuration_details", job_infrastructure_configuration_details)
        if job_log_configuration_override_details and not isinstance(job_log_configuration_override_details, list):
            raise TypeError("Expected argument 'job_log_configuration_override_details' to be a list")
        pulumi.set(__self__, "job_log_configuration_override_details", job_log_configuration_override_details)
        if job_run_id and not isinstance(job_run_id, str):
            raise TypeError("Expected argument 'job_run_id' to be a str")
        pulumi.set(__self__, "job_run_id", job_run_id)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if log_details and not isinstance(log_details, list):
            raise TypeError("Expected argument 'log_details' to be a list")
        pulumi.set(__self__, "log_details", log_details)
        if project_id and not isinstance(project_id, str):
            raise TypeError("Expected argument 'project_id' to be a str")
        pulumi.set(__self__, "project_id", project_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if time_accepted and not isinstance(time_accepted, str):
            raise TypeError("Expected argument 'time_accepted' to be a str")
        pulumi.set(__self__, "time_accepted", time_accepted)
        if time_finished and not isinstance(time_finished, str):
            raise TypeError("Expected argument 'time_finished' to be a str")
        pulumi.set(__self__, "time_finished", time_finished)
        if time_started and not isinstance(time_started, str):
            raise TypeError("Expected argument 'time_started' to be a str")
        pulumi.set(__self__, "time_started", time_started)

    @property
    @pulumi.getter
    def asynchronous(self) -> bool:
        return pulumi.get(self, "asynchronous")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the job.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="createdBy")
    def created_by(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the job run.
        """
        return pulumi.get(self, "created_by")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        A user-friendly display name for the resource.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the job run.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="jobConfigurationOverrideDetails")
    def job_configuration_override_details(self) -> Sequence['outputs.GetJobRunJobConfigurationOverrideDetailResult']:
        """
        The job configuration details
        """
        return pulumi.get(self, "job_configuration_override_details")

    @property
    @pulumi.getter(name="jobId")
    def job_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the job run.
        """
        return pulumi.get(self, "job_id")

    @property
    @pulumi.getter(name="jobInfrastructureConfigurationDetails")
    def job_infrastructure_configuration_details(self) -> Sequence['outputs.GetJobRunJobInfrastructureConfigurationDetailResult']:
        """
        The job infrastructure configuration details (shape, block storage, etc.)
        """
        return pulumi.get(self, "job_infrastructure_configuration_details")

    @property
    @pulumi.getter(name="jobLogConfigurationOverrideDetails")
    def job_log_configuration_override_details(self) -> Sequence['outputs.GetJobRunJobLogConfigurationOverrideDetailResult']:
        """
        Logging configuration for resource.
        """
        return pulumi.get(self, "job_log_configuration_override_details")

    @property
    @pulumi.getter(name="jobRunId")
    def job_run_id(self) -> str:
        return pulumi.get(self, "job_run_id")

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> str:
        """
        Details of the state of the job run.
        """
        return pulumi.get(self, "lifecycle_details")

    @property
    @pulumi.getter(name="logDetails")
    def log_details(self) -> Sequence['outputs.GetJobRunLogDetailResult']:
        """
        Customer logging details for job run.
        """
        return pulumi.get(self, "log_details")

    @property
    @pulumi.getter(name="projectId")
    def project_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate the job with.
        """
        return pulumi.get(self, "project_id")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The state of the job run.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeAccepted")
    def time_accepted(self) -> str:
        """
        The date and time the job run was accepted in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        """
        return pulumi.get(self, "time_accepted")

    @property
    @pulumi.getter(name="timeFinished")
    def time_finished(self) -> str:
        """
        The date and time the job run request was finished in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        """
        return pulumi.get(self, "time_finished")

    @property
    @pulumi.getter(name="timeStarted")
    def time_started(self) -> str:
        """
        The date and time the job run request was started in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        """
        return pulumi.get(self, "time_started")


class AwaitableGetJobRunResult(GetJobRunResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetJobRunResult(
            asynchronous=self.asynchronous,
            compartment_id=self.compartment_id,
            created_by=self.created_by,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            job_configuration_override_details=self.job_configuration_override_details,
            job_id=self.job_id,
            job_infrastructure_configuration_details=self.job_infrastructure_configuration_details,
            job_log_configuration_override_details=self.job_log_configuration_override_details,
            job_run_id=self.job_run_id,
            lifecycle_details=self.lifecycle_details,
            log_details=self.log_details,
            project_id=self.project_id,
            state=self.state,
            time_accepted=self.time_accepted,
            time_finished=self.time_finished,
            time_started=self.time_started)


def get_job_run(job_run_id: Optional[str] = None,
                opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetJobRunResult:
    """
    This data source provides details about a specific Job Run resource in Oracle Cloud Infrastructure Data Science service.

    Gets a job run.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_job_run = oci.DataScience.get_job_run(job_run_id=oci_datascience_job_run["test_job_run"]["id"])
    ```


    :param str job_run_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the job run.
    """
    __args__ = dict()
    __args__['jobRunId'] = job_run_id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = _utilities.get_version()
    __ret__ = pulumi.runtime.invoke('oci:DataScience/getJobRun:getJobRun', __args__, opts=opts, typ=GetJobRunResult).value

    return AwaitableGetJobRunResult(
        asynchronous=__ret__.asynchronous,
        compartment_id=__ret__.compartment_id,
        created_by=__ret__.created_by,
        defined_tags=__ret__.defined_tags,
        display_name=__ret__.display_name,
        freeform_tags=__ret__.freeform_tags,
        id=__ret__.id,
        job_configuration_override_details=__ret__.job_configuration_override_details,
        job_id=__ret__.job_id,
        job_infrastructure_configuration_details=__ret__.job_infrastructure_configuration_details,
        job_log_configuration_override_details=__ret__.job_log_configuration_override_details,
        job_run_id=__ret__.job_run_id,
        lifecycle_details=__ret__.lifecycle_details,
        log_details=__ret__.log_details,
        project_id=__ret__.project_id,
        state=__ret__.state,
        time_accepted=__ret__.time_accepted,
        time_finished=__ret__.time_finished,
        time_started=__ret__.time_started)


@_utilities.lift_output_func(get_job_run)
def get_job_run_output(job_run_id: Optional[pulumi.Input[str]] = None,
                       opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetJobRunResult]:
    """
    This data source provides details about a specific Job Run resource in Oracle Cloud Infrastructure Data Science service.

    Gets a job run.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_job_run = oci.DataScience.get_job_run(job_run_id=oci_datascience_job_run["test_job_run"]["id"])
    ```


    :param str job_run_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the job run.
    """
    ...
