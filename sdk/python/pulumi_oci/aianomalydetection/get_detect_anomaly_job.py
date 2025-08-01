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
    'GetDetectAnomalyJobResult',
    'AwaitableGetDetectAnomalyJobResult',
    'get_detect_anomaly_job',
    'get_detect_anomaly_job_output',
]

@pulumi.output_type
class GetDetectAnomalyJobResult:
    """
    A collection of values returned by getDetectAnomalyJob.
    """
    def __init__(__self__, compartment_id=None, defined_tags=None, description=None, detect_anomaly_job_id=None, display_name=None, freeform_tags=None, id=None, input_details=None, lifecycle_state_details=None, model_id=None, output_details=None, project_id=None, sensitivity=None, state=None, system_tags=None, time_accepted=None, time_finished=None, time_started=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        pulumi.set(__self__, "description", description)
        if detect_anomaly_job_id and not isinstance(detect_anomaly_job_id, str):
            raise TypeError("Expected argument 'detect_anomaly_job_id' to be a str")
        pulumi.set(__self__, "detect_anomaly_job_id", detect_anomaly_job_id)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if input_details and not isinstance(input_details, list):
            raise TypeError("Expected argument 'input_details' to be a list")
        pulumi.set(__self__, "input_details", input_details)
        if lifecycle_state_details and not isinstance(lifecycle_state_details, str):
            raise TypeError("Expected argument 'lifecycle_state_details' to be a str")
        pulumi.set(__self__, "lifecycle_state_details", lifecycle_state_details)
        if model_id and not isinstance(model_id, str):
            raise TypeError("Expected argument 'model_id' to be a str")
        pulumi.set(__self__, "model_id", model_id)
        if output_details and not isinstance(output_details, list):
            raise TypeError("Expected argument 'output_details' to be a list")
        pulumi.set(__self__, "output_details", output_details)
        if project_id and not isinstance(project_id, str):
            raise TypeError("Expected argument 'project_id' to be a str")
        pulumi.set(__self__, "project_id", project_id)
        if sensitivity and not isinstance(sensitivity, float):
            raise TypeError("Expected argument 'sensitivity' to be a float")
        pulumi.set(__self__, "sensitivity", sensitivity)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if system_tags and not isinstance(system_tags, dict):
            raise TypeError("Expected argument 'system_tags' to be a dict")
        pulumi.set(__self__, "system_tags", system_tags)
        if time_accepted and not isinstance(time_accepted, str):
            raise TypeError("Expected argument 'time_accepted' to be a str")
        pulumi.set(__self__, "time_accepted", time_accepted)
        if time_finished and not isinstance(time_finished, str):
            raise TypeError("Expected argument 'time_finished' to be a str")
        pulumi.set(__self__, "time_finished", time_finished)
        if time_started and not isinstance(time_started, str):
            raise TypeError("Expected argument 'time_started' to be a str")
        pulumi.set(__self__, "time_started", time_started)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The OCID of the compartment that starts the job.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, _builtins.str]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter
    def description(self) -> _builtins.str:
        """
        Detect anomaly job description.
        """
        return pulumi.get(self, "description")

    @_builtins.property
    @pulumi.getter(name="detectAnomalyJobId")
    def detect_anomaly_job_id(self) -> _builtins.str:
        return pulumi.get(self, "detect_anomaly_job_id")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> _builtins.str:
        """
        Detect anomaly job display name.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, _builtins.str]:
        """
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        Id of the job.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="inputDetails")
    def input_details(self) -> Sequence['outputs.GetDetectAnomalyJobInputDetailResult']:
        """
        Input details for detect anomaly job.
        """
        return pulumi.get(self, "input_details")

    @_builtins.property
    @pulumi.getter(name="lifecycleStateDetails")
    def lifecycle_state_details(self) -> _builtins.str:
        """
        The current state details of the batch document job.
        """
        return pulumi.get(self, "lifecycle_state_details")

    @_builtins.property
    @pulumi.getter(name="modelId")
    def model_id(self) -> _builtins.str:
        """
        The OCID of the trained model.
        """
        return pulumi.get(self, "model_id")

    @_builtins.property
    @pulumi.getter(name="outputDetails")
    def output_details(self) -> Sequence['outputs.GetDetectAnomalyJobOutputDetailResult']:
        """
        Output details for detect anomaly job.
        """
        return pulumi.get(self, "output_details")

    @_builtins.property
    @pulumi.getter(name="projectId")
    def project_id(self) -> _builtins.str:
        """
        The OCID of the project.
        """
        return pulumi.get(self, "project_id")

    @_builtins.property
    @pulumi.getter
    def sensitivity(self) -> _builtins.float:
        """
        The value that customer can adjust to control the sensitivity of anomaly detection
        """
        return pulumi.get(self, "sensitivity")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current state of the batch document job.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, _builtins.str]:
        """
        Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @_builtins.property
    @pulumi.getter(name="timeAccepted")
    def time_accepted(self) -> _builtins.str:
        """
        Job accepted time
        """
        return pulumi.get(self, "time_accepted")

    @_builtins.property
    @pulumi.getter(name="timeFinished")
    def time_finished(self) -> _builtins.str:
        """
        Job finished time
        """
        return pulumi.get(self, "time_finished")

    @_builtins.property
    @pulumi.getter(name="timeStarted")
    def time_started(self) -> _builtins.str:
        """
        Job started time
        """
        return pulumi.get(self, "time_started")


class AwaitableGetDetectAnomalyJobResult(GetDetectAnomalyJobResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDetectAnomalyJobResult(
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            description=self.description,
            detect_anomaly_job_id=self.detect_anomaly_job_id,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            input_details=self.input_details,
            lifecycle_state_details=self.lifecycle_state_details,
            model_id=self.model_id,
            output_details=self.output_details,
            project_id=self.project_id,
            sensitivity=self.sensitivity,
            state=self.state,
            system_tags=self.system_tags,
            time_accepted=self.time_accepted,
            time_finished=self.time_finished,
            time_started=self.time_started)


def get_detect_anomaly_job(detect_anomaly_job_id: Optional[_builtins.str] = None,
                           opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDetectAnomalyJobResult:
    """
    This data source provides details about a specific Detect Anomaly Job resource in Oracle Cloud Infrastructure Ai Anomaly Detection service.

    Gets a detect anomaly asynchronous job by identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_detect_anomaly_job = oci.AiAnomalyDetection.get_detect_anomaly_job(detect_anomaly_job_id=test_detect_anomaly_job_oci_ai_anomaly_detection_detect_anomaly_job["id"])
    ```


    :param _builtins.str detect_anomaly_job_id: Unique asynchronous job identifier.
    """
    __args__ = dict()
    __args__['detectAnomalyJobId'] = detect_anomaly_job_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:AiAnomalyDetection/getDetectAnomalyJob:getDetectAnomalyJob', __args__, opts=opts, typ=GetDetectAnomalyJobResult).value

    return AwaitableGetDetectAnomalyJobResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        description=pulumi.get(__ret__, 'description'),
        detect_anomaly_job_id=pulumi.get(__ret__, 'detect_anomaly_job_id'),
        display_name=pulumi.get(__ret__, 'display_name'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        id=pulumi.get(__ret__, 'id'),
        input_details=pulumi.get(__ret__, 'input_details'),
        lifecycle_state_details=pulumi.get(__ret__, 'lifecycle_state_details'),
        model_id=pulumi.get(__ret__, 'model_id'),
        output_details=pulumi.get(__ret__, 'output_details'),
        project_id=pulumi.get(__ret__, 'project_id'),
        sensitivity=pulumi.get(__ret__, 'sensitivity'),
        state=pulumi.get(__ret__, 'state'),
        system_tags=pulumi.get(__ret__, 'system_tags'),
        time_accepted=pulumi.get(__ret__, 'time_accepted'),
        time_finished=pulumi.get(__ret__, 'time_finished'),
        time_started=pulumi.get(__ret__, 'time_started'))
def get_detect_anomaly_job_output(detect_anomaly_job_id: Optional[pulumi.Input[_builtins.str]] = None,
                                  opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetDetectAnomalyJobResult]:
    """
    This data source provides details about a specific Detect Anomaly Job resource in Oracle Cloud Infrastructure Ai Anomaly Detection service.

    Gets a detect anomaly asynchronous job by identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_detect_anomaly_job = oci.AiAnomalyDetection.get_detect_anomaly_job(detect_anomaly_job_id=test_detect_anomaly_job_oci_ai_anomaly_detection_detect_anomaly_job["id"])
    ```


    :param _builtins.str detect_anomaly_job_id: Unique asynchronous job identifier.
    """
    __args__ = dict()
    __args__['detectAnomalyJobId'] = detect_anomaly_job_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:AiAnomalyDetection/getDetectAnomalyJob:getDetectAnomalyJob', __args__, opts=opts, typ=GetDetectAnomalyJobResult)
    return __ret__.apply(lambda __response__: GetDetectAnomalyJobResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        description=pulumi.get(__response__, 'description'),
        detect_anomaly_job_id=pulumi.get(__response__, 'detect_anomaly_job_id'),
        display_name=pulumi.get(__response__, 'display_name'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        id=pulumi.get(__response__, 'id'),
        input_details=pulumi.get(__response__, 'input_details'),
        lifecycle_state_details=pulumi.get(__response__, 'lifecycle_state_details'),
        model_id=pulumi.get(__response__, 'model_id'),
        output_details=pulumi.get(__response__, 'output_details'),
        project_id=pulumi.get(__response__, 'project_id'),
        sensitivity=pulumi.get(__response__, 'sensitivity'),
        state=pulumi.get(__response__, 'state'),
        system_tags=pulumi.get(__response__, 'system_tags'),
        time_accepted=pulumi.get(__response__, 'time_accepted'),
        time_finished=pulumi.get(__response__, 'time_finished'),
        time_started=pulumi.get(__response__, 'time_started')))
