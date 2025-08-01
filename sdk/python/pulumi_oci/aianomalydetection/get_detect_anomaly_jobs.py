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
    'GetDetectAnomalyJobsResult',
    'AwaitableGetDetectAnomalyJobsResult',
    'get_detect_anomaly_jobs',
    'get_detect_anomaly_jobs_output',
]

@pulumi.output_type
class GetDetectAnomalyJobsResult:
    """
    A collection of values returned by getDetectAnomalyJobs.
    """
    def __init__(__self__, compartment_id=None, detect_anomaly_job_collections=None, detect_anomaly_job_id=None, display_name=None, filters=None, id=None, model_id=None, project_id=None, state=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if detect_anomaly_job_collections and not isinstance(detect_anomaly_job_collections, list):
            raise TypeError("Expected argument 'detect_anomaly_job_collections' to be a list")
        pulumi.set(__self__, "detect_anomaly_job_collections", detect_anomaly_job_collections)
        if detect_anomaly_job_id and not isinstance(detect_anomaly_job_id, str):
            raise TypeError("Expected argument 'detect_anomaly_job_id' to be a str")
        pulumi.set(__self__, "detect_anomaly_job_id", detect_anomaly_job_id)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if model_id and not isinstance(model_id, str):
            raise TypeError("Expected argument 'model_id' to be a str")
        pulumi.set(__self__, "model_id", model_id)
        if project_id and not isinstance(project_id, str):
            raise TypeError("Expected argument 'project_id' to be a str")
        pulumi.set(__self__, "project_id", project_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The OCID of the compartment that starts the job.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="detectAnomalyJobCollections")
    def detect_anomaly_job_collections(self) -> Sequence['outputs.GetDetectAnomalyJobsDetectAnomalyJobCollectionResult']:
        """
        The list of detect_anomaly_job_collection.
        """
        return pulumi.get(self, "detect_anomaly_job_collections")

    @_builtins.property
    @pulumi.getter(name="detectAnomalyJobId")
    def detect_anomaly_job_id(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "detect_anomaly_job_id")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[_builtins.str]:
        """
        Detect anomaly job display name.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetDetectAnomalyJobsFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="modelId")
    def model_id(self) -> Optional[_builtins.str]:
        """
        The OCID of the trained model.
        """
        return pulumi.get(self, "model_id")

    @_builtins.property
    @pulumi.getter(name="projectId")
    def project_id(self) -> Optional[_builtins.str]:
        """
        The OCID of the project.
        """
        return pulumi.get(self, "project_id")

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[_builtins.str]:
        """
        The current state of the batch document job.
        """
        return pulumi.get(self, "state")


class AwaitableGetDetectAnomalyJobsResult(GetDetectAnomalyJobsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDetectAnomalyJobsResult(
            compartment_id=self.compartment_id,
            detect_anomaly_job_collections=self.detect_anomaly_job_collections,
            detect_anomaly_job_id=self.detect_anomaly_job_id,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            model_id=self.model_id,
            project_id=self.project_id,
            state=self.state)


def get_detect_anomaly_jobs(compartment_id: Optional[_builtins.str] = None,
                            detect_anomaly_job_id: Optional[_builtins.str] = None,
                            display_name: Optional[_builtins.str] = None,
                            filters: Optional[Sequence[Union['GetDetectAnomalyJobsFilterArgs', 'GetDetectAnomalyJobsFilterArgsDict']]] = None,
                            model_id: Optional[_builtins.str] = None,
                            project_id: Optional[_builtins.str] = None,
                            state: Optional[_builtins.str] = None,
                            opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDetectAnomalyJobsResult:
    """
    This data source provides the list of Detect Anomaly Jobs in Oracle Cloud Infrastructure Ai Anomaly Detection service.

    Returns a list of all the Anomaly Detection jobs in the specified compartment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_detect_anomaly_jobs = oci.AiAnomalyDetection.get_detect_anomaly_jobs(compartment_id=compartment_id,
        detect_anomaly_job_id=test_detect_anomaly_job["id"],
        display_name=detect_anomaly_job_display_name,
        model_id=test_model["id"],
        project_id=test_project["id"],
        state=detect_anomaly_job_state)
    ```


    :param _builtins.str compartment_id: The ID of the compartment in which to list resources.
    :param _builtins.str detect_anomaly_job_id: Unique Async Job identifier
    :param _builtins.str display_name: A filter to return only resources that match the entire display name given.
    :param _builtins.str model_id: The ID of the trained model for which to list the resources.
    :param _builtins.str project_id: The ID of the project for which to list the objects.
    :param _builtins.str state: <b>Filter</b> results by the specified lifecycle state. Must be a valid state for the resource type.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['detectAnomalyJobId'] = detect_anomaly_job_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['modelId'] = model_id
    __args__['projectId'] = project_id
    __args__['state'] = state
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:AiAnomalyDetection/getDetectAnomalyJobs:getDetectAnomalyJobs', __args__, opts=opts, typ=GetDetectAnomalyJobsResult).value

    return AwaitableGetDetectAnomalyJobsResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        detect_anomaly_job_collections=pulumi.get(__ret__, 'detect_anomaly_job_collections'),
        detect_anomaly_job_id=pulumi.get(__ret__, 'detect_anomaly_job_id'),
        display_name=pulumi.get(__ret__, 'display_name'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        model_id=pulumi.get(__ret__, 'model_id'),
        project_id=pulumi.get(__ret__, 'project_id'),
        state=pulumi.get(__ret__, 'state'))
def get_detect_anomaly_jobs_output(compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                                   detect_anomaly_job_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                   display_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                   filters: Optional[pulumi.Input[Optional[Sequence[Union['GetDetectAnomalyJobsFilterArgs', 'GetDetectAnomalyJobsFilterArgsDict']]]]] = None,
                                   model_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                   project_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                   state: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                   opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetDetectAnomalyJobsResult]:
    """
    This data source provides the list of Detect Anomaly Jobs in Oracle Cloud Infrastructure Ai Anomaly Detection service.

    Returns a list of all the Anomaly Detection jobs in the specified compartment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_detect_anomaly_jobs = oci.AiAnomalyDetection.get_detect_anomaly_jobs(compartment_id=compartment_id,
        detect_anomaly_job_id=test_detect_anomaly_job["id"],
        display_name=detect_anomaly_job_display_name,
        model_id=test_model["id"],
        project_id=test_project["id"],
        state=detect_anomaly_job_state)
    ```


    :param _builtins.str compartment_id: The ID of the compartment in which to list resources.
    :param _builtins.str detect_anomaly_job_id: Unique Async Job identifier
    :param _builtins.str display_name: A filter to return only resources that match the entire display name given.
    :param _builtins.str model_id: The ID of the trained model for which to list the resources.
    :param _builtins.str project_id: The ID of the project for which to list the objects.
    :param _builtins.str state: <b>Filter</b> results by the specified lifecycle state. Must be a valid state for the resource type.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['detectAnomalyJobId'] = detect_anomaly_job_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['modelId'] = model_id
    __args__['projectId'] = project_id
    __args__['state'] = state
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:AiAnomalyDetection/getDetectAnomalyJobs:getDetectAnomalyJobs', __args__, opts=opts, typ=GetDetectAnomalyJobsResult)
    return __ret__.apply(lambda __response__: GetDetectAnomalyJobsResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        detect_anomaly_job_collections=pulumi.get(__response__, 'detect_anomaly_job_collections'),
        detect_anomaly_job_id=pulumi.get(__response__, 'detect_anomaly_job_id'),
        display_name=pulumi.get(__response__, 'display_name'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        model_id=pulumi.get(__response__, 'model_id'),
        project_id=pulumi.get(__response__, 'project_id'),
        state=pulumi.get(__response__, 'state')))
