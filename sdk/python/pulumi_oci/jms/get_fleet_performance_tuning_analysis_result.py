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

__all__ = [
    'GetFleetPerformanceTuningAnalysisResultResult',
    'AwaitableGetFleetPerformanceTuningAnalysisResultResult',
    'get_fleet_performance_tuning_analysis_result',
    'get_fleet_performance_tuning_analysis_result_output',
]

@pulumi.output_type
class GetFleetPerformanceTuningAnalysisResultResult:
    """
    A collection of values returned by getFleetPerformanceTuningAnalysisResult.
    """
    def __init__(__self__, application_id=None, application_installation_id=None, application_installation_path=None, application_name=None, bucket=None, fleet_id=None, host_name=None, id=None, managed_instance_id=None, namespace=None, object=None, performance_tuning_analysis_result_id=None, result=None, time_created=None, time_finished=None, time_started=None, warning_count=None, work_request_id=None):
        if application_id and not isinstance(application_id, str):
            raise TypeError("Expected argument 'application_id' to be a str")
        pulumi.set(__self__, "application_id", application_id)
        if application_installation_id and not isinstance(application_installation_id, str):
            raise TypeError("Expected argument 'application_installation_id' to be a str")
        pulumi.set(__self__, "application_installation_id", application_installation_id)
        if application_installation_path and not isinstance(application_installation_path, str):
            raise TypeError("Expected argument 'application_installation_path' to be a str")
        pulumi.set(__self__, "application_installation_path", application_installation_path)
        if application_name and not isinstance(application_name, str):
            raise TypeError("Expected argument 'application_name' to be a str")
        pulumi.set(__self__, "application_name", application_name)
        if bucket and not isinstance(bucket, str):
            raise TypeError("Expected argument 'bucket' to be a str")
        pulumi.set(__self__, "bucket", bucket)
        if fleet_id and not isinstance(fleet_id, str):
            raise TypeError("Expected argument 'fleet_id' to be a str")
        pulumi.set(__self__, "fleet_id", fleet_id)
        if host_name and not isinstance(host_name, str):
            raise TypeError("Expected argument 'host_name' to be a str")
        pulumi.set(__self__, "host_name", host_name)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if managed_instance_id and not isinstance(managed_instance_id, str):
            raise TypeError("Expected argument 'managed_instance_id' to be a str")
        pulumi.set(__self__, "managed_instance_id", managed_instance_id)
        if namespace and not isinstance(namespace, str):
            raise TypeError("Expected argument 'namespace' to be a str")
        pulumi.set(__self__, "namespace", namespace)
        if object and not isinstance(object, str):
            raise TypeError("Expected argument 'object' to be a str")
        pulumi.set(__self__, "object", object)
        if performance_tuning_analysis_result_id and not isinstance(performance_tuning_analysis_result_id, str):
            raise TypeError("Expected argument 'performance_tuning_analysis_result_id' to be a str")
        pulumi.set(__self__, "performance_tuning_analysis_result_id", performance_tuning_analysis_result_id)
        if result and not isinstance(result, str):
            raise TypeError("Expected argument 'result' to be a str")
        pulumi.set(__self__, "result", result)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_finished and not isinstance(time_finished, str):
            raise TypeError("Expected argument 'time_finished' to be a str")
        pulumi.set(__self__, "time_finished", time_finished)
        if time_started and not isinstance(time_started, str):
            raise TypeError("Expected argument 'time_started' to be a str")
        pulumi.set(__self__, "time_started", time_started)
        if warning_count and not isinstance(warning_count, int):
            raise TypeError("Expected argument 'warning_count' to be a int")
        pulumi.set(__self__, "warning_count", warning_count)
        if work_request_id and not isinstance(work_request_id, str):
            raise TypeError("Expected argument 'work_request_id' to be a str")
        pulumi.set(__self__, "work_request_id", work_request_id)

    @_builtins.property
    @pulumi.getter(name="applicationId")
    def application_id(self) -> _builtins.str:
        """
        The OCID of the application for which the report has been generated.
        """
        return pulumi.get(self, "application_id")

    @_builtins.property
    @pulumi.getter(name="applicationInstallationId")
    def application_installation_id(self) -> _builtins.str:
        """
        The internal identifier of the application installation for which the report has been generated.
        """
        return pulumi.get(self, "application_installation_id")

    @_builtins.property
    @pulumi.getter(name="applicationInstallationPath")
    def application_installation_path(self) -> _builtins.str:
        """
        The installation path of the application for which the report has been generated.
        """
        return pulumi.get(self, "application_installation_path")

    @_builtins.property
    @pulumi.getter(name="applicationName")
    def application_name(self) -> _builtins.str:
        """
        The name of the application for which the report has been generated.
        """
        return pulumi.get(self, "application_name")

    @_builtins.property
    @pulumi.getter
    def bucket(self) -> _builtins.str:
        """
        The Object Storage bucket name of this analysis result.
        """
        return pulumi.get(self, "bucket")

    @_builtins.property
    @pulumi.getter(name="fleetId")
    def fleet_id(self) -> _builtins.str:
        """
        The fleet OCID.
        """
        return pulumi.get(self, "fleet_id")

    @_builtins.property
    @pulumi.getter(name="hostName")
    def host_name(self) -> _builtins.str:
        """
        The hostname of the managed instance.
        """
        return pulumi.get(self, "host_name")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="managedInstanceId")
    def managed_instance_id(self) -> _builtins.str:
        """
        The managed instance OCID.
        """
        return pulumi.get(self, "managed_instance_id")

    @_builtins.property
    @pulumi.getter
    def namespace(self) -> _builtins.str:
        """
        The Object Storage namespace of this analysis result.
        """
        return pulumi.get(self, "namespace")

    @_builtins.property
    @pulumi.getter
    def object(self) -> _builtins.str:
        """
        The Object Storage object name of this analysis result.
        """
        return pulumi.get(self, "object")

    @_builtins.property
    @pulumi.getter(name="performanceTuningAnalysisResultId")
    def performance_tuning_analysis_result_id(self) -> _builtins.str:
        return pulumi.get(self, "performance_tuning_analysis_result_id")

    @_builtins.property
    @pulumi.getter
    def result(self) -> _builtins.str:
        """
        Result of the analysis based on whether warnings have been found or not.
        """
        return pulumi.get(self, "result")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        The time the result is compiled.
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeFinished")
    def time_finished(self) -> _builtins.str:
        """
        The time the JFR recording has finished.
        """
        return pulumi.get(self, "time_finished")

    @_builtins.property
    @pulumi.getter(name="timeStarted")
    def time_started(self) -> _builtins.str:
        """
        The time the JFR recording has started.
        """
        return pulumi.get(self, "time_started")

    @_builtins.property
    @pulumi.getter(name="warningCount")
    def warning_count(self) -> _builtins.int:
        """
        Total number of warnings reported by the analysis.
        """
        return pulumi.get(self, "warning_count")

    @_builtins.property
    @pulumi.getter(name="workRequestId")
    def work_request_id(self) -> _builtins.str:
        """
        The OCID of the work request to start the analysis.
        """
        return pulumi.get(self, "work_request_id")


class AwaitableGetFleetPerformanceTuningAnalysisResultResult(GetFleetPerformanceTuningAnalysisResultResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetFleetPerformanceTuningAnalysisResultResult(
            application_id=self.application_id,
            application_installation_id=self.application_installation_id,
            application_installation_path=self.application_installation_path,
            application_name=self.application_name,
            bucket=self.bucket,
            fleet_id=self.fleet_id,
            host_name=self.host_name,
            id=self.id,
            managed_instance_id=self.managed_instance_id,
            namespace=self.namespace,
            object=self.object,
            performance_tuning_analysis_result_id=self.performance_tuning_analysis_result_id,
            result=self.result,
            time_created=self.time_created,
            time_finished=self.time_finished,
            time_started=self.time_started,
            warning_count=self.warning_count,
            work_request_id=self.work_request_id)


def get_fleet_performance_tuning_analysis_result(fleet_id: Optional[_builtins.str] = None,
                                                 performance_tuning_analysis_result_id: Optional[_builtins.str] = None,
                                                 opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetFleetPerformanceTuningAnalysisResultResult:
    """
    This data source provides details about a specific Fleet Performance Tuning Analysis Result resource in Oracle Cloud Infrastructure Jms service.

    Retrieve metadata of the Performance Tuning Analysis result.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_fleet_performance_tuning_analysis_result = oci.Jms.get_fleet_performance_tuning_analysis_result(fleet_id=test_fleet["id"],
        performance_tuning_analysis_result_id=fleet_performance_tuning_analysis_result_id)
    ```


    :param _builtins.str fleet_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
    :param _builtins.str performance_tuning_analysis_result_id: The OCID of the performance tuning analysis result.
    """
    __args__ = dict()
    __args__['fleetId'] = fleet_id
    __args__['performanceTuningAnalysisResultId'] = performance_tuning_analysis_result_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Jms/getFleetPerformanceTuningAnalysisResult:getFleetPerformanceTuningAnalysisResult', __args__, opts=opts, typ=GetFleetPerformanceTuningAnalysisResultResult).value

    return AwaitableGetFleetPerformanceTuningAnalysisResultResult(
        application_id=pulumi.get(__ret__, 'application_id'),
        application_installation_id=pulumi.get(__ret__, 'application_installation_id'),
        application_installation_path=pulumi.get(__ret__, 'application_installation_path'),
        application_name=pulumi.get(__ret__, 'application_name'),
        bucket=pulumi.get(__ret__, 'bucket'),
        fleet_id=pulumi.get(__ret__, 'fleet_id'),
        host_name=pulumi.get(__ret__, 'host_name'),
        id=pulumi.get(__ret__, 'id'),
        managed_instance_id=pulumi.get(__ret__, 'managed_instance_id'),
        namespace=pulumi.get(__ret__, 'namespace'),
        object=pulumi.get(__ret__, 'object'),
        performance_tuning_analysis_result_id=pulumi.get(__ret__, 'performance_tuning_analysis_result_id'),
        result=pulumi.get(__ret__, 'result'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_finished=pulumi.get(__ret__, 'time_finished'),
        time_started=pulumi.get(__ret__, 'time_started'),
        warning_count=pulumi.get(__ret__, 'warning_count'),
        work_request_id=pulumi.get(__ret__, 'work_request_id'))
def get_fleet_performance_tuning_analysis_result_output(fleet_id: Optional[pulumi.Input[_builtins.str]] = None,
                                                        performance_tuning_analysis_result_id: Optional[pulumi.Input[_builtins.str]] = None,
                                                        opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetFleetPerformanceTuningAnalysisResultResult]:
    """
    This data source provides details about a specific Fleet Performance Tuning Analysis Result resource in Oracle Cloud Infrastructure Jms service.

    Retrieve metadata of the Performance Tuning Analysis result.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_fleet_performance_tuning_analysis_result = oci.Jms.get_fleet_performance_tuning_analysis_result(fleet_id=test_fleet["id"],
        performance_tuning_analysis_result_id=fleet_performance_tuning_analysis_result_id)
    ```


    :param _builtins.str fleet_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
    :param _builtins.str performance_tuning_analysis_result_id: The OCID of the performance tuning analysis result.
    """
    __args__ = dict()
    __args__['fleetId'] = fleet_id
    __args__['performanceTuningAnalysisResultId'] = performance_tuning_analysis_result_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Jms/getFleetPerformanceTuningAnalysisResult:getFleetPerformanceTuningAnalysisResult', __args__, opts=opts, typ=GetFleetPerformanceTuningAnalysisResultResult)
    return __ret__.apply(lambda __response__: GetFleetPerformanceTuningAnalysisResultResult(
        application_id=pulumi.get(__response__, 'application_id'),
        application_installation_id=pulumi.get(__response__, 'application_installation_id'),
        application_installation_path=pulumi.get(__response__, 'application_installation_path'),
        application_name=pulumi.get(__response__, 'application_name'),
        bucket=pulumi.get(__response__, 'bucket'),
        fleet_id=pulumi.get(__response__, 'fleet_id'),
        host_name=pulumi.get(__response__, 'host_name'),
        id=pulumi.get(__response__, 'id'),
        managed_instance_id=pulumi.get(__response__, 'managed_instance_id'),
        namespace=pulumi.get(__response__, 'namespace'),
        object=pulumi.get(__response__, 'object'),
        performance_tuning_analysis_result_id=pulumi.get(__response__, 'performance_tuning_analysis_result_id'),
        result=pulumi.get(__response__, 'result'),
        time_created=pulumi.get(__response__, 'time_created'),
        time_finished=pulumi.get(__response__, 'time_finished'),
        time_started=pulumi.get(__response__, 'time_started'),
        warning_count=pulumi.get(__response__, 'warning_count'),
        work_request_id=pulumi.get(__response__, 'work_request_id')))
