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
    'GetTraceResult',
    'AwaitableGetTraceResult',
    'get_trace',
    'get_trace_output',
]

@pulumi.output_type
class GetTraceResult:
    """
    A collection of values returned by getTrace.
    """
    def __init__(__self__, apm_domain_id=None, error_span_count=None, id=None, is_fault=None, key=None, root_span_duration_in_ms=None, root_span_operation_name=None, root_span_service_name=None, service_summaries=None, span_count=None, span_summaries=None, spans=None, time_earliest_span_started=None, time_latest_span_ended=None, time_root_span_ended=None, time_root_span_started=None, trace_duration_in_ms=None, trace_error_code=None, trace_error_type=None, trace_key=None, trace_status=None):
        if apm_domain_id and not isinstance(apm_domain_id, str):
            raise TypeError("Expected argument 'apm_domain_id' to be a str")
        pulumi.set(__self__, "apm_domain_id", apm_domain_id)
        if error_span_count and not isinstance(error_span_count, int):
            raise TypeError("Expected argument 'error_span_count' to be a int")
        pulumi.set(__self__, "error_span_count", error_span_count)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if is_fault and not isinstance(is_fault, bool):
            raise TypeError("Expected argument 'is_fault' to be a bool")
        pulumi.set(__self__, "is_fault", is_fault)
        if key and not isinstance(key, str):
            raise TypeError("Expected argument 'key' to be a str")
        pulumi.set(__self__, "key", key)
        if root_span_duration_in_ms and not isinstance(root_span_duration_in_ms, int):
            raise TypeError("Expected argument 'root_span_duration_in_ms' to be a int")
        pulumi.set(__self__, "root_span_duration_in_ms", root_span_duration_in_ms)
        if root_span_operation_name and not isinstance(root_span_operation_name, str):
            raise TypeError("Expected argument 'root_span_operation_name' to be a str")
        pulumi.set(__self__, "root_span_operation_name", root_span_operation_name)
        if root_span_service_name and not isinstance(root_span_service_name, str):
            raise TypeError("Expected argument 'root_span_service_name' to be a str")
        pulumi.set(__self__, "root_span_service_name", root_span_service_name)
        if service_summaries and not isinstance(service_summaries, list):
            raise TypeError("Expected argument 'service_summaries' to be a list")
        pulumi.set(__self__, "service_summaries", service_summaries)
        if span_count and not isinstance(span_count, int):
            raise TypeError("Expected argument 'span_count' to be a int")
        pulumi.set(__self__, "span_count", span_count)
        if span_summaries and not isinstance(span_summaries, list):
            raise TypeError("Expected argument 'span_summaries' to be a list")
        pulumi.set(__self__, "span_summaries", span_summaries)
        if spans and not isinstance(spans, list):
            raise TypeError("Expected argument 'spans' to be a list")
        pulumi.set(__self__, "spans", spans)
        if time_earliest_span_started and not isinstance(time_earliest_span_started, str):
            raise TypeError("Expected argument 'time_earliest_span_started' to be a str")
        pulumi.set(__self__, "time_earliest_span_started", time_earliest_span_started)
        if time_latest_span_ended and not isinstance(time_latest_span_ended, str):
            raise TypeError("Expected argument 'time_latest_span_ended' to be a str")
        pulumi.set(__self__, "time_latest_span_ended", time_latest_span_ended)
        if time_root_span_ended and not isinstance(time_root_span_ended, str):
            raise TypeError("Expected argument 'time_root_span_ended' to be a str")
        pulumi.set(__self__, "time_root_span_ended", time_root_span_ended)
        if time_root_span_started and not isinstance(time_root_span_started, str):
            raise TypeError("Expected argument 'time_root_span_started' to be a str")
        pulumi.set(__self__, "time_root_span_started", time_root_span_started)
        if trace_duration_in_ms and not isinstance(trace_duration_in_ms, int):
            raise TypeError("Expected argument 'trace_duration_in_ms' to be a int")
        pulumi.set(__self__, "trace_duration_in_ms", trace_duration_in_ms)
        if trace_error_code and not isinstance(trace_error_code, str):
            raise TypeError("Expected argument 'trace_error_code' to be a str")
        pulumi.set(__self__, "trace_error_code", trace_error_code)
        if trace_error_type and not isinstance(trace_error_type, str):
            raise TypeError("Expected argument 'trace_error_type' to be a str")
        pulumi.set(__self__, "trace_error_type", trace_error_type)
        if trace_key and not isinstance(trace_key, str):
            raise TypeError("Expected argument 'trace_key' to be a str")
        pulumi.set(__self__, "trace_key", trace_key)
        if trace_status and not isinstance(trace_status, str):
            raise TypeError("Expected argument 'trace_status' to be a str")
        pulumi.set(__self__, "trace_status", trace_status)

    @property
    @pulumi.getter(name="apmDomainId")
    def apm_domain_id(self) -> str:
        return pulumi.get(self, "apm_domain_id")

    @property
    @pulumi.getter(name="errorSpanCount")
    def error_span_count(self) -> int:
        """
        The number of spans with errors that have been processed by the system for the trace. Note that the number of spans with errors will be less than or equal to the total number of spans in the trace.
        """
        return pulumi.get(self, "error_span_count")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="isFault")
    def is_fault(self) -> bool:
        """
        Boolean flag that indicates whether the trace has an error.
        """
        return pulumi.get(self, "is_fault")

    @property
    @pulumi.getter
    def key(self) -> str:
        """
        Unique identifier (spanId) for the span.  Note that this field is defined as spanKey in the API and it maps to the spanId in the trace data in Application Performance Monitoring.
        """
        return pulumi.get(self, "key")

    @property
    @pulumi.getter(name="rootSpanDurationInMs")
    def root_span_duration_in_ms(self) -> int:
        """
        Time taken for the root span operation to complete in milliseconds.
        """
        return pulumi.get(self, "root_span_duration_in_ms")

    @property
    @pulumi.getter(name="rootSpanOperationName")
    def root_span_operation_name(self) -> str:
        """
        Root span name associated with the trace. This is the flow start operation name. Null is displayed if the root span is not yet completed.
        """
        return pulumi.get(self, "root_span_operation_name")

    @property
    @pulumi.getter(name="rootSpanServiceName")
    def root_span_service_name(self) -> str:
        """
        Service associated with the trace.
        """
        return pulumi.get(self, "root_span_service_name")

    @property
    @pulumi.getter(name="serviceSummaries")
    def service_summaries(self) -> Sequence['outputs.GetTraceServiceSummaryResult']:
        """
        A summary of the spans by service.
        """
        return pulumi.get(self, "service_summaries")

    @property
    @pulumi.getter(name="spanCount")
    def span_count(self) -> int:
        """
        The number of spans that have been processed by the system for the trace.  Note that there could be additional spans that have not been processed or reported yet if the trace is still in progress.
        """
        return pulumi.get(self, "span_count")

    @property
    @pulumi.getter(name="spanSummaries")
    def span_summaries(self) -> Sequence['outputs.GetTraceSpanSummaryResult']:
        """
        Summary of the information pertaining to the spans in the trace window that is being queried.
        """
        return pulumi.get(self, "span_summaries")

    @property
    @pulumi.getter
    def spans(self) -> Sequence['outputs.GetTraceSpanResult']:
        """
        An array of spans in the trace.
        """
        return pulumi.get(self, "spans")

    @property
    @pulumi.getter(name="timeEarliestSpanStarted")
    def time_earliest_span_started(self) -> str:
        """
        Start time of the earliest span in the span collection.
        """
        return pulumi.get(self, "time_earliest_span_started")

    @property
    @pulumi.getter(name="timeLatestSpanEnded")
    def time_latest_span_ended(self) -> str:
        """
        End time of the span that most recently ended in the span collection.
        """
        return pulumi.get(self, "time_latest_span_ended")

    @property
    @pulumi.getter(name="timeRootSpanEnded")
    def time_root_span_ended(self) -> str:
        """
        End time of the root span for the span collection.
        """
        return pulumi.get(self, "time_root_span_ended")

    @property
    @pulumi.getter(name="timeRootSpanStarted")
    def time_root_span_started(self) -> str:
        """
        Start time of the root span for the span collection.
        """
        return pulumi.get(self, "time_root_span_started")

    @property
    @pulumi.getter(name="traceDurationInMs")
    def trace_duration_in_ms(self) -> int:
        """
        Time between the start of the earliest span and the end of the most recent span in milliseconds.
        """
        return pulumi.get(self, "trace_duration_in_ms")

    @property
    @pulumi.getter(name="traceErrorCode")
    def trace_error_code(self) -> str:
        """
        Error code of the trace.
        """
        return pulumi.get(self, "trace_error_code")

    @property
    @pulumi.getter(name="traceErrorType")
    def trace_error_type(self) -> str:
        """
        Error type of the trace.
        """
        return pulumi.get(self, "trace_error_type")

    @property
    @pulumi.getter(name="traceKey")
    def trace_key(self) -> str:
        """
        Unique identifier for the trace.
        """
        return pulumi.get(self, "trace_key")

    @property
    @pulumi.getter(name="traceStatus")
    def trace_status(self) -> str:
        """
        The status of the trace. The trace statuses are defined as follows: complete - a root span has been recorded, but there is no information on the errors. success - a complete root span is recorded there is a successful error type and error code - HTTP 200. incomplete - the root span has not yet been received. error - the root span returned with an error. There may or may not be an associated error code or error type.
        """
        return pulumi.get(self, "trace_status")


class AwaitableGetTraceResult(GetTraceResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetTraceResult(
            apm_domain_id=self.apm_domain_id,
            error_span_count=self.error_span_count,
            id=self.id,
            is_fault=self.is_fault,
            key=self.key,
            root_span_duration_in_ms=self.root_span_duration_in_ms,
            root_span_operation_name=self.root_span_operation_name,
            root_span_service_name=self.root_span_service_name,
            service_summaries=self.service_summaries,
            span_count=self.span_count,
            span_summaries=self.span_summaries,
            spans=self.spans,
            time_earliest_span_started=self.time_earliest_span_started,
            time_latest_span_ended=self.time_latest_span_ended,
            time_root_span_ended=self.time_root_span_ended,
            time_root_span_started=self.time_root_span_started,
            trace_duration_in_ms=self.trace_duration_in_ms,
            trace_error_code=self.trace_error_code,
            trace_error_type=self.trace_error_type,
            trace_key=self.trace_key,
            trace_status=self.trace_status)


def get_trace(apm_domain_id: Optional[str] = None,
              trace_key: Optional[str] = None,
              opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetTraceResult:
    """
    This data source provides details about a specific Trace resource in Oracle Cloud Infrastructure Apm Traces service.

    Gets the trace details identified by traceId.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_trace = oci.ApmTraces.get_trace(apm_domain_id=oci_apm_apm_domain["test_apm_domain"]["id"],
        trace_key=var["trace_trace_key"])
    ```


    :param str apm_domain_id: The APM Domain ID the request is intended for.
    :param str trace_key: Unique Application Performance Monitoring trace identifier (traceId).
    """
    __args__ = dict()
    __args__['apmDomainId'] = apm_domain_id
    __args__['traceKey'] = trace_key
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:ApmTraces/getTrace:getTrace', __args__, opts=opts, typ=GetTraceResult).value

    return AwaitableGetTraceResult(
        apm_domain_id=__ret__.apm_domain_id,
        error_span_count=__ret__.error_span_count,
        id=__ret__.id,
        is_fault=__ret__.is_fault,
        key=__ret__.key,
        root_span_duration_in_ms=__ret__.root_span_duration_in_ms,
        root_span_operation_name=__ret__.root_span_operation_name,
        root_span_service_name=__ret__.root_span_service_name,
        service_summaries=__ret__.service_summaries,
        span_count=__ret__.span_count,
        span_summaries=__ret__.span_summaries,
        spans=__ret__.spans,
        time_earliest_span_started=__ret__.time_earliest_span_started,
        time_latest_span_ended=__ret__.time_latest_span_ended,
        time_root_span_ended=__ret__.time_root_span_ended,
        time_root_span_started=__ret__.time_root_span_started,
        trace_duration_in_ms=__ret__.trace_duration_in_ms,
        trace_error_code=__ret__.trace_error_code,
        trace_error_type=__ret__.trace_error_type,
        trace_key=__ret__.trace_key,
        trace_status=__ret__.trace_status)


@_utilities.lift_output_func(get_trace)
def get_trace_output(apm_domain_id: Optional[pulumi.Input[str]] = None,
                     trace_key: Optional[pulumi.Input[str]] = None,
                     opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetTraceResult]:
    """
    This data source provides details about a specific Trace resource in Oracle Cloud Infrastructure Apm Traces service.

    Gets the trace details identified by traceId.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_trace = oci.ApmTraces.get_trace(apm_domain_id=oci_apm_apm_domain["test_apm_domain"]["id"],
        trace_key=var["trace_trace_key"])
    ```


    :param str apm_domain_id: The APM Domain ID the request is intended for.
    :param str trace_key: Unique Application Performance Monitoring trace identifier (traceId).
    """
    ...