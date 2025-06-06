// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApmTraces.Outputs
{

    [OutputType]
    public sealed class GetTraceSpanResult
    {
        /// <summary>
        /// Total span duration in milliseconds.
        /// </summary>
        public readonly string DurationInMs;
        /// <summary>
        /// Indicates if the span has an error.
        /// </summary>
        public readonly bool IsError;
        /// <summary>
        /// Unique identifier (spanId) for the span.  Note that this field is defined as spanKey in the API and it maps to the spanId in the trace data in Application Performance Monitoring.
        /// </summary>
        public readonly string Key;
        /// <summary>
        /// Kind associated with the span.
        /// </summary>
        public readonly string Kind;
        /// <summary>
        /// List of logs associated with the span.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetTraceSpanLogResult> Logs;
        /// <summary>
        /// Span name associated with the trace.  This is usually the method or URI of the request.
        /// </summary>
        public readonly string OperationName;
        /// <summary>
        /// Unique parent identifier for the span if one exists. For root spans this will be null.
        /// </summary>
        public readonly string ParentSpanKey;
        /// <summary>
        /// Service name associated with the span.
        /// </summary>
        public readonly string ServiceName;
        /// <summary>
        /// Source of span (spans, syn_spans).
        /// </summary>
        public readonly string SourceName;
        /// <summary>
        /// List of tags associated with the span.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetTraceSpanTagResult> Tags;
        /// <summary>
        /// Span end time.  Timestamp when the span was completed.
        /// </summary>
        public readonly string TimeEnded;
        /// <summary>
        /// Span start time.  Timestamp when the span was started.
        /// </summary>
        public readonly string TimeStarted;
        /// <summary>
        /// Unique Application Performance Monitoring trace identifier (traceId).
        /// </summary>
        public readonly string TraceKey;

        [OutputConstructor]
        private GetTraceSpanResult(
            string durationInMs,

            bool isError,

            string key,

            string kind,

            ImmutableArray<Outputs.GetTraceSpanLogResult> logs,

            string operationName,

            string parentSpanKey,

            string serviceName,

            string sourceName,

            ImmutableArray<Outputs.GetTraceSpanTagResult> tags,

            string timeEnded,

            string timeStarted,

            string traceKey)
        {
            DurationInMs = durationInMs;
            IsError = isError;
            Key = key;
            Kind = kind;
            Logs = logs;
            OperationName = operationName;
            ParentSpanKey = parentSpanKey;
            ServiceName = serviceName;
            SourceName = sourceName;
            Tags = tags;
            TimeEnded = timeEnded;
            TimeStarted = timeStarted;
            TraceKey = traceKey;
        }
    }
}
