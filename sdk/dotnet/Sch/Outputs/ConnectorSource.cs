// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Sch.Outputs
{

    [OutputType]
    public sealed class ConnectorSource
    {
        /// <summary>
        /// (Updatable) The type of [cursor](https://docs.cloud.oracle.com/iaas/Content/Streaming/Tasks/using_a_single_consumer.htm#usingcursors), which determines the starting point from which the stream will be consumed.
        /// </summary>
        public readonly Outputs.ConnectorSourceCursor? Cursor;
        /// <summary>
        /// (Updatable) The type descriminator.
        /// </summary>
        public readonly string Kind;
        /// <summary>
        /// (Updatable) The logs for this Logging source.
        /// </summary>
        public readonly ImmutableArray<Outputs.ConnectorSourceLogSource> LogSources;
        /// <summary>
        /// (Updatable) The list of metric namespaces to retrieve data from.
        /// </summary>
        public readonly ImmutableArray<Outputs.ConnectorSourceMonitoringSource> MonitoringSources;
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the stream.
        /// </summary>
        public readonly string? StreamId;

        [OutputConstructor]
        private ConnectorSource(
            Outputs.ConnectorSourceCursor? cursor,

            string kind,

            ImmutableArray<Outputs.ConnectorSourceLogSource> logSources,

            ImmutableArray<Outputs.ConnectorSourceMonitoringSource> monitoringSources,

            string? streamId)
        {
            Cursor = cursor;
            Kind = kind;
            LogSources = logSources;
            MonitoringSources = monitoringSources;
            StreamId = streamId;
        }
    }
}