// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataIntegration.Inputs
{

    public sealed class WorkspaceExportRequestExportedItemArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Aggregator key
        /// </summary>
        [Input("aggregatorKey")]
        public Input<string>? AggregatorKey { get; set; }

        /// <summary>
        /// Object identifier
        /// </summary>
        [Input("identifier")]
        public Input<string>? Identifier { get; set; }

        /// <summary>
        /// Export object request key
        /// </summary>
        [Input("key")]
        public Input<string>? Key { get; set; }

        /// <summary>
        /// Name of the export request.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// Object name path
        /// </summary>
        [Input("namePath")]
        public Input<string>? NamePath { get; set; }

        /// <summary>
        /// Object type
        /// </summary>
        [Input("objectType")]
        public Input<string>? ObjectType { get; set; }

        /// <summary>
        /// Object version
        /// </summary>
        [Input("objectVersion")]
        public Input<string>? ObjectVersion { get; set; }

        /// <summary>
        /// time at which this object was last updated.
        /// </summary>
        [Input("timeUpdatedInMillis")]
        public Input<string>? TimeUpdatedInMillis { get; set; }

        public WorkspaceExportRequestExportedItemArgs()
        {
        }
        public static new WorkspaceExportRequestExportedItemArgs Empty => new WorkspaceExportRequestExportedItemArgs();
    }
}