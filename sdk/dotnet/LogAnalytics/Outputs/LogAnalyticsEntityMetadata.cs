// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LogAnalytics.Outputs
{

    [OutputType]
    public sealed class LogAnalyticsEntityMetadata
    {
        /// <summary>
        /// (Updatable) An array of entity metadata details.
        /// </summary>
        public readonly ImmutableArray<Outputs.LogAnalyticsEntityMetadataItem> Items;

        [OutputConstructor]
        private LogAnalyticsEntityMetadata(ImmutableArray<Outputs.LogAnalyticsEntityMetadataItem> items)
        {
            Items = items;
        }
    }
}
