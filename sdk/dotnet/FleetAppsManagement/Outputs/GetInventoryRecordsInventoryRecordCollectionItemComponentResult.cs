// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FleetAppsManagement.Outputs
{

    [OutputType]
    public sealed class GetInventoryRecordsInventoryRecordCollectionItemComponentResult
    {
        /// <summary>
        /// Name of the target component
        /// </summary>
        public readonly string ComponentName;
        /// <summary>
        /// Path of the component
        /// </summary>
        public readonly string ComponentPath;
        /// <summary>
        /// Version of the target component
        /// </summary>
        public readonly string ComponentVersion;
        /// <summary>
        /// List of target properties
        /// </summary>
        public readonly ImmutableArray<Outputs.GetInventoryRecordsInventoryRecordCollectionItemComponentPropertyResult> Properties;

        [OutputConstructor]
        private GetInventoryRecordsInventoryRecordCollectionItemComponentResult(
            string componentName,

            string componentPath,

            string componentVersion,

            ImmutableArray<Outputs.GetInventoryRecordsInventoryRecordCollectionItemComponentPropertyResult> properties)
        {
            ComponentName = componentName;
            ComponentPath = componentPath;
            ComponentVersion = componentVersion;
            Properties = properties;
        }
    }
}
