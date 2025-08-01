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
    public sealed class GetSchedulerDefinitionsSchedulerDefinitionCollectionItemRunBookInputParameterArgumentResult
    {
        /// <summary>
        /// Content Source details.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSchedulerDefinitionsSchedulerDefinitionCollectionItemRunBookInputParameterArgumentContentResult> Contents;
        /// <summary>
        /// Task argument kind
        /// </summary>
        public readonly string Kind;
        /// <summary>
        /// Name of the input variable
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The task input
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private GetSchedulerDefinitionsSchedulerDefinitionCollectionItemRunBookInputParameterArgumentResult(
            ImmutableArray<Outputs.GetSchedulerDefinitionsSchedulerDefinitionCollectionItemRunBookInputParameterArgumentContentResult> contents,

            string kind,

            string name,

            string value)
        {
            Contents = contents;
            Kind = kind;
            Name = name;
            Value = value;
        }
    }
}
