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
    public sealed class SchedulerDefinitionRunBookInputParameterArgument
    {
        /// <summary>
        /// (Updatable) Content Source details.
        /// </summary>
        public readonly Outputs.SchedulerDefinitionRunBookInputParameterArgumentContent? Content;
        /// <summary>
        /// (Updatable) Task argument kind
        /// </summary>
        public readonly string Kind;
        /// <summary>
        /// (Updatable) Name of the input variable
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// (Updatable) The task input
        /// </summary>
        public readonly string? Value;

        [OutputConstructor]
        private SchedulerDefinitionRunBookInputParameterArgument(
            Outputs.SchedulerDefinitionRunBookInputParameterArgumentContent? content,

            string kind,

            string name,

            string? value)
        {
            Content = content;
            Kind = kind;
            Name = name;
            Value = value;
        }
    }
}
