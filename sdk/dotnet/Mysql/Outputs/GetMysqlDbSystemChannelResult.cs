// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Mysql.Outputs
{

    [OutputType]
    public sealed class GetMysqlDbSystemChannelResult
    {
        /// <summary>
        /// The OCID of the compartment the DB System belongs in.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// The user-friendly name for the DB System. It does not have to be unique.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The OCID of the DB System.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Specifies if the DB System read endpoint is enabled or not.
        /// </summary>
        public readonly bool IsEnabled;
        /// <summary>
        /// Additional information about the current lifecycleState.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// Parameters detailing how to provision the initial data of the DB System.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMysqlDbSystemChannelSourceResult> Sources;
        /// <summary>
        /// The current state of the DB System.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// Details about the Channel target.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMysqlDbSystemChannelTargetResult> Targets;
        /// <summary>
        /// The date and time the DB System was created.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time the DB System was last updated.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetMysqlDbSystemChannelResult(
            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            bool isEnabled,

            string lifecycleDetails,

            ImmutableArray<Outputs.GetMysqlDbSystemChannelSourceResult> sources,

            string state,

            ImmutableDictionary<string, string> systemTags,

            ImmutableArray<Outputs.GetMysqlDbSystemChannelTargetResult> targets,

            string timeCreated,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            IsEnabled = isEnabled;
            LifecycleDetails = lifecycleDetails;
            Sources = sources;
            State = state;
            SystemTags = systemTags;
            Targets = targets;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
