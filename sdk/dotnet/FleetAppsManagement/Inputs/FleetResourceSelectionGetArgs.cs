// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FleetAppsManagement.Inputs
{

    public sealed class FleetResourceSelectionGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Type of resource selection in a Fleet. Select resources manually or select resources based on rules.
        /// </summary>
        [Input("resourceSelectionType", required: true)]
        public Input<string> ResourceSelectionType { get; set; } = null!;

        /// <summary>
        /// (Updatable) Rule Selection Criteria for DYNAMIC resource selection for a GENERIC fleet. Rules define what resources are members of this fleet. All resources that meet the criteria are added automatically.
        /// </summary>
        [Input("ruleSelectionCriteria")]
        public Input<Inputs.FleetResourceSelectionRuleSelectionCriteriaGetArgs>? RuleSelectionCriteria { get; set; }

        public FleetResourceSelectionGetArgs()
        {
        }
        public static new FleetResourceSelectionGetArgs Empty => new FleetResourceSelectionGetArgs();
    }
}
