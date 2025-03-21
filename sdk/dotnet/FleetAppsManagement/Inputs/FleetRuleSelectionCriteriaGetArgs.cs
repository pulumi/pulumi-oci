// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FleetAppsManagement.Inputs
{

    public sealed class FleetRuleSelectionCriteriaGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Match condition for the rule selection. Include resources that match all rules or any of the rules.
        /// </summary>
        [Input("matchCondition", required: true)]
        public Input<string> MatchCondition { get; set; } = null!;

        [Input("rules", required: true)]
        private InputList<Inputs.FleetRuleSelectionCriteriaRuleGetArgs>? _rules;

        /// <summary>
        /// (Updatable) Rules.
        /// </summary>
        public InputList<Inputs.FleetRuleSelectionCriteriaRuleGetArgs> Rules
        {
            get => _rules ?? (_rules = new InputList<Inputs.FleetRuleSelectionCriteriaRuleGetArgs>());
            set => _rules = value;
        }

        public FleetRuleSelectionCriteriaGetArgs()
        {
        }
        public static new FleetRuleSelectionCriteriaGetArgs Empty => new FleetRuleSelectionCriteriaGetArgs();
    }
}
