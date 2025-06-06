// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard.Inputs
{

    public sealed class TargetTargetResponderRecipeResponderRuleGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Compartment OCID where the resource is created
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// The target description.
        /// 
        /// Avoid entering confidential information.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) Parameters to update details for a responder rule for a target responder recipe. TargetResponderRuleDetails contains all configurations associated with the ResponderRule, whereas UpdateTargetResponderRecipeResponderRuleDetails refers to the details that are to be updated for ResponderRule.
        /// </summary>
        [Input("details", required: true)]
        public Input<Inputs.TargetTargetResponderRecipeResponderRuleDetailsGetArgs> Details { get; set; } = null!;

        /// <summary>
        /// (Updatable) Display name for the target.
        /// 
        /// Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        [Input("policies")]
        private InputList<string>? _policies;

        /// <summary>
        /// List of policies
        /// </summary>
        public InputList<string> Policies
        {
            get => _policies ?? (_policies = new InputList<string>());
            set => _policies = value;
        }

        /// <summary>
        /// (Updatable) Unique identifier for target detector recipe
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("responderRuleId", required: true)]
        public Input<string> ResponderRuleId { get; set; } = null!;

        /// <summary>
        /// (Updatable) The enablement state of the detector rule
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        [Input("supportedModes")]
        private InputList<string>? _supportedModes;

        /// <summary>
        /// Supported execution modes for the responder rule
        /// </summary>
        public InputList<string> SupportedModes
        {
            get => _supportedModes ?? (_supportedModes = new InputList<string>());
            set => _supportedModes = value;
        }

        /// <summary>
        /// The date and time the target was created. Format defined by RFC3339.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The date and time the target was last updated. Format defined by RFC3339.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        /// <summary>
        /// Type of responder
        /// </summary>
        [Input("type")]
        public Input<string>? Type { get; set; }

        public TargetTargetResponderRecipeResponderRuleGetArgs()
        {
        }
        public static new TargetTargetResponderRecipeResponderRuleGetArgs Empty => new TargetTargetResponderRecipeResponderRuleGetArgs();
    }
}
