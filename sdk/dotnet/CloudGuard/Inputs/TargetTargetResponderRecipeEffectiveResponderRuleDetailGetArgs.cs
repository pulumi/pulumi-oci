// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard.Inputs
{

    public sealed class TargetTargetResponderRecipeEffectiveResponderRuleDetailGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Base condition object
        /// </summary>
        [Input("condition")]
        public Input<string>? Condition { get; set; }

        [Input("configurations")]
        private InputList<Inputs.TargetTargetResponderRecipeEffectiveResponderRuleDetailConfigurationGetArgs>? _configurations;

        /// <summary>
        /// (Updatable) Configurations associated with the ResponderRule
        /// </summary>
        public InputList<Inputs.TargetTargetResponderRecipeEffectiveResponderRuleDetailConfigurationGetArgs> Configurations
        {
            get => _configurations ?? (_configurations = new InputList<Inputs.TargetTargetResponderRecipeEffectiveResponderRuleDetailConfigurationGetArgs>());
            set => _configurations = value;
        }

        /// <summary>
        /// Identifies state for ResponderRule
        /// </summary>
        [Input("isEnabled")]
        public Input<bool>? IsEnabled { get; set; }

        /// <summary>
        /// (Updatable) Execution Mode for ResponderRule
        /// </summary>
        [Input("mode")]
        public Input<string>? Mode { get; set; }

        public TargetTargetResponderRecipeEffectiveResponderRuleDetailGetArgs()
        {
        }
        public static new TargetTargetResponderRecipeEffectiveResponderRuleDetailGetArgs Empty => new TargetTargetResponderRecipeEffectiveResponderRuleDetailGetArgs();
    }
}