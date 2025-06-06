// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard.Inputs
{

    public sealed class TargetTargetResponderRecipeEffectiveResponderRuleDetailArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The base condition resource.
        /// </summary>
        [Input("condition")]
        public Input<string>? Condition { get; set; }

        [Input("configurations")]
        private InputList<Inputs.TargetTargetResponderRecipeEffectiveResponderRuleDetailConfigurationArgs>? _configurations;

        /// <summary>
        /// List of responder rule configurations
        /// </summary>
        public InputList<Inputs.TargetTargetResponderRecipeEffectiveResponderRuleDetailConfigurationArgs> Configurations
        {
            get => _configurations ?? (_configurations = new InputList<Inputs.TargetTargetResponderRecipeEffectiveResponderRuleDetailConfigurationArgs>());
            set => _configurations = value;
        }

        /// <summary>
        /// Enabled state for the responder rule
        /// </summary>
        [Input("isEnabled")]
        public Input<bool>? IsEnabled { get; set; }

        /// <summary>
        /// Execution mode for the responder rule
        /// </summary>
        [Input("mode")]
        public Input<string>? Mode { get; set; }

        public TargetTargetResponderRecipeEffectiveResponderRuleDetailArgs()
        {
        }
        public static new TargetTargetResponderRecipeEffectiveResponderRuleDetailArgs Empty => new TargetTargetResponderRecipeEffectiveResponderRuleDetailArgs();
    }
}
