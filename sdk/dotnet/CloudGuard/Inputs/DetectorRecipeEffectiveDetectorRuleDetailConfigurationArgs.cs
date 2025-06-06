// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard.Inputs
{

    public sealed class DetectorRecipeEffectiveDetectorRuleDetailConfigurationArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Unique identifier of the configuration
        /// </summary>
        [Input("configKey")]
        public Input<string>? ConfigKey { get; set; }

        /// <summary>
        /// Configuration data type
        /// </summary>
        [Input("dataType")]
        public Input<string>? DataType { get; set; }

        /// <summary>
        /// Configuration name
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// Configuration value
        /// </summary>
        [Input("value")]
        public Input<string>? Value { get; set; }

        [Input("values")]
        private InputList<Inputs.DetectorRecipeEffectiveDetectorRuleDetailConfigurationValueArgs>? _values;

        /// <summary>
        /// List of configuration values
        /// </summary>
        public InputList<Inputs.DetectorRecipeEffectiveDetectorRuleDetailConfigurationValueArgs> Values
        {
            get => _values ?? (_values = new InputList<Inputs.DetectorRecipeEffectiveDetectorRuleDetailConfigurationValueArgs>());
            set => _values = value;
        }

        public DetectorRecipeEffectiveDetectorRuleDetailConfigurationArgs()
        {
        }
        public static new DetectorRecipeEffectiveDetectorRuleDetailConfigurationArgs Empty => new DetectorRecipeEffectiveDetectorRuleDetailConfigurationArgs();
    }
}
