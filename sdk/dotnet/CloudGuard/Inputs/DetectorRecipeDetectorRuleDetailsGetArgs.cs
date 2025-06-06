// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard.Inputs
{

    public sealed class DetectorRecipeDetectorRuleDetailsGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The base condition resource.
        /// </summary>
        [Input("condition")]
        public Input<string>? Condition { get; set; }

        [Input("configurations")]
        private InputList<Inputs.DetectorRecipeDetectorRuleDetailsConfigurationGetArgs>? _configurations;

        /// <summary>
        /// (Updatable) List of detector rule configurations
        /// </summary>
        public InputList<Inputs.DetectorRecipeDetectorRuleDetailsConfigurationGetArgs> Configurations
        {
            get => _configurations ?? (_configurations = new InputList<Inputs.DetectorRecipeDetectorRuleDetailsConfigurationGetArgs>());
            set => _configurations = value;
        }

        /// <summary>
        /// (Updatable) The unique identifier of the attached data source
        /// </summary>
        [Input("dataSourceId")]
        public Input<string>? DataSourceId { get; set; }

        /// <summary>
        /// (Updatable) Description for the detector rule
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        [Input("entitiesMappings")]
        private InputList<Inputs.DetectorRecipeDetectorRuleDetailsEntitiesMappingGetArgs>? _entitiesMappings;

        /// <summary>
        /// (Updatable) Data source entities mapping for a detector rule
        /// </summary>
        public InputList<Inputs.DetectorRecipeDetectorRuleDetailsEntitiesMappingGetArgs> EntitiesMappings
        {
            get => _entitiesMappings ?? (_entitiesMappings = new InputList<Inputs.DetectorRecipeDetectorRuleDetailsEntitiesMappingGetArgs>());
            set => _entitiesMappings = value;
        }

        /// <summary>
        /// Can the rule be configured?
        /// </summary>
        [Input("isConfigurationAllowed")]
        public Input<bool>? IsConfigurationAllowed { get; set; }

        /// <summary>
        /// (Updatable) Enablement status of the detector rule
        /// </summary>
        [Input("isEnabled", required: true)]
        public Input<bool> IsEnabled { get; set; } = null!;

        [Input("labels")]
        private InputList<string>? _labels;

        /// <summary>
        /// (Updatable) User-defined labels for a detector rule
        /// </summary>
        public InputList<string> Labels
        {
            get => _labels ?? (_labels = new InputList<string>());
            set => _labels = value;
        }

        /// <summary>
        /// (Updatable) Recommendation for the detector rule
        /// </summary>
        [Input("recommendation")]
        public Input<string>? Recommendation { get; set; }

        /// <summary>
        /// (Updatable) The risk level of the detector rule
        /// </summary>
        [Input("riskLevel", required: true)]
        public Input<string> RiskLevel { get; set; } = null!;

        public DetectorRecipeDetectorRuleDetailsGetArgs()
        {
        }
        public static new DetectorRecipeDetectorRuleDetailsGetArgs Empty => new DetectorRecipeDetectorRuleDetailsGetArgs();
    }
}
