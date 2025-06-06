// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard.Inputs
{

    public sealed class TargetTargetDetectorRecipeDetectorRuleGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The ID of the attached data source
        /// </summary>
        [Input("dataSourceId")]
        public Input<string>? DataSourceId { get; set; }

        /// <summary>
        /// The target description.
        /// 
        /// Avoid entering confidential information.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) Parameters to update detector rule configuration details in a detector recipe attached to a target.
        /// </summary>
        [Input("details", required: true)]
        public Input<Inputs.TargetTargetDetectorRecipeDetectorRuleDetailsGetArgs> Details { get; set; } = null!;

        /// <summary>
        /// Detector type for the rule
        /// </summary>
        [Input("detector")]
        public Input<string>? Detector { get; set; }

        /// <summary>
        /// (Updatable) Unique identifier for the detector rule
        /// </summary>
        [Input("detectorRuleId", required: true)]
        public Input<string> DetectorRuleId { get; set; } = null!;

        /// <summary>
        /// (Updatable) Display name for the target.
        /// 
        /// Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("entitiesMappings")]
        private InputList<Inputs.TargetTargetDetectorRecipeDetectorRuleEntitiesMappingGetArgs>? _entitiesMappings;

        /// <summary>
        /// Data source entities mapping for a detector rule
        /// </summary>
        public InputList<Inputs.TargetTargetDetectorRecipeDetectorRuleEntitiesMappingGetArgs> EntitiesMappings
        {
            get => _entitiesMappings ?? (_entitiesMappings = new InputList<Inputs.TargetTargetDetectorRecipeDetectorRuleEntitiesMappingGetArgs>());
            set => _entitiesMappings = value;
        }

        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        [Input("managedListTypes")]
        private InputList<string>? _managedListTypes;

        /// <summary>
        /// List of managed list types related to this rule
        /// </summary>
        public InputList<string> ManagedListTypes
        {
            get => _managedListTypes ?? (_managedListTypes = new InputList<string>());
            set => _managedListTypes = value;
        }

        /// <summary>
        /// Recommendation for TargetDetectorRecipeDetectorRule resource
        /// </summary>
        [Input("recommendation")]
        public Input<string>? Recommendation { get; set; }

        /// <summary>
        /// The type of resource which is monitored by the detector rule. For example, Instance, Database, VCN, Policy. To find the resource type for a particular rule, see [Detector Recipe Reference] (/iaas/cloud-guard/using/detect-recipes.htm#detect-recipes-reference).
        /// </summary>
        [Input("resourceType")]
        public Input<string>? ResourceType { get; set; }

        /// <summary>
        /// Service type of the configuration to which the rule is applied
        /// </summary>
        [Input("serviceType")]
        public Input<string>? ServiceType { get; set; }

        /// <summary>
        /// (Updatable) The enablement state of the detector rule
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

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

        public TargetTargetDetectorRecipeDetectorRuleGetArgs()
        {
        }
        public static new TargetTargetDetectorRecipeDetectorRuleGetArgs Empty => new TargetTargetDetectorRecipeDetectorRuleGetArgs();
    }
}
