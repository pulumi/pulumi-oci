// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard.Inputs
{

    public sealed class DetectorRecipeEffectiveDetectorRuleArgs : global::Pulumi.ResourceArgs
    {
        [Input("candidateResponderRules")]
        private InputList<Inputs.DetectorRecipeEffectiveDetectorRuleCandidateResponderRuleArgs>? _candidateResponderRules;

        /// <summary>
        /// List of CandidateResponderRule related to this rule
        /// </summary>
        public InputList<Inputs.DetectorRecipeEffectiveDetectorRuleCandidateResponderRuleArgs> CandidateResponderRules
        {
            get => _candidateResponderRules ?? (_candidateResponderRules = new InputList<Inputs.DetectorRecipeEffectiveDetectorRuleCandidateResponderRuleArgs>());
            set => _candidateResponderRules = value;
        }

        /// <summary>
        /// (Updatable) Detector recipe description.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        [Input("details")]
        private InputList<Inputs.DetectorRecipeEffectiveDetectorRuleDetailArgs>? _details;

        /// <summary>
        /// (Updatable) Details of a Detector Rule to be overriden in Detector Recipe
        /// </summary>
        public InputList<Inputs.DetectorRecipeEffectiveDetectorRuleDetailArgs> Details
        {
            get => _details ?? (_details = new InputList<Inputs.DetectorRecipeEffectiveDetectorRuleDetailArgs>());
            set => _details = value;
        }

        /// <summary>
        /// detector for the rule
        /// </summary>
        [Input("detector")]
        public Input<string>? Detector { get; set; }

        /// <summary>
        /// (Updatable) DetectorRecipeRule Identifier
        /// </summary>
        [Input("detectorRuleId")]
        public Input<string>? DetectorRuleId { get; set; }

        /// <summary>
        /// (Updatable) Detector recipe display name.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        [Input("managedListTypes")]
        private InputList<string>? _managedListTypes;

        /// <summary>
        /// List of cloudguard managed list types related to this rule
        /// </summary>
        public InputList<string> ManagedListTypes
        {
            get => _managedListTypes ?? (_managedListTypes = new InputList<string>());
            set => _managedListTypes = value;
        }

        /// <summary>
        /// Recommendation for DetectorRecipeDetectorRule
        /// </summary>
        [Input("recommendation")]
        public Input<string>? Recommendation { get; set; }

        /// <summary>
        /// resource type of the configuration to which the rule is applied
        /// </summary>
        [Input("resourceType")]
        public Input<string>? ResourceType { get; set; }

        /// <summary>
        /// service type of the configuration to which the rule is applied
        /// </summary>
        [Input("serviceType")]
        public Input<string>? ServiceType { get; set; }

        /// <summary>
        /// The current state of the resource.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The date and time the detector recipe was created. Format defined by RFC3339.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The date and time the detector recipe was updated. Format defined by RFC3339.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public DetectorRecipeEffectiveDetectorRuleArgs()
        {
        }
        public static new DetectorRecipeEffectiveDetectorRuleArgs Empty => new DetectorRecipeEffectiveDetectorRuleArgs();
    }
}