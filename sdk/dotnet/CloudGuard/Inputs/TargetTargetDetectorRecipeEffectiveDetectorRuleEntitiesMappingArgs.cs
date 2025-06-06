// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard.Inputs
{

    public sealed class TargetTargetDetectorRecipeEffectiveDetectorRuleEntitiesMappingArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Display name for the target.
        /// 
        /// Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// Type of entity
        /// </summary>
        [Input("entityType")]
        public Input<string>? EntityType { get; set; }

        /// <summary>
        /// The entity value mapped to a data source query
        /// </summary>
        [Input("queryField")]
        public Input<string>? QueryField { get; set; }

        public TargetTargetDetectorRecipeEffectiveDetectorRuleEntitiesMappingArgs()
        {
        }
        public static new TargetTargetDetectorRecipeEffectiveDetectorRuleEntitiesMappingArgs Empty => new TargetTargetDetectorRecipeEffectiveDetectorRuleEntitiesMappingArgs();
    }
}
