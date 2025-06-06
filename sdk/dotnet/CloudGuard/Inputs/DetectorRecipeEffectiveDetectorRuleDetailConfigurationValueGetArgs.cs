// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard.Inputs
{

    public sealed class DetectorRecipeEffectiveDetectorRuleDetailConfigurationValueGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Configuration list item type (CUSTOM or MANAGED)
        /// </summary>
        [Input("listType")]
        public Input<string>? ListType { get; set; }

        /// <summary>
        /// Type of content in the managed list
        /// </summary>
        [Input("managedListType")]
        public Input<string>? ManagedListType { get; set; }

        /// <summary>
        /// Configuration value
        /// </summary>
        [Input("value")]
        public Input<string>? Value { get; set; }

        public DetectorRecipeEffectiveDetectorRuleDetailConfigurationValueGetArgs()
        {
        }
        public static new DetectorRecipeEffectiveDetectorRuleDetailConfigurationValueGetArgs Empty => new DetectorRecipeEffectiveDetectorRuleDetailConfigurationValueGetArgs();
    }
}
