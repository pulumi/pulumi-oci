// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard.Outputs
{

    [OutputType]
    public sealed class GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleCandidateResponderRuleResult
    {
        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Ocid for detector recipe
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Preferred state
        /// </summary>
        public readonly bool IsPreferred;

        [OutputConstructor]
        private GetDetectorRecipesDetectorRecipeCollectionItemDetectorRuleCandidateResponderRuleResult(
            string displayName,

            string id,

            bool isPreferred)
        {
            DisplayName = displayName;
            Id = id;
            IsPreferred = isPreferred;
        }
    }
}