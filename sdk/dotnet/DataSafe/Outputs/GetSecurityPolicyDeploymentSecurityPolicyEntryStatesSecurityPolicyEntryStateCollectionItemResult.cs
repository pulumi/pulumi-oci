// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe.Outputs
{

    [OutputType]
    public sealed class GetSecurityPolicyDeploymentSecurityPolicyEntryStatesSecurityPolicyEntryStateCollectionItemResult
    {
        /// <summary>
        /// The current state of the security policy deployment.
        /// </summary>
        public readonly string DeploymentStatus;
        /// <summary>
        /// Details specific to the security policy entry.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSecurityPolicyDeploymentSecurityPolicyEntryStatesSecurityPolicyEntryStateCollectionItemEntryDetailResult> EntryDetails;
        /// <summary>
        /// Unique id of the security policy entry state.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The OCID of the security policy deployment resource.
        /// </summary>
        public readonly string SecurityPolicyDeploymentId;
        /// <summary>
        /// An optional filter to return only resources that match the specified security policy entry OCID.
        /// </summary>
        public readonly string SecurityPolicyEntryId;

        [OutputConstructor]
        private GetSecurityPolicyDeploymentSecurityPolicyEntryStatesSecurityPolicyEntryStateCollectionItemResult(
            string deploymentStatus,

            ImmutableArray<Outputs.GetSecurityPolicyDeploymentSecurityPolicyEntryStatesSecurityPolicyEntryStateCollectionItemEntryDetailResult> entryDetails,

            string id,

            string securityPolicyDeploymentId,

            string securityPolicyEntryId)
        {
            DeploymentStatus = deploymentStatus;
            EntryDetails = entryDetails;
            Id = id;
            SecurityPolicyDeploymentId = securityPolicyDeploymentId;
            SecurityPolicyEntryId = securityPolicyEntryId;
        }
    }
}
