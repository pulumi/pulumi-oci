// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FleetAppsManagement.Outputs
{

    [OutputType]
    public sealed class GetFleetCredentialEntitySpecificResult
    {
        /// <summary>
        /// At what level the credential is provided?
        /// </summary>
        public readonly string CredentialLevel;
        /// <summary>
        /// OCID of the resource associated with the target for which the credential is created.
        /// </summary>
        public readonly string ResourceId;
        /// <summary>
        /// Target name for which the credential is provided.
        /// </summary>
        public readonly string Target;
        /// <summary>
        /// List of fleet credential variables.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetFleetCredentialEntitySpecificVariableResult> Variables;

        [OutputConstructor]
        private GetFleetCredentialEntitySpecificResult(
            string credentialLevel,

            string resourceId,

            string target,

            ImmutableArray<Outputs.GetFleetCredentialEntitySpecificVariableResult> variables)
        {
            CredentialLevel = credentialLevel;
            ResourceId = resourceId;
            Target = target;
            Variables = variables;
        }
    }
}
