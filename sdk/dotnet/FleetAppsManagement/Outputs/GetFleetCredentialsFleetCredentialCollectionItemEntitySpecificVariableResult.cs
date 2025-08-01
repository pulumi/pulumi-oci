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
    public sealed class GetFleetCredentialsFleetCredentialCollectionItemEntitySpecificVariableResult
    {
        /// <summary>
        /// Name of the variable.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The value corresponding to the credential.
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private GetFleetCredentialsFleetCredentialCollectionItemEntitySpecificVariableResult(
            string name,

            string value)
        {
            Name = name;
            Value = value;
        }
    }
}
