// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Outputs
{

    [OutputType]
    public sealed class GetConnectionsConnectionCollectionItemResult
    {
        /// <summary>
        /// The OCID of personal access token saved in secret store.
        /// </summary>
        public readonly string AccessToken;
        /// <summary>
        /// OCID of personal Bitbucket Cloud AppPassword saved in secret store
        /// </summary>
        public readonly string AppPassword;
        /// <summary>
        /// The Base URL of the hosted BitbucketServer/Visual Builder Studio server.
        /// </summary>
        public readonly string BaseUrl;
        /// <summary>
        /// The OCID of the compartment in which to list resources.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// A filter to return only resources that match the given connection type.
        /// </summary>
        public readonly string ConnectionType;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// Optional description about the connection.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// Unique identifier or OCID for listing a single resource by ID.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The result of validating the credentials of a connection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetConnectionsConnectionCollectionItemLastConnectionValidationResultResult> LastConnectionValidationResults;
        /// <summary>
        /// unique project identifier
        /// </summary>
        public readonly string ProjectId;
        /// <summary>
        /// A filter to return only connections that matches the given lifecycle state.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The time the connection was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time the connection was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// TLS configuration used by build service to verify TLS connection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetConnectionsConnectionCollectionItemTlsVerifyConfigResult> TlsVerifyConfigs;
        /// <summary>
        /// Public Bitbucket Cloud Username in plain text
        /// </summary>
        public readonly string Username;

        [OutputConstructor]
        private GetConnectionsConnectionCollectionItemResult(
            string accessToken,

            string appPassword,

            string baseUrl,

            string compartmentId,

            string connectionType,

            ImmutableDictionary<string, string> definedTags,

            string description,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            ImmutableArray<Outputs.GetConnectionsConnectionCollectionItemLastConnectionValidationResultResult> lastConnectionValidationResults,

            string projectId,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated,

            ImmutableArray<Outputs.GetConnectionsConnectionCollectionItemTlsVerifyConfigResult> tlsVerifyConfigs,

            string username)
        {
            AccessToken = accessToken;
            AppPassword = appPassword;
            BaseUrl = baseUrl;
            CompartmentId = compartmentId;
            ConnectionType = connectionType;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            LastConnectionValidationResults = lastConnectionValidationResults;
            ProjectId = projectId;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            TlsVerifyConfigs = tlsVerifyConfigs;
            Username = username;
        }
    }
}
