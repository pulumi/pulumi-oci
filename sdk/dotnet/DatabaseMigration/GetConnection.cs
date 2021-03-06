// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseMigration
{
    public static class GetConnection
    {
        /// <summary>
        /// This data source provides details about a specific Connection resource in Oracle Cloud Infrastructure Database Migration service.
        /// 
        /// Display Database Connection details.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testConnection = Output.Create(Oci.DatabaseMigration.GetConnection.InvokeAsync(new Oci.DatabaseMigration.GetConnectionArgs
        ///         {
        ///             ConnectionId = oci_database_migration_connection.Test_connection.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetConnectionResult> InvokeAsync(GetConnectionArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetConnectionResult>("oci:DatabaseMigration/getConnection:getConnection", args ?? new GetConnectionArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Connection resource in Oracle Cloud Infrastructure Database Migration service.
        /// 
        /// Display Database Connection details.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testConnection = Output.Create(Oci.DatabaseMigration.GetConnection.InvokeAsync(new Oci.DatabaseMigration.GetConnectionArgs
        ///         {
        ///             ConnectionId = oci_database_migration_connection.Test_connection.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetConnectionResult> Invoke(GetConnectionInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetConnectionResult>("oci:DatabaseMigration/getConnection:getConnection", args ?? new GetConnectionInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetConnectionArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the database connection
        /// </summary>
        [Input("connectionId", required: true)]
        public string ConnectionId { get; set; } = null!;

        public GetConnectionArgs()
        {
        }
    }

    public sealed class GetConnectionInvokeArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the database connection
        /// </summary>
        [Input("connectionId", required: true)]
        public Input<string> ConnectionId { get; set; } = null!;

        public GetConnectionInvokeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetConnectionResult
    {
        /// <summary>
        /// Database Administrator Credentials details.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetConnectionAdminCredentialResult> AdminCredentials;
        /// <summary>
        /// This name is the distinguished name used while creating the certificate on target database.
        /// </summary>
        public readonly string CertificateTdn;
        /// <summary>
        /// OCID of the compartment where the secret containing the credentials will be created.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Connect Descriptor details.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetConnectionConnectDescriptorResult> ConnectDescriptors;
        public readonly string ConnectionId;
        /// <summary>
        /// OCID of the Secret in the Oracle Cloud Infrastructure vault containing the Database Connection credentials.
        /// </summary>
        public readonly string CredentialsSecretId;
        /// <summary>
        /// The OCID of the cloud database.
        /// </summary>
        public readonly string DatabaseId;
        /// <summary>
        /// Database connection type.
        /// </summary>
        public readonly string DatabaseType;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// Database Connection display name identifier.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a previously created Private Endpoint.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// Oracle Cloud Infrastructure Private Endpoint configuration details.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetConnectionPrivateEndpointResult> PrivateEndpoints;
        /// <summary>
        /// Details of the SSH key that will be used.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetConnectionSshDetailResult> SshDetails;
        /// <summary>
        /// The current state of the Connection resource.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> SystemTags;
        /// <summary>
        /// The time the Connection resource was created. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time of the last Connection resource details update. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeUpdated;
        public readonly string TlsKeystore;
        public readonly string TlsWallet;
        /// <summary>
        /// Oracle Cloud Infrastructure Vault details to store migration and connection credentials secrets
        /// </summary>
        public readonly ImmutableArray<Outputs.GetConnectionVaultDetailResult> VaultDetails;

        [OutputConstructor]
        private GetConnectionResult(
            ImmutableArray<Outputs.GetConnectionAdminCredentialResult> adminCredentials,

            string certificateTdn,

            string compartmentId,

            ImmutableArray<Outputs.GetConnectionConnectDescriptorResult> connectDescriptors,

            string connectionId,

            string credentialsSecretId,

            string databaseId,

            string databaseType,

            ImmutableDictionary<string, object> definedTags,

            string displayName,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string lifecycleDetails,

            ImmutableArray<Outputs.GetConnectionPrivateEndpointResult> privateEndpoints,

            ImmutableArray<Outputs.GetConnectionSshDetailResult> sshDetails,

            string state,

            ImmutableDictionary<string, object> systemTags,

            string timeCreated,

            string timeUpdated,

            string tlsKeystore,

            string tlsWallet,

            ImmutableArray<Outputs.GetConnectionVaultDetailResult> vaultDetails)
        {
            AdminCredentials = adminCredentials;
            CertificateTdn = certificateTdn;
            CompartmentId = compartmentId;
            ConnectDescriptors = connectDescriptors;
            ConnectionId = connectionId;
            CredentialsSecretId = credentialsSecretId;
            DatabaseId = databaseId;
            DatabaseType = databaseType;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            PrivateEndpoints = privateEndpoints;
            SshDetails = sshDetails;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            TlsKeystore = tlsKeystore;
            TlsWallet = tlsWallet;
            VaultDetails = vaultDetails;
        }
    }
}
