// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement
{
    /// <summary>
    /// This resource provides the Managed Databases Reset Database Parameter resource in Oracle Cloud Infrastructure Database Management service.
    /// 
    /// Resets database parameter values to their default or startup values.
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using System.Collections.Generic;
    /// using System.Linq;
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// return await Deployment.RunAsync(() =&gt; 
    /// {
    ///     var testManagedDatabasesResetDatabaseParameter = new Oci.DatabaseManagement.ManagedDatabasesResetDatabaseParameter("test_managed_databases_reset_database_parameter", new()
    ///     {
    ///         ManagedDatabaseId = testManagedDatabase.Id,
    ///         Parameters = managedDatabasesResetDatabaseParameterParameters,
    ///         Scope = managedDatabasesResetDatabaseParameterScope,
    ///         Credentials = new Oci.DatabaseManagement.Inputs.ManagedDatabasesResetDatabaseParameterCredentialsArgs
    ///         {
    ///             Password = managedDatabasesResetDatabaseParameterCredentialsPassword,
    ///             Role = managedDatabasesResetDatabaseParameterCredentialsRole,
    ///             SecretId = testSecret.Id,
    ///             UserName = testUser.Name,
    ///         },
    ///         DatabaseCredential = new Oci.DatabaseManagement.Inputs.ManagedDatabasesResetDatabaseParameterDatabaseCredentialArgs
    ///         {
    ///             CredentialType = managedDatabasesResetDatabaseParameterDatabaseCredentialCredentialType,
    ///             NamedCredentialId = testNamedCredential.Id,
    ///             Password = managedDatabasesResetDatabaseParameterDatabaseCredentialPassword,
    ///             PasswordSecretId = testSecret.Id,
    ///             Role = managedDatabasesResetDatabaseParameterDatabaseCredentialRole,
    ///             Username = managedDatabasesResetDatabaseParameterDatabaseCredentialUsername,
    ///         },
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// Import is not supported for this resource.
    /// </summary>
    [OciResourceType("oci:DatabaseManagement/managedDatabasesResetDatabaseParameter:ManagedDatabasesResetDatabaseParameter")]
    public partial class ManagedDatabasesResetDatabaseParameter : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The database credentials used to perform management activity. Provide one of the following attribute set. (userName, password, role) OR (userName, secretId, role) OR (namedCredentialId)
        /// </summary>
        [Output("credentials")]
        public Output<Outputs.ManagedDatabasesResetDatabaseParameterCredentials> Credentials { get; private set; } = null!;

        /// <summary>
        /// The credential to connect to the database to perform tablespace administration tasks.
        /// </summary>
        [Output("databaseCredential")]
        public Output<Outputs.ManagedDatabasesResetDatabaseParameterDatabaseCredential> DatabaseCredential { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
        /// </summary>
        [Output("managedDatabaseId")]
        public Output<string> ManagedDatabaseId { get; private set; } = null!;

        /// <summary>
        /// A list of database parameter names.
        /// </summary>
        [Output("parameters")]
        public Output<ImmutableArray<string>> Parameters { get; private set; } = null!;

        /// <summary>
        /// The clause used to specify when the parameter change takes effect.
        /// 
        /// Use `MEMORY` to make the change in memory and ensure that it takes effect immediately. Use `SPFILE` to make the change in the server parameter file. The change takes effect when the database is next shut down and started up again. Use `BOTH` to make the change in memory and in the server parameter file. The change takes effect immediately and persists after the database is shut down and started up again.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("scope")]
        public Output<string> Scope { get; private set; } = null!;


        /// <summary>
        /// Create a ManagedDatabasesResetDatabaseParameter resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public ManagedDatabasesResetDatabaseParameter(string name, ManagedDatabasesResetDatabaseParameterArgs args, CustomResourceOptions? options = null)
            : base("oci:DatabaseManagement/managedDatabasesResetDatabaseParameter:ManagedDatabasesResetDatabaseParameter", name, args ?? new ManagedDatabasesResetDatabaseParameterArgs(), MakeResourceOptions(options, ""))
        {
        }

        private ManagedDatabasesResetDatabaseParameter(string name, Input<string> id, ManagedDatabasesResetDatabaseParameterState? state = null, CustomResourceOptions? options = null)
            : base("oci:DatabaseManagement/managedDatabasesResetDatabaseParameter:ManagedDatabasesResetDatabaseParameter", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing ManagedDatabasesResetDatabaseParameter resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static ManagedDatabasesResetDatabaseParameter Get(string name, Input<string> id, ManagedDatabasesResetDatabaseParameterState? state = null, CustomResourceOptions? options = null)
        {
            return new ManagedDatabasesResetDatabaseParameter(name, id, state, options);
        }
    }

    public sealed class ManagedDatabasesResetDatabaseParameterArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The database credentials used to perform management activity. Provide one of the following attribute set. (userName, password, role) OR (userName, secretId, role) OR (namedCredentialId)
        /// </summary>
        [Input("credentials")]
        public Input<Inputs.ManagedDatabasesResetDatabaseParameterCredentialsArgs>? Credentials { get; set; }

        /// <summary>
        /// The credential to connect to the database to perform tablespace administration tasks.
        /// </summary>
        [Input("databaseCredential")]
        public Input<Inputs.ManagedDatabasesResetDatabaseParameterDatabaseCredentialArgs>? DatabaseCredential { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
        /// </summary>
        [Input("managedDatabaseId", required: true)]
        public Input<string> ManagedDatabaseId { get; set; } = null!;

        [Input("parameters", required: true)]
        private InputList<string>? _parameters;

        /// <summary>
        /// A list of database parameter names.
        /// </summary>
        public InputList<string> Parameters
        {
            get => _parameters ?? (_parameters = new InputList<string>());
            set => _parameters = value;
        }

        /// <summary>
        /// The clause used to specify when the parameter change takes effect.
        /// 
        /// Use `MEMORY` to make the change in memory and ensure that it takes effect immediately. Use `SPFILE` to make the change in the server parameter file. The change takes effect when the database is next shut down and started up again. Use `BOTH` to make the change in memory and in the server parameter file. The change takes effect immediately and persists after the database is shut down and started up again.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("scope", required: true)]
        public Input<string> Scope { get; set; } = null!;

        public ManagedDatabasesResetDatabaseParameterArgs()
        {
        }
        public static new ManagedDatabasesResetDatabaseParameterArgs Empty => new ManagedDatabasesResetDatabaseParameterArgs();
    }

    public sealed class ManagedDatabasesResetDatabaseParameterState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The database credentials used to perform management activity. Provide one of the following attribute set. (userName, password, role) OR (userName, secretId, role) OR (namedCredentialId)
        /// </summary>
        [Input("credentials")]
        public Input<Inputs.ManagedDatabasesResetDatabaseParameterCredentialsGetArgs>? Credentials { get; set; }

        /// <summary>
        /// The credential to connect to the database to perform tablespace administration tasks.
        /// </summary>
        [Input("databaseCredential")]
        public Input<Inputs.ManagedDatabasesResetDatabaseParameterDatabaseCredentialGetArgs>? DatabaseCredential { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
        /// </summary>
        [Input("managedDatabaseId")]
        public Input<string>? ManagedDatabaseId { get; set; }

        [Input("parameters")]
        private InputList<string>? _parameters;

        /// <summary>
        /// A list of database parameter names.
        /// </summary>
        public InputList<string> Parameters
        {
            get => _parameters ?? (_parameters = new InputList<string>());
            set => _parameters = value;
        }

        /// <summary>
        /// The clause used to specify when the parameter change takes effect.
        /// 
        /// Use `MEMORY` to make the change in memory and ensure that it takes effect immediately. Use `SPFILE` to make the change in the server parameter file. The change takes effect when the database is next shut down and started up again. Use `BOTH` to make the change in memory and in the server parameter file. The change takes effect immediately and persists after the database is shut down and started up again.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("scope")]
        public Input<string>? Scope { get; set; }

        public ManagedDatabasesResetDatabaseParameterState()
        {
        }
        public static new ManagedDatabasesResetDatabaseParameterState Empty => new ManagedDatabasesResetDatabaseParameterState();
    }
}
