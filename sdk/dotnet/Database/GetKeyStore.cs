// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetKeyStore
    {
        /// <summary>
        /// This data source provides details about a specific Key Store resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets information about the specified key store.
        /// 
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
        ///     var testKeyStore = Oci.Database.GetKeyStore.Invoke(new()
        ///     {
        ///         KeyStoreId = testKeyStoreOciDatabaseKeyStore.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetKeyStoreResult> InvokeAsync(GetKeyStoreArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetKeyStoreResult>("oci:Database/getKeyStore:getKeyStore", args ?? new GetKeyStoreArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Key Store resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets information about the specified key store.
        /// 
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
        ///     var testKeyStore = Oci.Database.GetKeyStore.Invoke(new()
        ///     {
        ///         KeyStoreId = testKeyStoreOciDatabaseKeyStore.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetKeyStoreResult> Invoke(GetKeyStoreInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetKeyStoreResult>("oci:Database/getKeyStore:getKeyStore", args ?? new GetKeyStoreInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Key Store resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets information about the specified key store.
        /// 
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
        ///     var testKeyStore = Oci.Database.GetKeyStore.Invoke(new()
        ///     {
        ///         KeyStoreId = testKeyStoreOciDatabaseKeyStore.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetKeyStoreResult> Invoke(GetKeyStoreInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetKeyStoreResult>("oci:Database/getKeyStore:getKeyStore", args ?? new GetKeyStoreInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetKeyStoreArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the key store.
        /// </summary>
        [Input("keyStoreId", required: true)]
        public string KeyStoreId { get; set; } = null!;

        public GetKeyStoreArgs()
        {
        }
        public static new GetKeyStoreArgs Empty => new GetKeyStoreArgs();
    }

    public sealed class GetKeyStoreInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the key store.
        /// </summary>
        [Input("keyStoreId", required: true)]
        public Input<string> KeyStoreId { get; set; } = null!;

        public GetKeyStoreInvokeArgs()
        {
        }
        public static new GetKeyStoreInvokeArgs Empty => new GetKeyStoreInvokeArgs();
    }


    [OutputType]
    public sealed class GetKeyStoreResult
    {
        /// <summary>
        /// List of databases associated with the key store.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetKeyStoreAssociatedDatabaseResult> AssociatedDatabases;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        public readonly int ConfirmDetailsTrigger;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// The user-friendly name for the key store. The name does not need to be unique.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the key store.
        /// </summary>
        public readonly string Id;
        public readonly string KeyStoreId;
        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The current state of the key store.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The date and time that the key store was created.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// Key store type details.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetKeyStoreTypeDetailResult> TypeDetails;

        [OutputConstructor]
        private GetKeyStoreResult(
            ImmutableArray<Outputs.GetKeyStoreAssociatedDatabaseResult> associatedDatabases,

            string compartmentId,

            int confirmDetailsTrigger,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string keyStoreId,

            string lifecycleDetails,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            ImmutableArray<Outputs.GetKeyStoreTypeDetailResult> typeDetails)
        {
            AssociatedDatabases = associatedDatabases;
            CompartmentId = compartmentId;
            ConfirmDetailsTrigger = confirmDetailsTrigger;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            KeyStoreId = keyStoreId;
            LifecycleDetails = lifecycleDetails;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TypeDetails = typeDetails;
        }
    }
}
