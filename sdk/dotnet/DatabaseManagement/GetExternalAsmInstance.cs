// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement
{
    public static class GetExternalAsmInstance
    {
        /// <summary>
        /// This data source provides details about a specific External Asm Instance resource in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets the details for the external ASM instance specified by `externalAsmInstanceId`.
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
        ///     var testExternalAsmInstance = Oci.DatabaseManagement.GetExternalAsmInstance.Invoke(new()
        ///     {
        ///         ExternalAsmInstanceId = testExternalAsmInstanceOciDatabaseManagementExternalAsmInstance.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetExternalAsmInstanceResult> InvokeAsync(GetExternalAsmInstanceArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetExternalAsmInstanceResult>("oci:DatabaseManagement/getExternalAsmInstance:getExternalAsmInstance", args ?? new GetExternalAsmInstanceArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific External Asm Instance resource in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets the details for the external ASM instance specified by `externalAsmInstanceId`.
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
        ///     var testExternalAsmInstance = Oci.DatabaseManagement.GetExternalAsmInstance.Invoke(new()
        ///     {
        ///         ExternalAsmInstanceId = testExternalAsmInstanceOciDatabaseManagementExternalAsmInstance.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetExternalAsmInstanceResult> Invoke(GetExternalAsmInstanceInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetExternalAsmInstanceResult>("oci:DatabaseManagement/getExternalAsmInstance:getExternalAsmInstance", args ?? new GetExternalAsmInstanceInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific External Asm Instance resource in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets the details for the external ASM instance specified by `externalAsmInstanceId`.
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
        ///     var testExternalAsmInstance = Oci.DatabaseManagement.GetExternalAsmInstance.Invoke(new()
        ///     {
        ///         ExternalAsmInstanceId = testExternalAsmInstanceOciDatabaseManagementExternalAsmInstance.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetExternalAsmInstanceResult> Invoke(GetExternalAsmInstanceInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetExternalAsmInstanceResult>("oci:DatabaseManagement/getExternalAsmInstance:getExternalAsmInstance", args ?? new GetExternalAsmInstanceInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetExternalAsmInstanceArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external ASM instance.
        /// </summary>
        [Input("externalAsmInstanceId", required: true)]
        public string ExternalAsmInstanceId { get; set; } = null!;

        public GetExternalAsmInstanceArgs()
        {
        }
        public static new GetExternalAsmInstanceArgs Empty => new GetExternalAsmInstanceArgs();
    }

    public sealed class GetExternalAsmInstanceInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external ASM instance.
        /// </summary>
        [Input("externalAsmInstanceId", required: true)]
        public Input<string> ExternalAsmInstanceId { get; set; } = null!;

        public GetExternalAsmInstanceInvokeArgs()
        {
        }
        public static new GetExternalAsmInstanceInvokeArgs Empty => new GetExternalAsmInstanceInvokeArgs();
    }


    [OutputType]
    public sealed class GetExternalAsmInstanceResult
    {
        /// <summary>
        /// The Automatic Diagnostic Repository (ADR) home directory for the ASM instance.
        /// </summary>
        public readonly string AdrHomeDirectory;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The name of the external ASM instance.
        /// </summary>
        public readonly string ComponentName;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// The user-friendly name for the ASM instance. The name does not have to be unique.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external ASM that the ASM instance belongs to.
        /// </summary>
        public readonly string ExternalAsmId;
        public readonly string ExternalAsmInstanceId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB node on which the ASM instance is running.
        /// </summary>
        public readonly string ExternalDbNodeId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system that the ASM instance is a part of.
        /// </summary>
        public readonly string ExternalDbSystemId;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The name of the host on which the ASM instance is running.
        /// </summary>
        public readonly string HostName;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external ASM instance.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The current lifecycle state of the external ASM instance.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The date and time the external ASM instance was created.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the external ASM instance was last updated.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetExternalAsmInstanceResult(
            string adrHomeDirectory,

            string compartmentId,

            string componentName,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            string externalAsmId,

            string externalAsmInstanceId,

            string externalDbNodeId,

            string externalDbSystemId,

            ImmutableDictionary<string, string> freeformTags,

            string hostName,

            string id,

            string lifecycleDetails,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated)
        {
            AdrHomeDirectory = adrHomeDirectory;
            CompartmentId = compartmentId;
            ComponentName = componentName;
            DefinedTags = definedTags;
            DisplayName = displayName;
            ExternalAsmId = externalAsmId;
            ExternalAsmInstanceId = externalAsmInstanceId;
            ExternalDbNodeId = externalDbNodeId;
            ExternalDbSystemId = externalDbSystemId;
            FreeformTags = freeformTags;
            HostName = hostName;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
