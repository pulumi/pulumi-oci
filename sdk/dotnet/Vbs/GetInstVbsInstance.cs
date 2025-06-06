// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Vbs
{
    public static class GetInstVbsInstance
    {
        /// <summary>
        /// This data source provides details about a specific Vbs Instance resource in Oracle Cloud Infrastructure Vbs Inst service.
        /// 
        /// Gets a VbsInstance by identifier
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
        ///     var testVbsInstance = Oci.Vbs.GetInstVbsInstance.Invoke(new()
        ///     {
        ///         VbsInstanceId = testVbsInstanceOciVbsInstVbsInstance.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetInstVbsInstanceResult> InvokeAsync(GetInstVbsInstanceArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetInstVbsInstanceResult>("oci:Vbs/getInstVbsInstance:getInstVbsInstance", args ?? new GetInstVbsInstanceArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Vbs Instance resource in Oracle Cloud Infrastructure Vbs Inst service.
        /// 
        /// Gets a VbsInstance by identifier
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
        ///     var testVbsInstance = Oci.Vbs.GetInstVbsInstance.Invoke(new()
        ///     {
        ///         VbsInstanceId = testVbsInstanceOciVbsInstVbsInstance.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetInstVbsInstanceResult> Invoke(GetInstVbsInstanceInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetInstVbsInstanceResult>("oci:Vbs/getInstVbsInstance:getInstVbsInstance", args ?? new GetInstVbsInstanceInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Vbs Instance resource in Oracle Cloud Infrastructure Vbs Inst service.
        /// 
        /// Gets a VbsInstance by identifier
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
        ///     var testVbsInstance = Oci.Vbs.GetInstVbsInstance.Invoke(new()
        ///     {
        ///         VbsInstanceId = testVbsInstanceOciVbsInstVbsInstance.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetInstVbsInstanceResult> Invoke(GetInstVbsInstanceInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetInstVbsInstanceResult>("oci:Vbs/getInstVbsInstance:getInstVbsInstance", args ?? new GetInstVbsInstanceInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetInstVbsInstanceArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// unique VbsInstance identifier
        /// </summary>
        [Input("vbsInstanceId", required: true)]
        public string VbsInstanceId { get; set; } = null!;

        public GetInstVbsInstanceArgs()
        {
        }
        public static new GetInstVbsInstanceArgs Empty => new GetInstVbsInstanceArgs();
    }

    public sealed class GetInstVbsInstanceInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// unique VbsInstance identifier
        /// </summary>
        [Input("vbsInstanceId", required: true)]
        public Input<string> VbsInstanceId { get; set; } = null!;

        public GetInstVbsInstanceInvokeArgs()
        {
        }
        public static new GetInstVbsInstanceInvokeArgs Empty => new GetInstVbsInstanceInvokeArgs();
    }


    [OutputType]
    public sealed class GetInstVbsInstanceResult
    {
        /// <summary>
        /// Compartment of the service instance
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// Service instance display name
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// Unique identifier that is immutable on creation
        /// </summary>
        public readonly string Id;
        public readonly string IdcsAccessToken;
        /// <summary>
        /// Whether the VBS service instance owner explicitly approved VBS to create and use resources in the customer tenancy
        /// </summary>
        public readonly bool IsResourceUsageAgreementGranted;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string LifecyleDetails;
        /// <summary>
        /// Service instance name (unique identifier)
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// Compartment where VBS may create additional resources for the service instance
        /// </summary>
        public readonly string ResourceCompartmentId;
        /// <summary>
        /// The current state of the VbsInstance.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The time the the VbsInstance was created. An RFC3339 formatted datetime string
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time the VbsInstance was updated. An RFC3339 formatted datetime string
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// Public web URL for accessing the VBS service instance
        /// </summary>
        public readonly string VbsAccessUrl;
        public readonly string VbsInstanceId;

        [OutputConstructor]
        private GetInstVbsInstanceResult(
            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string idcsAccessToken,

            bool isResourceUsageAgreementGranted,

            string lifecyleDetails,

            string name,

            string resourceCompartmentId,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated,

            string vbsAccessUrl,

            string vbsInstanceId)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            IdcsAccessToken = idcsAccessToken;
            IsResourceUsageAgreementGranted = isResourceUsageAgreementGranted;
            LifecyleDetails = lifecyleDetails;
            Name = name;
            ResourceCompartmentId = resourceCompartmentId;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            VbsAccessUrl = vbsAccessUrl;
            VbsInstanceId = vbsInstanceId;
        }
    }
}
