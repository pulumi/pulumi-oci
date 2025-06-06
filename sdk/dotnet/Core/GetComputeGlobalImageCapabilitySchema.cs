// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetComputeGlobalImageCapabilitySchema
    {
        /// <summary>
        /// This data source provides details about a specific Compute Global Image Capability Schema resource in Oracle Cloud Infrastructure Core service.
        /// 
        /// Gets the specified Compute Global Image Capability Schema
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
        ///     var testComputeGlobalImageCapabilitySchema = Oci.Core.GetComputeGlobalImageCapabilitySchema.Invoke(new()
        ///     {
        ///         ComputeGlobalImageCapabilitySchemaId = testComputeGlobalImageCapabilitySchemaOciCoreComputeGlobalImageCapabilitySchema.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetComputeGlobalImageCapabilitySchemaResult> InvokeAsync(GetComputeGlobalImageCapabilitySchemaArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetComputeGlobalImageCapabilitySchemaResult>("oci:Core/getComputeGlobalImageCapabilitySchema:getComputeGlobalImageCapabilitySchema", args ?? new GetComputeGlobalImageCapabilitySchemaArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Compute Global Image Capability Schema resource in Oracle Cloud Infrastructure Core service.
        /// 
        /// Gets the specified Compute Global Image Capability Schema
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
        ///     var testComputeGlobalImageCapabilitySchema = Oci.Core.GetComputeGlobalImageCapabilitySchema.Invoke(new()
        ///     {
        ///         ComputeGlobalImageCapabilitySchemaId = testComputeGlobalImageCapabilitySchemaOciCoreComputeGlobalImageCapabilitySchema.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetComputeGlobalImageCapabilitySchemaResult> Invoke(GetComputeGlobalImageCapabilitySchemaInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetComputeGlobalImageCapabilitySchemaResult>("oci:Core/getComputeGlobalImageCapabilitySchema:getComputeGlobalImageCapabilitySchema", args ?? new GetComputeGlobalImageCapabilitySchemaInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Compute Global Image Capability Schema resource in Oracle Cloud Infrastructure Core service.
        /// 
        /// Gets the specified Compute Global Image Capability Schema
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
        ///     var testComputeGlobalImageCapabilitySchema = Oci.Core.GetComputeGlobalImageCapabilitySchema.Invoke(new()
        ///     {
        ///         ComputeGlobalImageCapabilitySchemaId = testComputeGlobalImageCapabilitySchemaOciCoreComputeGlobalImageCapabilitySchema.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetComputeGlobalImageCapabilitySchemaResult> Invoke(GetComputeGlobalImageCapabilitySchemaInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetComputeGlobalImageCapabilitySchemaResult>("oci:Core/getComputeGlobalImageCapabilitySchema:getComputeGlobalImageCapabilitySchema", args ?? new GetComputeGlobalImageCapabilitySchemaInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetComputeGlobalImageCapabilitySchemaArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute global image capability schema
        /// </summary>
        [Input("computeGlobalImageCapabilitySchemaId", required: true)]
        public string ComputeGlobalImageCapabilitySchemaId { get; set; } = null!;

        public GetComputeGlobalImageCapabilitySchemaArgs()
        {
        }
        public static new GetComputeGlobalImageCapabilitySchemaArgs Empty => new GetComputeGlobalImageCapabilitySchemaArgs();
    }

    public sealed class GetComputeGlobalImageCapabilitySchemaInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute global image capability schema
        /// </summary>
        [Input("computeGlobalImageCapabilitySchemaId", required: true)]
        public Input<string> ComputeGlobalImageCapabilitySchemaId { get; set; } = null!;

        public GetComputeGlobalImageCapabilitySchemaInvokeArgs()
        {
        }
        public static new GetComputeGlobalImageCapabilitySchemaInvokeArgs Empty => new GetComputeGlobalImageCapabilitySchemaInvokeArgs();
    }


    [OutputType]
    public sealed class GetComputeGlobalImageCapabilitySchemaResult
    {
        /// <summary>
        /// The OCID of the compartment containing the compute global image capability schema
        /// </summary>
        public readonly string CompartmentId;
        public readonly string ComputeGlobalImageCapabilitySchemaId;
        /// <summary>
        /// The name of the global capabilities version resource that is considered the current version.
        /// </summary>
        public readonly string CurrentVersionName;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The date and time the compute global image capability schema was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;

        [OutputConstructor]
        private GetComputeGlobalImageCapabilitySchemaResult(
            string compartmentId,

            string computeGlobalImageCapabilitySchemaId,

            string currentVersionName,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string timeCreated)
        {
            CompartmentId = compartmentId;
            ComputeGlobalImageCapabilitySchemaId = computeGlobalImageCapabilitySchemaId;
            CurrentVersionName = currentVersionName;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            TimeCreated = timeCreated;
        }
    }
}
