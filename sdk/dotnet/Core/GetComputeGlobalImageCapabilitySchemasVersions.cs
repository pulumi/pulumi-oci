// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetComputeGlobalImageCapabilitySchemasVersions
    {
        /// <summary>
        /// This data source provides the list of Compute Global Image Capability Schemas Versions in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists Compute Global Image Capability Schema versions in the specified compartment.
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
        ///     var testComputeGlobalImageCapabilitySchemasVersions = Oci.Core.GetComputeGlobalImageCapabilitySchemasVersions.Invoke(new()
        ///     {
        ///         ComputeGlobalImageCapabilitySchemaId = testComputeGlobalImageCapabilitySchema.Id,
        ///         DisplayName = computeGlobalImageCapabilitySchemasVersionDisplayName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetComputeGlobalImageCapabilitySchemasVersionsResult> InvokeAsync(GetComputeGlobalImageCapabilitySchemasVersionsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetComputeGlobalImageCapabilitySchemasVersionsResult>("oci:Core/getComputeGlobalImageCapabilitySchemasVersions:getComputeGlobalImageCapabilitySchemasVersions", args ?? new GetComputeGlobalImageCapabilitySchemasVersionsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Compute Global Image Capability Schemas Versions in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists Compute Global Image Capability Schema versions in the specified compartment.
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
        ///     var testComputeGlobalImageCapabilitySchemasVersions = Oci.Core.GetComputeGlobalImageCapabilitySchemasVersions.Invoke(new()
        ///     {
        ///         ComputeGlobalImageCapabilitySchemaId = testComputeGlobalImageCapabilitySchema.Id,
        ///         DisplayName = computeGlobalImageCapabilitySchemasVersionDisplayName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetComputeGlobalImageCapabilitySchemasVersionsResult> Invoke(GetComputeGlobalImageCapabilitySchemasVersionsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetComputeGlobalImageCapabilitySchemasVersionsResult>("oci:Core/getComputeGlobalImageCapabilitySchemasVersions:getComputeGlobalImageCapabilitySchemasVersions", args ?? new GetComputeGlobalImageCapabilitySchemasVersionsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Compute Global Image Capability Schemas Versions in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists Compute Global Image Capability Schema versions in the specified compartment.
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
        ///     var testComputeGlobalImageCapabilitySchemasVersions = Oci.Core.GetComputeGlobalImageCapabilitySchemasVersions.Invoke(new()
        ///     {
        ///         ComputeGlobalImageCapabilitySchemaId = testComputeGlobalImageCapabilitySchema.Id,
        ///         DisplayName = computeGlobalImageCapabilitySchemasVersionDisplayName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetComputeGlobalImageCapabilitySchemasVersionsResult> Invoke(GetComputeGlobalImageCapabilitySchemasVersionsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetComputeGlobalImageCapabilitySchemasVersionsResult>("oci:Core/getComputeGlobalImageCapabilitySchemasVersions:getComputeGlobalImageCapabilitySchemasVersions", args ?? new GetComputeGlobalImageCapabilitySchemasVersionsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetComputeGlobalImageCapabilitySchemasVersionsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute global image capability schema
        /// </summary>
        [Input("computeGlobalImageCapabilitySchemaId", required: true)]
        public string ComputeGlobalImageCapabilitySchemaId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetComputeGlobalImageCapabilitySchemasVersionsFilterArgs>? _filters;
        public List<Inputs.GetComputeGlobalImageCapabilitySchemasVersionsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetComputeGlobalImageCapabilitySchemasVersionsFilterArgs>());
            set => _filters = value;
        }

        public GetComputeGlobalImageCapabilitySchemasVersionsArgs()
        {
        }
        public static new GetComputeGlobalImageCapabilitySchemasVersionsArgs Empty => new GetComputeGlobalImageCapabilitySchemasVersionsArgs();
    }

    public sealed class GetComputeGlobalImageCapabilitySchemasVersionsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute global image capability schema
        /// </summary>
        [Input("computeGlobalImageCapabilitySchemaId", required: true)]
        public Input<string> ComputeGlobalImageCapabilitySchemaId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetComputeGlobalImageCapabilitySchemasVersionsFilterInputArgs>? _filters;
        public InputList<Inputs.GetComputeGlobalImageCapabilitySchemasVersionsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetComputeGlobalImageCapabilitySchemasVersionsFilterInputArgs>());
            set => _filters = value;
        }

        public GetComputeGlobalImageCapabilitySchemasVersionsInvokeArgs()
        {
        }
        public static new GetComputeGlobalImageCapabilitySchemasVersionsInvokeArgs Empty => new GetComputeGlobalImageCapabilitySchemasVersionsInvokeArgs();
    }


    [OutputType]
    public sealed class GetComputeGlobalImageCapabilitySchemasVersionsResult
    {
        /// <summary>
        /// The ocid of the compute global image capability schema
        /// </summary>
        public readonly string ComputeGlobalImageCapabilitySchemaId;
        /// <summary>
        /// The list of compute_global_image_capability_schema_versions.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetComputeGlobalImageCapabilitySchemasVersionsComputeGlobalImageCapabilitySchemaVersionResult> ComputeGlobalImageCapabilitySchemaVersions;
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetComputeGlobalImageCapabilitySchemasVersionsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;

        [OutputConstructor]
        private GetComputeGlobalImageCapabilitySchemasVersionsResult(
            string computeGlobalImageCapabilitySchemaId,

            ImmutableArray<Outputs.GetComputeGlobalImageCapabilitySchemasVersionsComputeGlobalImageCapabilitySchemaVersionResult> computeGlobalImageCapabilitySchemaVersions,

            string? displayName,

            ImmutableArray<Outputs.GetComputeGlobalImageCapabilitySchemasVersionsFilterResult> filters,

            string id)
        {
            ComputeGlobalImageCapabilitySchemaId = computeGlobalImageCapabilitySchemaId;
            ComputeGlobalImageCapabilitySchemaVersions = computeGlobalImageCapabilitySchemaVersions;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
        }
    }
}
