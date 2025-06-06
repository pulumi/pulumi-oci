// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity
{
    public static class GetTagDefaults
    {
        /// <summary>
        /// This data source provides the list of Tag Defaults in Oracle Cloud Infrastructure Identity service.
        /// 
        /// Lists the tag defaults for tag definitions in the specified compartment.
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
        ///     var testTagDefaults = Oci.Identity.GetTagDefaults.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         Id = tagDefaultId,
        ///         State = tagDefaultState,
        ///         TagDefinitionId = testTagDefinition.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetTagDefaultsResult> InvokeAsync(GetTagDefaultsArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetTagDefaultsResult>("oci:Identity/getTagDefaults:getTagDefaults", args ?? new GetTagDefaultsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Tag Defaults in Oracle Cloud Infrastructure Identity service.
        /// 
        /// Lists the tag defaults for tag definitions in the specified compartment.
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
        ///     var testTagDefaults = Oci.Identity.GetTagDefaults.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         Id = tagDefaultId,
        ///         State = tagDefaultState,
        ///         TagDefinitionId = testTagDefinition.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetTagDefaultsResult> Invoke(GetTagDefaultsInvokeArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetTagDefaultsResult>("oci:Identity/getTagDefaults:getTagDefaults", args ?? new GetTagDefaultsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Tag Defaults in Oracle Cloud Infrastructure Identity service.
        /// 
        /// Lists the tag defaults for tag definitions in the specified compartment.
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
        ///     var testTagDefaults = Oci.Identity.GetTagDefaults.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         Id = tagDefaultId,
        ///         State = tagDefaultState,
        ///         TagDefinitionId = testTagDefinition.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetTagDefaultsResult> Invoke(GetTagDefaultsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetTagDefaultsResult>("oci:Identity/getTagDefaults:getTagDefaults", args ?? new GetTagDefaultsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetTagDefaultsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment (remember that the tenancy is simply the root compartment).
        /// </summary>
        [Input("compartmentId")]
        public string? CompartmentId { get; set; }

        [Input("filters")]
        private List<Inputs.GetTagDefaultsFilterArgs>? _filters;
        public List<Inputs.GetTagDefaultsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetTagDefaultsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to only return resources that match the specified OCID exactly.
        /// </summary>
        [Input("id")]
        public string? Id { get; set; }

        /// <summary>
        /// A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        /// <summary>
        /// The OCID of the tag definition.
        /// </summary>
        [Input("tagDefinitionId")]
        public string? TagDefinitionId { get; set; }

        public GetTagDefaultsArgs()
        {
        }
        public static new GetTagDefaultsArgs Empty => new GetTagDefaultsArgs();
    }

    public sealed class GetTagDefaultsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment (remember that the tenancy is simply the root compartment).
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetTagDefaultsFilterInputArgs>? _filters;
        public InputList<Inputs.GetTagDefaultsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetTagDefaultsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to only return resources that match the specified OCID exactly.
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        /// <summary>
        /// A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The OCID of the tag definition.
        /// </summary>
        [Input("tagDefinitionId")]
        public Input<string>? TagDefinitionId { get; set; }

        public GetTagDefaultsInvokeArgs()
        {
        }
        public static new GetTagDefaultsInvokeArgs Empty => new GetTagDefaultsInvokeArgs();
    }


    [OutputType]
    public sealed class GetTagDefaultsResult
    {
        /// <summary>
        /// The OCID of the compartment. The tag default applies to all new resources that get created in the compartment. Resources that existed before the tag default was created are not tagged.
        /// </summary>
        public readonly string? CompartmentId;
        public readonly ImmutableArray<Outputs.GetTagDefaultsFilterResult> Filters;
        /// <summary>
        /// The OCID of the tag default.
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// The tag default's current state. After creating a `TagDefault`, make sure its `lifecycleState` is ACTIVE before using it.
        /// </summary>
        public readonly string? State;
        /// <summary>
        /// The list of tag_defaults.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetTagDefaultsTagDefaultResult> TagDefaults;
        /// <summary>
        /// The OCID of the tag definition. The tag default will always assign a default value for this tag definition.
        /// </summary>
        public readonly string? TagDefinitionId;

        [OutputConstructor]
        private GetTagDefaultsResult(
            string? compartmentId,

            ImmutableArray<Outputs.GetTagDefaultsFilterResult> filters,

            string? id,

            string? state,

            ImmutableArray<Outputs.GetTagDefaultsTagDefaultResult> tagDefaults,

            string? tagDefinitionId)
        {
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
            State = state;
            TagDefaults = tagDefaults;
            TagDefinitionId = tagDefinitionId;
        }
    }
}
