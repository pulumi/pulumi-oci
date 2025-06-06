// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity
{
    public static class GetTagStandardTagNamespaceTemplate
    {
        /// <summary>
        /// This data source provides details about a specific Tag Standard Tag Namespace Template resource in Oracle Cloud Infrastructure Identity service.
        /// 
        /// Retrieve the standard tag namespace template given the standard tag namespace name.
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
        ///     var testTagStandardTagNamespaceTemplate = Oci.Identity.GetTagStandardTagNamespaceTemplate.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         StandardTagNamespaceName = testTagNamespace.Name,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetTagStandardTagNamespaceTemplateResult> InvokeAsync(GetTagStandardTagNamespaceTemplateArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetTagStandardTagNamespaceTemplateResult>("oci:Identity/getTagStandardTagNamespaceTemplate:getTagStandardTagNamespaceTemplate", args ?? new GetTagStandardTagNamespaceTemplateArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Tag Standard Tag Namespace Template resource in Oracle Cloud Infrastructure Identity service.
        /// 
        /// Retrieve the standard tag namespace template given the standard tag namespace name.
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
        ///     var testTagStandardTagNamespaceTemplate = Oci.Identity.GetTagStandardTagNamespaceTemplate.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         StandardTagNamespaceName = testTagNamespace.Name,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetTagStandardTagNamespaceTemplateResult> Invoke(GetTagStandardTagNamespaceTemplateInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetTagStandardTagNamespaceTemplateResult>("oci:Identity/getTagStandardTagNamespaceTemplate:getTagStandardTagNamespaceTemplate", args ?? new GetTagStandardTagNamespaceTemplateInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Tag Standard Tag Namespace Template resource in Oracle Cloud Infrastructure Identity service.
        /// 
        /// Retrieve the standard tag namespace template given the standard tag namespace name.
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
        ///     var testTagStandardTagNamespaceTemplate = Oci.Identity.GetTagStandardTagNamespaceTemplate.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         StandardTagNamespaceName = testTagNamespace.Name,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetTagStandardTagNamespaceTemplateResult> Invoke(GetTagStandardTagNamespaceTemplateInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetTagStandardTagNamespaceTemplateResult>("oci:Identity/getTagStandardTagNamespaceTemplate:getTagStandardTagNamespaceTemplate", args ?? new GetTagStandardTagNamespaceTemplateInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetTagStandardTagNamespaceTemplateArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment (remember that the tenancy is simply the root compartment).
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// The name of the standard tag namespace tempate that is requested
        /// </summary>
        [Input("standardTagNamespaceName", required: true)]
        public string StandardTagNamespaceName { get; set; } = null!;

        public GetTagStandardTagNamespaceTemplateArgs()
        {
        }
        public static new GetTagStandardTagNamespaceTemplateArgs Empty => new GetTagStandardTagNamespaceTemplateArgs();
    }

    public sealed class GetTagStandardTagNamespaceTemplateInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment (remember that the tenancy is simply the root compartment).
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// The name of the standard tag namespace tempate that is requested
        /// </summary>
        [Input("standardTagNamespaceName", required: true)]
        public Input<string> StandardTagNamespaceName { get; set; } = null!;

        public GetTagStandardTagNamespaceTemplateInvokeArgs()
        {
        }
        public static new GetTagStandardTagNamespaceTemplateInvokeArgs Empty => new GetTagStandardTagNamespaceTemplateInvokeArgs();
    }


    [OutputType]
    public sealed class GetTagStandardTagNamespaceTemplateResult
    {
        public readonly string CompartmentId;
        /// <summary>
        /// The default description of the tag namespace that users can use to create the tag definition
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The reserved name of this standard tag namespace
        /// </summary>
        public readonly string StandardTagNamespaceName;
        /// <summary>
        /// The status of the standard tag namespace
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// The template of the tag definition. This object includes necessary details to create the provided standard tag definition.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetTagStandardTagNamespaceTemplateTagDefinitionTemplateResult> TagDefinitionTemplates;

        [OutputConstructor]
        private GetTagStandardTagNamespaceTemplateResult(
            string compartmentId,

            string description,

            string id,

            string standardTagNamespaceName,

            string status,

            ImmutableArray<Outputs.GetTagStandardTagNamespaceTemplateTagDefinitionTemplateResult> tagDefinitionTemplates)
        {
            CompartmentId = compartmentId;
            Description = description;
            Id = id;
            StandardTagNamespaceName = standardTagNamespaceName;
            Status = status;
            TagDefinitionTemplates = tagDefinitionTemplates;
        }
    }
}
