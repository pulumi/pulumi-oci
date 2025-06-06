// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Optimizer
{
    public static class GetProfileLevel
    {
        /// <summary>
        /// This data source provides details about a specific Profile Level resource in Oracle Cloud Infrastructure Optimizer service.
        /// 
        /// Lists the existing profile levels.
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
        ///     var testProfileLevel = Oci.Optimizer.GetProfileLevel.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         CompartmentIdInSubtree = profileLevelCompartmentIdInSubtree,
        ///         Name = profileLevelName,
        ///         RecommendationName = testRecommendation.Name,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetProfileLevelResult> InvokeAsync(GetProfileLevelArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetProfileLevelResult>("oci:Optimizer/getProfileLevel:getProfileLevel", args ?? new GetProfileLevelArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Profile Level resource in Oracle Cloud Infrastructure Optimizer service.
        /// 
        /// Lists the existing profile levels.
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
        ///     var testProfileLevel = Oci.Optimizer.GetProfileLevel.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         CompartmentIdInSubtree = profileLevelCompartmentIdInSubtree,
        ///         Name = profileLevelName,
        ///         RecommendationName = testRecommendation.Name,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetProfileLevelResult> Invoke(GetProfileLevelInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetProfileLevelResult>("oci:Optimizer/getProfileLevel:getProfileLevel", args ?? new GetProfileLevelInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Profile Level resource in Oracle Cloud Infrastructure Optimizer service.
        /// 
        /// Lists the existing profile levels.
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
        ///     var testProfileLevel = Oci.Optimizer.GetProfileLevel.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         CompartmentIdInSubtree = profileLevelCompartmentIdInSubtree,
        ///         Name = profileLevelName,
        ///         RecommendationName = testRecommendation.Name,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetProfileLevelResult> Invoke(GetProfileLevelInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetProfileLevelResult>("oci:Optimizer/getProfileLevel:getProfileLevel", args ?? new GetProfileLevelInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetProfileLevelArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the the setting of `accessLevel`.
        /// 
        /// Can only be set to true when performing ListCompartments on the tenancy (root compartment).
        /// </summary>
        [Input("compartmentIdInSubtree", required: true)]
        public bool CompartmentIdInSubtree { get; set; }

        /// <summary>
        /// Optional. A filter that returns results that match the name specified.
        /// </summary>
        [Input("name")]
        public string? Name { get; set; }

        /// <summary>
        /// Optional. A filter that returns results that match the recommendation name specified.
        /// </summary>
        [Input("recommendationName")]
        public string? RecommendationName { get; set; }

        public GetProfileLevelArgs()
        {
        }
        public static new GetProfileLevelArgs Empty => new GetProfileLevelArgs();
    }

    public sealed class GetProfileLevelInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the the setting of `accessLevel`.
        /// 
        /// Can only be set to true when performing ListCompartments on the tenancy (root compartment).
        /// </summary>
        [Input("compartmentIdInSubtree", required: true)]
        public Input<bool> CompartmentIdInSubtree { get; set; } = null!;

        /// <summary>
        /// Optional. A filter that returns results that match the name specified.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// Optional. A filter that returns results that match the recommendation name specified.
        /// </summary>
        [Input("recommendationName")]
        public Input<string>? RecommendationName { get; set; }

        public GetProfileLevelInvokeArgs()
        {
        }
        public static new GetProfileLevelInvokeArgs Empty => new GetProfileLevelInvokeArgs();
    }


    [OutputType]
    public sealed class GetProfileLevelResult
    {
        public readonly string CompartmentId;
        public readonly bool CompartmentIdInSubtree;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A collection of profile levels.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetProfileLevelItemResult> Items;
        /// <summary>
        /// A unique name for the profile level.
        /// </summary>
        public readonly string? Name;
        /// <summary>
        /// The name of the recommendation this profile level applies to.
        /// </summary>
        public readonly string? RecommendationName;

        [OutputConstructor]
        private GetProfileLevelResult(
            string compartmentId,

            bool compartmentIdInSubtree,

            string id,

            ImmutableArray<Outputs.GetProfileLevelItemResult> items,

            string? name,

            string? recommendationName)
        {
            CompartmentId = compartmentId;
            CompartmentIdInSubtree = compartmentIdInSubtree;
            Id = id;
            Items = items;
            Name = name;
            RecommendationName = recommendationName;
        }
    }
}
