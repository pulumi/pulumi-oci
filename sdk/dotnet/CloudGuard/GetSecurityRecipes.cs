// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard
{
    public static class GetSecurityRecipes
    {
        /// <summary>
        /// This data source provides the list of Security Recipes in Oracle Cloud Infrastructure Cloud Guard service.
        /// 
        /// Returns a list of security zone recipes (SecurityRecipeSummary resources) in a
        /// compartment, identified by compartmentId.
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
        ///     var testSecurityRecipes = Oci.CloudGuard.GetSecurityRecipes.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = securityRecipeDisplayName,
        ///         Id = securityRecipeId,
        ///         State = securityRecipeState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetSecurityRecipesResult> InvokeAsync(GetSecurityRecipesArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetSecurityRecipesResult>("oci:CloudGuard/getSecurityRecipes:getSecurityRecipes", args ?? new GetSecurityRecipesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Security Recipes in Oracle Cloud Infrastructure Cloud Guard service.
        /// 
        /// Returns a list of security zone recipes (SecurityRecipeSummary resources) in a
        /// compartment, identified by compartmentId.
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
        ///     var testSecurityRecipes = Oci.CloudGuard.GetSecurityRecipes.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = securityRecipeDisplayName,
        ///         Id = securityRecipeId,
        ///         State = securityRecipeState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetSecurityRecipesResult> Invoke(GetSecurityRecipesInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetSecurityRecipesResult>("oci:CloudGuard/getSecurityRecipes:getSecurityRecipes", args ?? new GetSecurityRecipesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Security Recipes in Oracle Cloud Infrastructure Cloud Guard service.
        /// 
        /// Returns a list of security zone recipes (SecurityRecipeSummary resources) in a
        /// compartment, identified by compartmentId.
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
        ///     var testSecurityRecipes = Oci.CloudGuard.GetSecurityRecipes.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = securityRecipeDisplayName,
        ///         Id = securityRecipeId,
        ///         State = securityRecipeState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetSecurityRecipesResult> Invoke(GetSecurityRecipesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetSecurityRecipesResult>("oci:CloudGuard/getSecurityRecipes:getSecurityRecipes", args ?? new GetSecurityRecipesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetSecurityRecipesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetSecurityRecipesFilterArgs>? _filters;
        public List<Inputs.GetSecurityRecipesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetSecurityRecipesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The unique identifier of the security zone recipe. (`SecurityRecipe`)
        /// </summary>
        [Input("id")]
        public string? Id { get; set; }

        /// <summary>
        /// The field lifecycle state. Only one state can be provided. Default value for state is active. If no value is specified state is active.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetSecurityRecipesArgs()
        {
        }
        public static new GetSecurityRecipesArgs Empty => new GetSecurityRecipesArgs();
    }

    public sealed class GetSecurityRecipesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetSecurityRecipesFilterInputArgs>? _filters;
        public InputList<Inputs.GetSecurityRecipesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetSecurityRecipesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The unique identifier of the security zone recipe. (`SecurityRecipe`)
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        /// <summary>
        /// The field lifecycle state. Only one state can be provided. Default value for state is active. If no value is specified state is active.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetSecurityRecipesInvokeArgs()
        {
        }
        public static new GetSecurityRecipesInvokeArgs Empty => new GetSecurityRecipesInvokeArgs();
    }


    [OutputType]
    public sealed class GetSecurityRecipesResult
    {
        /// <summary>
        /// The OCID of the compartment that contains the recipe
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The recipe's display name
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetSecurityRecipesFilterResult> Filters;
        /// <summary>
        /// Unique identifier that can’t be changed after creation
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// The list of security_recipe_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSecurityRecipesSecurityRecipeCollectionResult> SecurityRecipeCollections;
        /// <summary>
        /// The current lifecycle state of the recipe
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetSecurityRecipesResult(
            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetSecurityRecipesFilterResult> filters,

            string? id,

            ImmutableArray<Outputs.GetSecurityRecipesSecurityRecipeCollectionResult> securityRecipeCollections,

            string? state)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            SecurityRecipeCollections = securityRecipeCollections;
            State = state;
        }
    }
}
