// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard
{
    public static class GetDetectorRecipe
    {
        /// <summary>
        /// This data source provides details about a specific Detector Recipe resource in Oracle Cloud Infrastructure Cloud Guard service.
        /// 
        /// Returns a detector recipe (DetectorRecipe resource) identified by detectorRecipeId.
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
        ///     var testDetectorRecipe = Oci.CloudGuard.GetDetectorRecipe.Invoke(new()
        ///     {
        ///         DetectorRecipeId = testDetectorRecipeOciCloudGuardDetectorRecipe.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetDetectorRecipeResult> InvokeAsync(GetDetectorRecipeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetDetectorRecipeResult>("oci:CloudGuard/getDetectorRecipe:getDetectorRecipe", args ?? new GetDetectorRecipeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Detector Recipe resource in Oracle Cloud Infrastructure Cloud Guard service.
        /// 
        /// Returns a detector recipe (DetectorRecipe resource) identified by detectorRecipeId.
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
        ///     var testDetectorRecipe = Oci.CloudGuard.GetDetectorRecipe.Invoke(new()
        ///     {
        ///         DetectorRecipeId = testDetectorRecipeOciCloudGuardDetectorRecipe.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDetectorRecipeResult> Invoke(GetDetectorRecipeInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetDetectorRecipeResult>("oci:CloudGuard/getDetectorRecipe:getDetectorRecipe", args ?? new GetDetectorRecipeInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Detector Recipe resource in Oracle Cloud Infrastructure Cloud Guard service.
        /// 
        /// Returns a detector recipe (DetectorRecipe resource) identified by detectorRecipeId.
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
        ///     var testDetectorRecipe = Oci.CloudGuard.GetDetectorRecipe.Invoke(new()
        ///     {
        ///         DetectorRecipeId = testDetectorRecipeOciCloudGuardDetectorRecipe.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDetectorRecipeResult> Invoke(GetDetectorRecipeInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetDetectorRecipeResult>("oci:CloudGuard/getDetectorRecipe:getDetectorRecipe", args ?? new GetDetectorRecipeInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDetectorRecipeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Detector recipe OCID
        /// </summary>
        [Input("detectorRecipeId", required: true)]
        public string DetectorRecipeId { get; set; } = null!;

        public GetDetectorRecipeArgs()
        {
        }
        public static new GetDetectorRecipeArgs Empty => new GetDetectorRecipeArgs();
    }

    public sealed class GetDetectorRecipeInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Detector recipe OCID
        /// </summary>
        [Input("detectorRecipeId", required: true)]
        public Input<string> DetectorRecipeId { get; set; } = null!;

        public GetDetectorRecipeInvokeArgs()
        {
        }
        public static new GetDetectorRecipeInvokeArgs Empty => new GetDetectorRecipeInvokeArgs();
    }


    [OutputType]
    public sealed class GetDetectorRecipeResult
    {
        /// <summary>
        /// Compartment OCID of detector recipe
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// Description for detector recipe detector rule
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Detector recipe for the rule
        /// </summary>
        public readonly string Detector;
        public readonly string DetectorRecipeId;
        /// <summary>
        /// Recipe type ( STANDARD, ENTERPRISE )
        /// </summary>
        public readonly string DetectorRecipeType;
        /// <summary>
        /// List of detector rules for the detector type for recipe - user input
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDetectorRecipeDetectorRuleResult> DetectorRules;
        /// <summary>
        /// Display name of the entity
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// List of effective detector rules for the detector type for recipe after applying defaults
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDetectorRecipeEffectiveDetectorRuleResult> EffectiveDetectorRules;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// OCID for detector recipe
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Owner of detector recipe
        /// </summary>
        public readonly string Owner;
        /// <summary>
        /// Recipe OCID of the source recipe to be cloned
        /// </summary>
        public readonly string SourceDetectorRecipeId;
        /// <summary>
        /// The current lifecycle state of the resource
        /// </summary>
        public readonly string State;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// List of target IDs to which the recipe is attached
        /// </summary>
        public readonly ImmutableArray<string> TargetIds;
        /// <summary>
        /// The date and time the detector recipe was created Format defined by RFC3339.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the detector recipe was last updated Format defined by RFC3339.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetDetectorRecipeResult(
            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string description,

            string detector,

            string detectorRecipeId,

            string detectorRecipeType,

            ImmutableArray<Outputs.GetDetectorRecipeDetectorRuleResult> detectorRules,

            string displayName,

            ImmutableArray<Outputs.GetDetectorRecipeEffectiveDetectorRuleResult> effectiveDetectorRules,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string owner,

            string sourceDetectorRecipeId,

            string state,

            ImmutableDictionary<string, string> systemTags,

            ImmutableArray<string> targetIds,

            string timeCreated,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            Description = description;
            Detector = detector;
            DetectorRecipeId = detectorRecipeId;
            DetectorRecipeType = detectorRecipeType;
            DetectorRules = detectorRules;
            DisplayName = displayName;
            EffectiveDetectorRules = effectiveDetectorRules;
            FreeformTags = freeformTags;
            Id = id;
            Owner = owner;
            SourceDetectorRecipeId = sourceDetectorRecipeId;
            State = state;
            SystemTags = systemTags;
            TargetIds = targetIds;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
