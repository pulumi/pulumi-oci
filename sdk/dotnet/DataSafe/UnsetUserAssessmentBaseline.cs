// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe
{
    /// <summary>
    /// This resource provides the Unset User Assessment Baseline resource in Oracle Cloud Infrastructure Data Safe service.
    /// 
    /// Removes the baseline setting for the saved user assessment. The saved user assessment is no longer considered a baseline.
    /// Sets the if-match parameter to the value of the etag from a previous GET or POST response for that resource.
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using System.Collections.Generic;
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// return await Deployment.RunAsync(() =&gt; 
    /// {
    ///     var testUnsetUserAssessmentBaseline = new Oci.DataSafe.UnsetUserAssessmentBaseline("testUnsetUserAssessmentBaseline", new()
    ///     {
    ///         UserAssessmentId = oci_data_safe_user_assessment.Test_user_assessment.Id,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// UnsetUserAssessmentBaseline can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:DataSafe/unsetUserAssessmentBaseline:UnsetUserAssessmentBaseline test_unset_user_assessment_baseline "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:DataSafe/unsetUserAssessmentBaseline:UnsetUserAssessmentBaseline")]
    public partial class UnsetUserAssessmentBaseline : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The OCID of the user assessment.
        /// </summary>
        [Output("userAssessmentId")]
        public Output<string> UserAssessmentId { get; private set; } = null!;


        /// <summary>
        /// Create a UnsetUserAssessmentBaseline resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public UnsetUserAssessmentBaseline(string name, UnsetUserAssessmentBaselineArgs args, CustomResourceOptions? options = null)
            : base("oci:DataSafe/unsetUserAssessmentBaseline:UnsetUserAssessmentBaseline", name, args ?? new UnsetUserAssessmentBaselineArgs(), MakeResourceOptions(options, ""))
        {
        }

        private UnsetUserAssessmentBaseline(string name, Input<string> id, UnsetUserAssessmentBaselineState? state = null, CustomResourceOptions? options = null)
            : base("oci:DataSafe/unsetUserAssessmentBaseline:UnsetUserAssessmentBaseline", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing UnsetUserAssessmentBaseline resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static UnsetUserAssessmentBaseline Get(string name, Input<string> id, UnsetUserAssessmentBaselineState? state = null, CustomResourceOptions? options = null)
        {
            return new UnsetUserAssessmentBaseline(name, id, state, options);
        }
    }

    public sealed class UnsetUserAssessmentBaselineArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of the user assessment.
        /// </summary>
        [Input("userAssessmentId", required: true)]
        public Input<string> UserAssessmentId { get; set; } = null!;

        public UnsetUserAssessmentBaselineArgs()
        {
        }
        public static new UnsetUserAssessmentBaselineArgs Empty => new UnsetUserAssessmentBaselineArgs();
    }

    public sealed class UnsetUserAssessmentBaselineState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of the user assessment.
        /// </summary>
        [Input("userAssessmentId")]
        public Input<string>? UserAssessmentId { get; set; }

        public UnsetUserAssessmentBaselineState()
        {
        }
        public static new UnsetUserAssessmentBaselineState Empty => new UnsetUserAssessmentBaselineState();
    }
}