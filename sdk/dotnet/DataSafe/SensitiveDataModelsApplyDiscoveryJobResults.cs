// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe
{
    [OciResourceType("oci:DataSafe/sensitiveDataModelsApplyDiscoveryJobResults:SensitiveDataModelsApplyDiscoveryJobResults")]
    public partial class SensitiveDataModelsApplyDiscoveryJobResults : global::Pulumi.CustomResource
    {
        [Output("discoveryJobId")]
        public Output<string> DiscoveryJobId { get; private set; } = null!;

        [Output("sensitiveDataModelId")]
        public Output<string> SensitiveDataModelId { get; private set; } = null!;


        /// <summary>
        /// Create a SensitiveDataModelsApplyDiscoveryJobResults resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public SensitiveDataModelsApplyDiscoveryJobResults(string name, SensitiveDataModelsApplyDiscoveryJobResultsArgs args, CustomResourceOptions? options = null)
            : base("oci:DataSafe/sensitiveDataModelsApplyDiscoveryJobResults:SensitiveDataModelsApplyDiscoveryJobResults", name, args ?? new SensitiveDataModelsApplyDiscoveryJobResultsArgs(), MakeResourceOptions(options, ""))
        {
        }

        private SensitiveDataModelsApplyDiscoveryJobResults(string name, Input<string> id, SensitiveDataModelsApplyDiscoveryJobResultsState? state = null, CustomResourceOptions? options = null)
            : base("oci:DataSafe/sensitiveDataModelsApplyDiscoveryJobResults:SensitiveDataModelsApplyDiscoveryJobResults", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing SensitiveDataModelsApplyDiscoveryJobResults resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static SensitiveDataModelsApplyDiscoveryJobResults Get(string name, Input<string> id, SensitiveDataModelsApplyDiscoveryJobResultsState? state = null, CustomResourceOptions? options = null)
        {
            return new SensitiveDataModelsApplyDiscoveryJobResults(name, id, state, options);
        }
    }

    public sealed class SensitiveDataModelsApplyDiscoveryJobResultsArgs : global::Pulumi.ResourceArgs
    {
        [Input("discoveryJobId", required: true)]
        public Input<string> DiscoveryJobId { get; set; } = null!;

        [Input("sensitiveDataModelId", required: true)]
        public Input<string> SensitiveDataModelId { get; set; } = null!;

        public SensitiveDataModelsApplyDiscoveryJobResultsArgs()
        {
        }
        public static new SensitiveDataModelsApplyDiscoveryJobResultsArgs Empty => new SensitiveDataModelsApplyDiscoveryJobResultsArgs();
    }

    public sealed class SensitiveDataModelsApplyDiscoveryJobResultsState : global::Pulumi.ResourceArgs
    {
        [Input("discoveryJobId")]
        public Input<string>? DiscoveryJobId { get; set; }

        [Input("sensitiveDataModelId")]
        public Input<string>? SensitiveDataModelId { get; set; }

        public SensitiveDataModelsApplyDiscoveryJobResultsState()
        {
        }
        public static new SensitiveDataModelsApplyDiscoveryJobResultsState Empty => new SensitiveDataModelsApplyDiscoveryJobResultsState();
    }
}