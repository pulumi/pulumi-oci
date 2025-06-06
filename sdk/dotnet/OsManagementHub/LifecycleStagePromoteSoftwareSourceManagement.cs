// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagementHub
{
    /// <summary>
    /// This resource provides the Lifecycle Stage Promote Software Source Management resource in Oracle Cloud Infrastructure Os Management Hub service.
    /// 
    /// Updates the versioned custom software source content to the specified lifecycle stage.
    /// A versioned custom software source OCID (softwareSourceId) is required when promoting content to the first lifecycle stage. You must promote content to the first stage before promoting to subsequent stages, otherwise the service returns an error.
    /// The softwareSourceId is optional when promoting content to the second, third, forth, or fifth stages. If you provide a softwareSourceId, the service validates that it matches the softwareSourceId of the previous stage. If it does not match, the service returns an error. If you don't provide a softwareSourceId, the service promotes the versioned software source from the previous lifecycle stage. If the previous lifecycle stage has no software source, the service returns an error.
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
    ///     var testLifecycleStagePromoteSoftwareSourceManagement = new Oci.OsManagementHub.LifecycleStagePromoteSoftwareSourceManagement("test_lifecycle_stage_promote_software_source_management", new()
    ///     {
    ///         LifecycleStageId = testLifecycleStage.Id,
    ///         SoftwareSourceId = testSoftwareSource.Id,
    ///         WorkRequestDetails = new Oci.OsManagementHub.Inputs.LifecycleStagePromoteSoftwareSourceManagementWorkRequestDetailsArgs
    ///         {
    ///             Description = lifecycleStagePromoteSoftwareSourceManagementWorkRequestDetailsDescription,
    ///             DisplayName = lifecycleStagePromoteSoftwareSourceManagementWorkRequestDetailsDisplayName,
    ///         },
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// LifecycleStagePromoteSoftwareSourceManagement can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:OsManagementHub/lifecycleStagePromoteSoftwareSourceManagement:LifecycleStagePromoteSoftwareSourceManagement test_lifecycle_stage_promote_software_source_management "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:OsManagementHub/lifecycleStagePromoteSoftwareSourceManagement:LifecycleStagePromoteSoftwareSourceManagement")]
    public partial class LifecycleStagePromoteSoftwareSourceManagement : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the lifecycle stage.
        /// </summary>
        [Output("lifecycleStageId")]
        public Output<string> LifecycleStageId { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source. This filter returns resources associated with this software source.
        /// </summary>
        [Output("softwareSourceId")]
        public Output<string> SoftwareSourceId { get; private set; } = null!;

        /// <summary>
        /// Provides the name and description of the job.
        /// </summary>
        [Output("workRequestDetails")]
        public Output<Outputs.LifecycleStagePromoteSoftwareSourceManagementWorkRequestDetails> WorkRequestDetails { get; private set; } = null!;


        /// <summary>
        /// Create a LifecycleStagePromoteSoftwareSourceManagement resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public LifecycleStagePromoteSoftwareSourceManagement(string name, LifecycleStagePromoteSoftwareSourceManagementArgs args, CustomResourceOptions? options = null)
            : base("oci:OsManagementHub/lifecycleStagePromoteSoftwareSourceManagement:LifecycleStagePromoteSoftwareSourceManagement", name, args ?? new LifecycleStagePromoteSoftwareSourceManagementArgs(), MakeResourceOptions(options, ""))
        {
        }

        private LifecycleStagePromoteSoftwareSourceManagement(string name, Input<string> id, LifecycleStagePromoteSoftwareSourceManagementState? state = null, CustomResourceOptions? options = null)
            : base("oci:OsManagementHub/lifecycleStagePromoteSoftwareSourceManagement:LifecycleStagePromoteSoftwareSourceManagement", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing LifecycleStagePromoteSoftwareSourceManagement resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static LifecycleStagePromoteSoftwareSourceManagement Get(string name, Input<string> id, LifecycleStagePromoteSoftwareSourceManagementState? state = null, CustomResourceOptions? options = null)
        {
            return new LifecycleStagePromoteSoftwareSourceManagement(name, id, state, options);
        }
    }

    public sealed class LifecycleStagePromoteSoftwareSourceManagementArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the lifecycle stage.
        /// </summary>
        [Input("lifecycleStageId", required: true)]
        public Input<string> LifecycleStageId { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source. This filter returns resources associated with this software source.
        /// </summary>
        [Input("softwareSourceId")]
        public Input<string>? SoftwareSourceId { get; set; }

        /// <summary>
        /// Provides the name and description of the job.
        /// </summary>
        [Input("workRequestDetails")]
        public Input<Inputs.LifecycleStagePromoteSoftwareSourceManagementWorkRequestDetailsArgs>? WorkRequestDetails { get; set; }

        public LifecycleStagePromoteSoftwareSourceManagementArgs()
        {
        }
        public static new LifecycleStagePromoteSoftwareSourceManagementArgs Empty => new LifecycleStagePromoteSoftwareSourceManagementArgs();
    }

    public sealed class LifecycleStagePromoteSoftwareSourceManagementState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the lifecycle stage.
        /// </summary>
        [Input("lifecycleStageId")]
        public Input<string>? LifecycleStageId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source. This filter returns resources associated with this software source.
        /// </summary>
        [Input("softwareSourceId")]
        public Input<string>? SoftwareSourceId { get; set; }

        /// <summary>
        /// Provides the name and description of the job.
        /// </summary>
        [Input("workRequestDetails")]
        public Input<Inputs.LifecycleStagePromoteSoftwareSourceManagementWorkRequestDetailsGetArgs>? WorkRequestDetails { get; set; }

        public LifecycleStagePromoteSoftwareSourceManagementState()
        {
        }
        public static new LifecycleStagePromoteSoftwareSourceManagementState Empty => new LifecycleStagePromoteSoftwareSourceManagementState();
    }
}
