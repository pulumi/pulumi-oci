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
    /// This resource provides the Profile Attach Lifecycle Stage Management resource in Oracle Cloud Infrastructure Os Management Hub service.
    /// 
    /// Attaches the specified lifecycle stage to a profile.
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
    ///     var testProfileAttachLifecycleStageManagement = new Oci.OsManagementHub.ProfileAttachLifecycleStageManagement("test_profile_attach_lifecycle_stage_management", new()
    ///     {
    ///         LifecycleStageId = testLifecycleStage.Id,
    ///         ProfileId = testProfile.Id,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// ProfileAttachLifecycleStageManagement can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:OsManagementHub/profileAttachLifecycleStageManagement:ProfileAttachLifecycleStageManagement test_profile_attach_lifecycle_stage_management "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:OsManagementHub/profileAttachLifecycleStageManagement:ProfileAttachLifecycleStageManagement")]
    public partial class ProfileAttachLifecycleStageManagement : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the lifecycle stage that the instance will be associated with.
        /// </summary>
        [Output("lifecycleStageId")]
        public Output<string> LifecycleStageId { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the registration profile.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("profileId")]
        public Output<string> ProfileId { get; private set; } = null!;


        /// <summary>
        /// Create a ProfileAttachLifecycleStageManagement resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public ProfileAttachLifecycleStageManagement(string name, ProfileAttachLifecycleStageManagementArgs args, CustomResourceOptions? options = null)
            : base("oci:OsManagementHub/profileAttachLifecycleStageManagement:ProfileAttachLifecycleStageManagement", name, args ?? new ProfileAttachLifecycleStageManagementArgs(), MakeResourceOptions(options, ""))
        {
        }

        private ProfileAttachLifecycleStageManagement(string name, Input<string> id, ProfileAttachLifecycleStageManagementState? state = null, CustomResourceOptions? options = null)
            : base("oci:OsManagementHub/profileAttachLifecycleStageManagement:ProfileAttachLifecycleStageManagement", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing ProfileAttachLifecycleStageManagement resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static ProfileAttachLifecycleStageManagement Get(string name, Input<string> id, ProfileAttachLifecycleStageManagementState? state = null, CustomResourceOptions? options = null)
        {
            return new ProfileAttachLifecycleStageManagement(name, id, state, options);
        }
    }

    public sealed class ProfileAttachLifecycleStageManagementArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the lifecycle stage that the instance will be associated with.
        /// </summary>
        [Input("lifecycleStageId", required: true)]
        public Input<string> LifecycleStageId { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the registration profile.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("profileId", required: true)]
        public Input<string> ProfileId { get; set; } = null!;

        public ProfileAttachLifecycleStageManagementArgs()
        {
        }
        public static new ProfileAttachLifecycleStageManagementArgs Empty => new ProfileAttachLifecycleStageManagementArgs();
    }

    public sealed class ProfileAttachLifecycleStageManagementState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the lifecycle stage that the instance will be associated with.
        /// </summary>
        [Input("lifecycleStageId")]
        public Input<string>? LifecycleStageId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the registration profile.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("profileId")]
        public Input<string>? ProfileId { get; set; }

        public ProfileAttachLifecycleStageManagementState()
        {
        }
        public static new ProfileAttachLifecycleStageManagementState Empty => new ProfileAttachLifecycleStageManagementState();
    }
}
