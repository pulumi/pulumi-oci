// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement
{
    /// <summary>
    /// This resource provides the External Db System Stack Monitorings Management resource in Oracle Cloud Infrastructure Database Management service.
    /// 
    /// Enables Stack Monitoring for all the components of the specified
    /// external DB system (except databases).
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
    ///     var testExternalDbSystemStackMonitoringsManagement = new Oci.DatabaseManagement.ExternalDbSystemStackMonitoringsManagement("test_external_db_system_stack_monitorings_management", new()
    ///     {
    ///         ExternalDbSystemId = testExternalDbSystem.Id,
    ///         EnableStackMonitoring = enableStackMonitoring,
    ///         IsEnabled = externalDbSystemStackMonitoringsManagementIsEnabled,
    ///         Metadata = externalDbSystemStackMonitoringsManagementMetadata,
    ///     });
    /// 
    /// });
    /// ```
    /// </summary>
    [OciResourceType("oci:DatabaseManagement/externalDbSystemStackMonitoringsManagement:ExternalDbSystemStackMonitoringsManagement")]
    public partial class ExternalDbSystemStackMonitoringsManagement : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("enableStackMonitoring")]
        public Output<bool> EnableStackMonitoring { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
        /// </summary>
        [Output("externalDbSystemId")]
        public Output<string> ExternalDbSystemId { get; private set; } = null!;

        /// <summary>
        /// The status of the associated service.
        /// </summary>
        [Output("isEnabled")]
        public Output<bool> IsEnabled { get; private set; } = null!;

        /// <summary>
        /// The associated service-specific inputs in JSON string format, which Database Management can identify.
        /// </summary>
        [Output("metadata")]
        public Output<string> Metadata { get; private set; } = null!;


        /// <summary>
        /// Create a ExternalDbSystemStackMonitoringsManagement resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public ExternalDbSystemStackMonitoringsManagement(string name, ExternalDbSystemStackMonitoringsManagementArgs args, CustomResourceOptions? options = null)
            : base("oci:DatabaseManagement/externalDbSystemStackMonitoringsManagement:ExternalDbSystemStackMonitoringsManagement", name, args ?? new ExternalDbSystemStackMonitoringsManagementArgs(), MakeResourceOptions(options, ""))
        {
        }

        private ExternalDbSystemStackMonitoringsManagement(string name, Input<string> id, ExternalDbSystemStackMonitoringsManagementState? state = null, CustomResourceOptions? options = null)
            : base("oci:DatabaseManagement/externalDbSystemStackMonitoringsManagement:ExternalDbSystemStackMonitoringsManagement", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing ExternalDbSystemStackMonitoringsManagement resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static ExternalDbSystemStackMonitoringsManagement Get(string name, Input<string> id, ExternalDbSystemStackMonitoringsManagementState? state = null, CustomResourceOptions? options = null)
        {
            return new ExternalDbSystemStackMonitoringsManagement(name, id, state, options);
        }
    }

    public sealed class ExternalDbSystemStackMonitoringsManagementArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("enableStackMonitoring", required: true)]
        public Input<bool> EnableStackMonitoring { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
        /// </summary>
        [Input("externalDbSystemId", required: true)]
        public Input<string> ExternalDbSystemId { get; set; } = null!;

        /// <summary>
        /// The status of the associated service.
        /// </summary>
        [Input("isEnabled")]
        public Input<bool>? IsEnabled { get; set; }

        /// <summary>
        /// The associated service-specific inputs in JSON string format, which Database Management can identify.
        /// </summary>
        [Input("metadata")]
        public Input<string>? Metadata { get; set; }

        public ExternalDbSystemStackMonitoringsManagementArgs()
        {
        }
        public static new ExternalDbSystemStackMonitoringsManagementArgs Empty => new ExternalDbSystemStackMonitoringsManagementArgs();
    }

    public sealed class ExternalDbSystemStackMonitoringsManagementState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("enableStackMonitoring")]
        public Input<bool>? EnableStackMonitoring { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
        /// </summary>
        [Input("externalDbSystemId")]
        public Input<string>? ExternalDbSystemId { get; set; }

        /// <summary>
        /// The status of the associated service.
        /// </summary>
        [Input("isEnabled")]
        public Input<bool>? IsEnabled { get; set; }

        /// <summary>
        /// The associated service-specific inputs in JSON string format, which Database Management can identify.
        /// </summary>
        [Input("metadata")]
        public Input<string>? Metadata { get; set; }

        public ExternalDbSystemStackMonitoringsManagementState()
        {
        }
        public static new ExternalDbSystemStackMonitoringsManagementState Empty => new ExternalDbSystemStackMonitoringsManagementState();
    }
}
