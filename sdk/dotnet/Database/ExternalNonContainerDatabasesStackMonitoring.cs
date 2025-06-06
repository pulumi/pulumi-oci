// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    /// <summary>
    /// This resource provides the Externalnoncontainerdatabases Stack Monitoring resource in Oracle Cloud Infrastructure Database service.
    /// 
    /// Enable Stack Monitoring for the external non-container database.
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
    ///     var testExternalnoncontainerdatabasesStackMonitoring = new Oci.Database.ExternalNonContainerDatabasesStackMonitoring("test_externalnoncontainerdatabases_stack_monitoring", new()
    ///     {
    ///         ExternalDatabaseConnectorId = testExternalDatabaseConnector.Id,
    ///         ExternalNonContainerDatabaseId = testExternalNonContainerDatabase.Id,
    ///         EnableStackMonitoring = true,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// Import is not supported for this resource.
    /// </summary>
    [OciResourceType("oci:Database/externalNonContainerDatabasesStackMonitoring:ExternalNonContainerDatabasesStackMonitoring")]
    public partial class ExternalNonContainerDatabasesStackMonitoring : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) Enabling Stack Monitoring on External Non Container Databases . Requires boolean value "true" or "false".
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("enableStackMonitoring")]
        public Output<bool> EnableStackMonitoring { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
        /// </summary>
        [Output("externalDatabaseConnectorId")]
        public Output<string> ExternalDatabaseConnectorId { get; private set; } = null!;

        /// <summary>
        /// The external non-container database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Output("externalNonContainerDatabaseId")]
        public Output<string> ExternalNonContainerDatabaseId { get; private set; } = null!;


        /// <summary>
        /// Create a ExternalNonContainerDatabasesStackMonitoring resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public ExternalNonContainerDatabasesStackMonitoring(string name, ExternalNonContainerDatabasesStackMonitoringArgs args, CustomResourceOptions? options = null)
            : base("oci:Database/externalNonContainerDatabasesStackMonitoring:ExternalNonContainerDatabasesStackMonitoring", name, args ?? new ExternalNonContainerDatabasesStackMonitoringArgs(), MakeResourceOptions(options, ""))
        {
        }

        private ExternalNonContainerDatabasesStackMonitoring(string name, Input<string> id, ExternalNonContainerDatabasesStackMonitoringState? state = null, CustomResourceOptions? options = null)
            : base("oci:Database/externalNonContainerDatabasesStackMonitoring:ExternalNonContainerDatabasesStackMonitoring", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing ExternalNonContainerDatabasesStackMonitoring resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static ExternalNonContainerDatabasesStackMonitoring Get(string name, Input<string> id, ExternalNonContainerDatabasesStackMonitoringState? state = null, CustomResourceOptions? options = null)
        {
            return new ExternalNonContainerDatabasesStackMonitoring(name, id, state, options);
        }
    }

    public sealed class ExternalNonContainerDatabasesStackMonitoringArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Enabling Stack Monitoring on External Non Container Databases . Requires boolean value "true" or "false".
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("enableStackMonitoring", required: true)]
        public Input<bool> EnableStackMonitoring { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
        /// </summary>
        [Input("externalDatabaseConnectorId", required: true)]
        public Input<string> ExternalDatabaseConnectorId { get; set; } = null!;

        /// <summary>
        /// The external non-container database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("externalNonContainerDatabaseId", required: true)]
        public Input<string> ExternalNonContainerDatabaseId { get; set; } = null!;

        public ExternalNonContainerDatabasesStackMonitoringArgs()
        {
        }
        public static new ExternalNonContainerDatabasesStackMonitoringArgs Empty => new ExternalNonContainerDatabasesStackMonitoringArgs();
    }

    public sealed class ExternalNonContainerDatabasesStackMonitoringState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Enabling Stack Monitoring on External Non Container Databases . Requires boolean value "true" or "false".
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("enableStackMonitoring")]
        public Input<bool>? EnableStackMonitoring { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external database connector](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalDatabaseConnectorDetails).
        /// </summary>
        [Input("externalDatabaseConnectorId")]
        public Input<string>? ExternalDatabaseConnectorId { get; set; }

        /// <summary>
        /// The external non-container database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("externalNonContainerDatabaseId")]
        public Input<string>? ExternalNonContainerDatabaseId { get; set; }

        public ExternalNonContainerDatabasesStackMonitoringState()
        {
        }
        public static new ExternalNonContainerDatabasesStackMonitoringState Empty => new ExternalNonContainerDatabasesStackMonitoringState();
    }
}
