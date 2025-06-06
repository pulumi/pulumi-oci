// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience
{
    public static class GetMlApplicationImplementation
    {
        /// <summary>
        /// This data source provides details about a specific Ml Application Implementation resource in Oracle Cloud Infrastructure Data Science service.
        /// 
        /// Gets a MlApplicationImplementation by identifier
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
        ///     var testMlApplicationImplementation = Oci.DataScience.GetMlApplicationImplementation.Invoke(new()
        ///     {
        ///         MlApplicationImplementationId = testMlApplicationImplementationOciDatascienceMlApplicationImplementation.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetMlApplicationImplementationResult> InvokeAsync(GetMlApplicationImplementationArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetMlApplicationImplementationResult>("oci:DataScience/getMlApplicationImplementation:getMlApplicationImplementation", args ?? new GetMlApplicationImplementationArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Ml Application Implementation resource in Oracle Cloud Infrastructure Data Science service.
        /// 
        /// Gets a MlApplicationImplementation by identifier
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
        ///     var testMlApplicationImplementation = Oci.DataScience.GetMlApplicationImplementation.Invoke(new()
        ///     {
        ///         MlApplicationImplementationId = testMlApplicationImplementationOciDatascienceMlApplicationImplementation.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetMlApplicationImplementationResult> Invoke(GetMlApplicationImplementationInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetMlApplicationImplementationResult>("oci:DataScience/getMlApplicationImplementation:getMlApplicationImplementation", args ?? new GetMlApplicationImplementationInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Ml Application Implementation resource in Oracle Cloud Infrastructure Data Science service.
        /// 
        /// Gets a MlApplicationImplementation by identifier
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
        ///     var testMlApplicationImplementation = Oci.DataScience.GetMlApplicationImplementation.Invoke(new()
        ///     {
        ///         MlApplicationImplementationId = testMlApplicationImplementationOciDatascienceMlApplicationImplementation.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetMlApplicationImplementationResult> Invoke(GetMlApplicationImplementationInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetMlApplicationImplementationResult>("oci:DataScience/getMlApplicationImplementation:getMlApplicationImplementation", args ?? new GetMlApplicationImplementationInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetMlApplicationImplementationArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// unique MlApplicationImplementation identifier
        /// </summary>
        [Input("mlApplicationImplementationId", required: true)]
        public string MlApplicationImplementationId { get; set; } = null!;

        public GetMlApplicationImplementationArgs()
        {
        }
        public static new GetMlApplicationImplementationArgs Empty => new GetMlApplicationImplementationArgs();
    }

    public sealed class GetMlApplicationImplementationInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// unique MlApplicationImplementation identifier
        /// </summary>
        [Input("mlApplicationImplementationId", required: true)]
        public Input<string> MlApplicationImplementationId { get; set; } = null!;

        public GetMlApplicationImplementationInvokeArgs()
        {
        }
        public static new GetMlApplicationImplementationInvokeArgs Empty => new GetMlApplicationImplementationInvokeArgs();
    }


    [OutputType]
    public sealed class GetMlApplicationImplementationResult
    {
        /// <summary>
        /// List of ML Application Implementation OCIDs for which migration from this implementation is allowed. Migration means that if consumers change implementation for their instances to implementation with OCID from this list, instance components will be updated in place otherwise new instance components are created based on the new implementation and old instance components are removed.
        /// </summary>
        public readonly ImmutableArray<string> AllowedMigrationDestinations;
        /// <summary>
        /// List of application components (OCI resources shared for all MlApplicationInstances). These have been created automatically based on their definitions in the ML Application package.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMlApplicationImplementationApplicationComponentResult> ApplicationComponents;
        /// <summary>
        /// The OCID of the compartment where ML Application Implementation is created.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Schema of configuration which needs to be provided for each ML Application Instance. It is defined in the ML Application package descriptor.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMlApplicationImplementationConfigurationSchemaResult> ConfigurationSchemas;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// short description of the argument
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The OCID of the MlApplicationImplementation. Unique identifier that is immutable after creation.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// Configuration of Logging for ML Application Implementation.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMlApplicationImplementationLoggingResult> Loggings;
        /// <summary>
        /// The OCID of the ML Application implemented by this ML Application Implementation.
        /// </summary>
        public readonly string MlApplicationId;
        public readonly string MlApplicationImplementationId;
        /// <summary>
        /// The name of ML Application (based on mlApplicationId)
        /// </summary>
        public readonly string MlApplicationName;
        public readonly ImmutableDictionary<string, string> MlApplicationPackage;
        /// <summary>
        /// List of ML Application package arguments provided during ML Application package upload.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMlApplicationImplementationMlApplicationPackageArgumentResult> MlApplicationPackageArguments;
        /// <summary>
        /// ML Application Implementation name which is unique for given ML Application.
        /// </summary>
        public readonly string Name;
        public readonly ImmutableDictionary<string, string> OpcMlAppPackageArgs;
        /// <summary>
        /// The version of ML Application Package (e.g. "1.2" or "2.0.4") defined in ML Application package descriptor. Value is not mandatory only for CREATING state otherwise it must be always presented.
        /// </summary>
        public readonly string PackageVersion;
        /// <summary>
        /// The current state of the MlApplicationImplementation.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// Creation time of MlApplicationImplementation creation in the format defined by RFC 3339.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// Time of last MlApplicationImplementation update in the format defined by RFC 3339.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetMlApplicationImplementationResult(
            ImmutableArray<string> allowedMigrationDestinations,

            ImmutableArray<Outputs.GetMlApplicationImplementationApplicationComponentResult> applicationComponents,

            string compartmentId,

            ImmutableArray<Outputs.GetMlApplicationImplementationConfigurationSchemaResult> configurationSchemas,

            ImmutableDictionary<string, string> definedTags,

            string description,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string lifecycleDetails,

            ImmutableArray<Outputs.GetMlApplicationImplementationLoggingResult> loggings,

            string mlApplicationId,

            string mlApplicationImplementationId,

            string mlApplicationName,

            ImmutableDictionary<string, string> mlApplicationPackage,

            ImmutableArray<Outputs.GetMlApplicationImplementationMlApplicationPackageArgumentResult> mlApplicationPackageArguments,

            string name,

            ImmutableDictionary<string, string> opcMlAppPackageArgs,

            string packageVersion,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated)
        {
            AllowedMigrationDestinations = allowedMigrationDestinations;
            ApplicationComponents = applicationComponents;
            CompartmentId = compartmentId;
            ConfigurationSchemas = configurationSchemas;
            DefinedTags = definedTags;
            Description = description;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            Loggings = loggings;
            MlApplicationId = mlApplicationId;
            MlApplicationImplementationId = mlApplicationImplementationId;
            MlApplicationName = mlApplicationName;
            MlApplicationPackage = mlApplicationPackage;
            MlApplicationPackageArguments = mlApplicationPackageArguments;
            Name = name;
            OpcMlAppPackageArgs = opcMlAppPackageArgs;
            PackageVersion = packageVersion;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
