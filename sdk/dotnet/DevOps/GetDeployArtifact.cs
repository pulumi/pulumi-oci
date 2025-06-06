// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps
{
    public static class GetDeployArtifact
    {
        /// <summary>
        /// This data source provides details about a specific Deploy Artifact resource in Oracle Cloud Infrastructure Devops service.
        /// 
        /// Retrieves a deployment artifact by identifier.
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
        ///     var testDeployArtifact = Oci.DevOps.GetDeployArtifact.Invoke(new()
        ///     {
        ///         DeployArtifactId = testDeployArtifactOciDevopsDeployArtifact.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetDeployArtifactResult> InvokeAsync(GetDeployArtifactArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetDeployArtifactResult>("oci:DevOps/getDeployArtifact:getDeployArtifact", args ?? new GetDeployArtifactArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Deploy Artifact resource in Oracle Cloud Infrastructure Devops service.
        /// 
        /// Retrieves a deployment artifact by identifier.
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
        ///     var testDeployArtifact = Oci.DevOps.GetDeployArtifact.Invoke(new()
        ///     {
        ///         DeployArtifactId = testDeployArtifactOciDevopsDeployArtifact.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDeployArtifactResult> Invoke(GetDeployArtifactInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetDeployArtifactResult>("oci:DevOps/getDeployArtifact:getDeployArtifact", args ?? new GetDeployArtifactInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Deploy Artifact resource in Oracle Cloud Infrastructure Devops service.
        /// 
        /// Retrieves a deployment artifact by identifier.
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
        ///     var testDeployArtifact = Oci.DevOps.GetDeployArtifact.Invoke(new()
        ///     {
        ///         DeployArtifactId = testDeployArtifactOciDevopsDeployArtifact.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDeployArtifactResult> Invoke(GetDeployArtifactInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetDeployArtifactResult>("oci:DevOps/getDeployArtifact:getDeployArtifact", args ?? new GetDeployArtifactInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDeployArtifactArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Unique artifact identifier.
        /// </summary>
        [Input("deployArtifactId", required: true)]
        public string DeployArtifactId { get; set; } = null!;

        public GetDeployArtifactArgs()
        {
        }
        public static new GetDeployArtifactArgs Empty => new GetDeployArtifactArgs();
    }

    public sealed class GetDeployArtifactInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Unique artifact identifier.
        /// </summary>
        [Input("deployArtifactId", required: true)]
        public Input<string> DeployArtifactId { get; set; } = null!;

        public GetDeployArtifactInvokeArgs()
        {
        }
        public static new GetDeployArtifactInvokeArgs Empty => new GetDeployArtifactInvokeArgs();
    }


    [OutputType]
    public sealed class GetDeployArtifactResult
    {
        /// <summary>
        /// Mode for artifact parameter substitution. Options: `"NONE", "SUBSTITUTE_PLACEHOLDERS"` For Helm Deployments only "NONE" is supported.
        /// </summary>
        public readonly string ArgumentSubstitutionMode;
        /// <summary>
        /// The OCID of a compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        public readonly string DeployArtifactId;
        /// <summary>
        /// Specifies source of an artifact.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeployArtifactDeployArtifactSourceResult> DeployArtifactSources;
        /// <summary>
        /// Type of the deployment artifact.
        /// </summary>
        public readonly string DeployArtifactType;
        /// <summary>
        /// Optional description about the artifact to be deployed.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Deployment artifact identifier, which can be renamed and is not necessarily unique. Avoid entering confidential information.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// Unique identifier that is immutable on creation.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A detailed message describing the current state. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The OCID of a project.
        /// </summary>
        public readonly string ProjectId;
        /// <summary>
        /// Current state of the deployment artifact.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// Time the deployment artifact was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// Time the deployment artifact was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetDeployArtifactResult(
            string argumentSubstitutionMode,

            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string deployArtifactId,

            ImmutableArray<Outputs.GetDeployArtifactDeployArtifactSourceResult> deployArtifactSources,

            string deployArtifactType,

            string description,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string lifecycleDetails,

            string projectId,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated)
        {
            ArgumentSubstitutionMode = argumentSubstitutionMode;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DeployArtifactId = deployArtifactId;
            DeployArtifactSources = deployArtifactSources;
            DeployArtifactType = deployArtifactType;
            Description = description;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            ProjectId = projectId;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
