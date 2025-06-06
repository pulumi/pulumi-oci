// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps
{
    /// <summary>
    /// This resource provides the Deploy Artifact resource in Oracle Cloud Infrastructure Devops service.
    /// 
    /// Creates a new deployment artifact.
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
    ///     var testDeployArtifact = new Oci.DevOps.DeployArtifact("test_deploy_artifact", new()
    ///     {
    ///         ArgumentSubstitutionMode = deployArtifactArgumentSubstitutionMode,
    ///         DeployArtifactSource = new Oci.DevOps.Inputs.DeployArtifactDeployArtifactSourceArgs
    ///         {
    ///             DeployArtifactSourceType = deployArtifactDeployArtifactSourceDeployArtifactSourceType,
    ///             Base64encodedContent = deployArtifactDeployArtifactSourceBase64encodedContent,
    ///             ChartUrl = deployArtifactDeployArtifactSourceChartUrl,
    ///             DeployArtifactPath = deployArtifactDeployArtifactSourceDeployArtifactPath,
    ///             DeployArtifactVersion = deployArtifactDeployArtifactSourceDeployArtifactVersion,
    ///             HelmArtifactSourceType = deployArtifactDeployArtifactSourceHelmArtifactSourceType,
    ///             HelmVerificationKeySource = new Oci.DevOps.Inputs.DeployArtifactDeployArtifactSourceHelmVerificationKeySourceArgs
    ///             {
    ///                 VerificationKeySourceType = deployArtifactDeployArtifactSourceHelmVerificationKeySourceVerificationKeySourceType,
    ///                 CurrentPublicKey = deployArtifactDeployArtifactSourceHelmVerificationKeySourceCurrentPublicKey,
    ///                 PreviousPublicKey = deployArtifactDeployArtifactSourceHelmVerificationKeySourcePreviousPublicKey,
    ///                 VaultSecretId = testSecret.Id,
    ///             },
    ///             ImageDigest = deployArtifactDeployArtifactSourceImageDigest,
    ///             ImageUri = deployArtifactDeployArtifactSourceImageUri,
    ///             RepositoryId = testRepository.Id,
    ///         },
    ///         DeployArtifactType = deployArtifactDeployArtifactType,
    ///         ProjectId = testProject.Id,
    ///         DefinedTags = 
    ///         {
    ///             { "foo-namespace.bar-key", "value" },
    ///         },
    ///         Description = deployArtifactDescription,
    ///         DisplayName = deployArtifactDisplayName,
    ///         FreeformTags = 
    ///         {
    ///             { "bar-key", "value" },
    ///         },
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// DeployArtifacts can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:DevOps/deployArtifact:DeployArtifact test_deploy_artifact "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:DevOps/deployArtifact:DeployArtifact")]
    public partial class DeployArtifact : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) Mode for artifact parameter substitution. Options: `"NONE", "SUBSTITUTE_PLACEHOLDERS"` For Helm Deployments only "NONE" is supported.
        /// </summary>
        [Output("argumentSubstitutionMode")]
        public Output<string> ArgumentSubstitutionMode { get; private set; } = null!;

        /// <summary>
        /// The OCID of a compartment.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Specifies source of an artifact.
        /// </summary>
        [Output("deployArtifactSource")]
        public Output<Outputs.DeployArtifactDeployArtifactSource> DeployArtifactSource { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Type of the deployment artifact.
        /// </summary>
        [Output("deployArtifactType")]
        public Output<string> DeployArtifactType { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Optional description about the deployment artifact.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Deployment artifact display name. Avoid entering confidential information.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// A detailed message describing the current state. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// The OCID of a project.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("projectId")]
        public Output<string> ProjectId { get; private set; } = null!;

        /// <summary>
        /// Current state of the deployment artifact.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, string>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// Time the deployment artifact was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// Time the deployment artifact was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a DeployArtifact resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public DeployArtifact(string name, DeployArtifactArgs args, CustomResourceOptions? options = null)
            : base("oci:DevOps/deployArtifact:DeployArtifact", name, args ?? new DeployArtifactArgs(), MakeResourceOptions(options, ""))
        {
        }

        private DeployArtifact(string name, Input<string> id, DeployArtifactState? state = null, CustomResourceOptions? options = null)
            : base("oci:DevOps/deployArtifact:DeployArtifact", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing DeployArtifact resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static DeployArtifact Get(string name, Input<string> id, DeployArtifactState? state = null, CustomResourceOptions? options = null)
        {
            return new DeployArtifact(name, id, state, options);
        }
    }

    public sealed class DeployArtifactArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Mode for artifact parameter substitution. Options: `"NONE", "SUBSTITUTE_PLACEHOLDERS"` For Helm Deployments only "NONE" is supported.
        /// </summary>
        [Input("argumentSubstitutionMode", required: true)]
        public Input<string> ArgumentSubstitutionMode { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Specifies source of an artifact.
        /// </summary>
        [Input("deployArtifactSource", required: true)]
        public Input<Inputs.DeployArtifactDeployArtifactSourceArgs> DeployArtifactSource { get; set; } = null!;

        /// <summary>
        /// (Updatable) Type of the deployment artifact.
        /// </summary>
        [Input("deployArtifactType", required: true)]
        public Input<string> DeployArtifactType { get; set; } = null!;

        /// <summary>
        /// (Updatable) Optional description about the deployment artifact.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) Deployment artifact display name. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// The OCID of a project.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("projectId", required: true)]
        public Input<string> ProjectId { get; set; } = null!;

        public DeployArtifactArgs()
        {
        }
        public static new DeployArtifactArgs Empty => new DeployArtifactArgs();
    }

    public sealed class DeployArtifactState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Mode for artifact parameter substitution. Options: `"NONE", "SUBSTITUTE_PLACEHOLDERS"` For Helm Deployments only "NONE" is supported.
        /// </summary>
        [Input("argumentSubstitutionMode")]
        public Input<string>? ArgumentSubstitutionMode { get; set; }

        /// <summary>
        /// The OCID of a compartment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Specifies source of an artifact.
        /// </summary>
        [Input("deployArtifactSource")]
        public Input<Inputs.DeployArtifactDeployArtifactSourceGetArgs>? DeployArtifactSource { get; set; }

        /// <summary>
        /// (Updatable) Type of the deployment artifact.
        /// </summary>
        [Input("deployArtifactType")]
        public Input<string>? DeployArtifactType { get; set; }

        /// <summary>
        /// (Updatable) Optional description about the deployment artifact.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) Deployment artifact display name. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// A detailed message describing the current state. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// The OCID of a project.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("projectId")]
        public Input<string>? ProjectId { get; set; }

        /// <summary>
        /// Current state of the deployment artifact.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        [Input("systemTags")]
        private InputMap<string>? _systemTags;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public InputMap<string> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<string>());
            set => _systemTags = value;
        }

        /// <summary>
        /// Time the deployment artifact was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// Time the deployment artifact was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public DeployArtifactState()
        {
        }
        public static new DeployArtifactState Empty => new DeployArtifactState();
    }
}
