// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.MediaServices
{
    public static class GetMediaWorkflowTaskDeclaration
    {
        /// <summary>
        /// This data source provides details about a specific Media Workflow Task Declaration resource in Oracle Cloud Infrastructure Media Services service.
        /// 
        /// Returns a list of MediaWorkflowTaskDeclarations.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testMediaWorkflowTaskDeclaration = Oci.MediaServices.GetMediaWorkflowTaskDeclaration.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         IsCurrent = @var.Media_workflow_task_declaration_is_current,
        ///         Name = @var.Media_workflow_task_declaration_name,
        ///         Version = @var.Media_workflow_task_declaration_version,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetMediaWorkflowTaskDeclarationResult> InvokeAsync(GetMediaWorkflowTaskDeclarationArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetMediaWorkflowTaskDeclarationResult>("oci:MediaServices/getMediaWorkflowTaskDeclaration:getMediaWorkflowTaskDeclaration", args ?? new GetMediaWorkflowTaskDeclarationArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Media Workflow Task Declaration resource in Oracle Cloud Infrastructure Media Services service.
        /// 
        /// Returns a list of MediaWorkflowTaskDeclarations.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testMediaWorkflowTaskDeclaration = Oci.MediaServices.GetMediaWorkflowTaskDeclaration.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         IsCurrent = @var.Media_workflow_task_declaration_is_current,
        ///         Name = @var.Media_workflow_task_declaration_name,
        ///         Version = @var.Media_workflow_task_declaration_version,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetMediaWorkflowTaskDeclarationResult> Invoke(GetMediaWorkflowTaskDeclarationInvokeArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetMediaWorkflowTaskDeclarationResult>("oci:MediaServices/getMediaWorkflowTaskDeclaration:getMediaWorkflowTaskDeclaration", args ?? new GetMediaWorkflowTaskDeclarationInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetMediaWorkflowTaskDeclarationArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId")]
        public string? CompartmentId { get; set; }

        /// <summary>
        /// A filter to only select the newest version for each MediaWorkflowTaskDeclaration name.
        /// </summary>
        [Input("isCurrent")]
        public bool? IsCurrent { get; set; }

        /// <summary>
        /// A filter to return only the resources with their system defined, unique name matching the given name.
        /// </summary>
        [Input("name")]
        public string? Name { get; set; }

        /// <summary>
        /// A filter to select MediaWorkflowTaskDeclaration by version.
        /// </summary>
        [Input("version")]
        public int? Version { get; set; }

        public GetMediaWorkflowTaskDeclarationArgs()
        {
        }
        public static new GetMediaWorkflowTaskDeclarationArgs Empty => new GetMediaWorkflowTaskDeclarationArgs();
    }

    public sealed class GetMediaWorkflowTaskDeclarationInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// A filter to only select the newest version for each MediaWorkflowTaskDeclaration name.
        /// </summary>
        [Input("isCurrent")]
        public Input<bool>? IsCurrent { get; set; }

        /// <summary>
        /// A filter to return only the resources with their system defined, unique name matching the given name.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// A filter to select MediaWorkflowTaskDeclaration by version.
        /// </summary>
        [Input("version")]
        public Input<int>? Version { get; set; }

        public GetMediaWorkflowTaskDeclarationInvokeArgs()
        {
        }
        public static new GetMediaWorkflowTaskDeclarationInvokeArgs Empty => new GetMediaWorkflowTaskDeclarationInvokeArgs();
    }


    [OutputType]
    public sealed class GetMediaWorkflowTaskDeclarationResult
    {
        public readonly string? CompartmentId;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly bool? IsCurrent;
        /// <summary>
        /// List of MediaWorkflowTaskDeclaration objects.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMediaWorkflowTaskDeclarationItemResult> Items;
        /// <summary>
        /// MediaWorkflowTaskDeclaration identifier. The name and version should be unique among MediaWorkflowTaskDeclarations.
        /// </summary>
        public readonly string? Name;
        /// <summary>
        /// The version of MediaWorkflowTaskDeclaration, incremented whenever the team implementing the task processor modifies the JSON schema of this declaration's definitions, parameters or list of required parameters.
        /// </summary>
        public readonly int? Version;

        [OutputConstructor]
        private GetMediaWorkflowTaskDeclarationResult(
            string? compartmentId,

            string id,

            bool? isCurrent,

            ImmutableArray<Outputs.GetMediaWorkflowTaskDeclarationItemResult> items,

            string? name,

            int? version)
        {
            CompartmentId = compartmentId;
            Id = id;
            IsCurrent = isCurrent;
            Items = items;
            Name = name;
            Version = version;
        }
    }
}