// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps
{
    public static class GetRepositoryObject
    {
        /// <summary>
        /// This data source provides details about a specific Repository Object resource in Oracle Cloud Infrastructure Devops service.
        /// 
        /// Retrieves blob of specific branch name/commit ID and file path.
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
        ///     var testRepositoryObject = Oci.DevOps.GetRepositoryObject.Invoke(new()
        ///     {
        ///         RepositoryId = oci_devops_repository.Test_repository.Id,
        ///         FilePath = @var.Repository_object_file_path,
        ///         RefName = @var.Repository_object_ref_name,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetRepositoryObjectResult> InvokeAsync(GetRepositoryObjectArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetRepositoryObjectResult>("oci:DevOps/getRepositoryObject:getRepositoryObject", args ?? new GetRepositoryObjectArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Repository Object resource in Oracle Cloud Infrastructure Devops service.
        /// 
        /// Retrieves blob of specific branch name/commit ID and file path.
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
        ///     var testRepositoryObject = Oci.DevOps.GetRepositoryObject.Invoke(new()
        ///     {
        ///         RepositoryId = oci_devops_repository.Test_repository.Id,
        ///         FilePath = @var.Repository_object_file_path,
        ///         RefName = @var.Repository_object_ref_name,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetRepositoryObjectResult> Invoke(GetRepositoryObjectInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetRepositoryObjectResult>("oci:DevOps/getRepositoryObject:getRepositoryObject", args ?? new GetRepositoryObjectInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetRepositoryObjectArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// A filter to return only commits that affect any of the specified paths.
        /// </summary>
        [Input("filePath")]
        public string? FilePath { get; set; }

        /// <summary>
        /// A filter to return only resources that match the given reference name.
        /// </summary>
        [Input("refName")]
        public string? RefName { get; set; }

        /// <summary>
        /// Unique repository identifier.
        /// </summary>
        [Input("repositoryId", required: true)]
        public string RepositoryId { get; set; } = null!;

        public GetRepositoryObjectArgs()
        {
        }
        public static new GetRepositoryObjectArgs Empty => new GetRepositoryObjectArgs();
    }

    public sealed class GetRepositoryObjectInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// A filter to return only commits that affect any of the specified paths.
        /// </summary>
        [Input("filePath")]
        public Input<string>? FilePath { get; set; }

        /// <summary>
        /// A filter to return only resources that match the given reference name.
        /// </summary>
        [Input("refName")]
        public Input<string>? RefName { get; set; }

        /// <summary>
        /// Unique repository identifier.
        /// </summary>
        [Input("repositoryId", required: true)]
        public Input<string> RepositoryId { get; set; } = null!;

        public GetRepositoryObjectInvokeArgs()
        {
        }
        public static new GetRepositoryObjectInvokeArgs Empty => new GetRepositoryObjectInvokeArgs();
    }


    [OutputType]
    public sealed class GetRepositoryObjectResult
    {
        public readonly string? FilePath;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Flag to determine if the object contains binary file content or not.
        /// </summary>
        public readonly bool IsBinary;
        public readonly string? RefName;
        public readonly string RepositoryId;
        /// <summary>
        /// SHA-1 hash of git object.
        /// </summary>
        public readonly string Sha;
        /// <summary>
        /// Size in bytes.
        /// </summary>
        public readonly string SizeInBytes;
        /// <summary>
        /// The type of git object.
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private GetRepositoryObjectResult(
            string? filePath,

            string id,

            bool isBinary,

            string? refName,

            string repositoryId,

            string sha,

            string sizeInBytes,

            string type)
        {
            FilePath = filePath;
            Id = id;
            IsBinary = isBinary;
            RefName = refName;
            RepositoryId = repositoryId;
            Sha = sha;
            SizeInBytes = sizeInBytes;
            Type = type;
        }
    }
}