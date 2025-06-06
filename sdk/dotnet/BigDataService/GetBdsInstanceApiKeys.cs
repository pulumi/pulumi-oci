// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.BigDataService
{
    public static class GetBdsInstanceApiKeys
    {
        /// <summary>
        /// This data source provides details about a specific Bds Instance Api Key resource in Oracle Cloud Infrastructure Big Data Service service.
        /// 
        /// Returns the user's API key information for the given ID.
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
        ///     var testBdsInstanceApiKey = Oci.BigDataService.GetBdsInstanceApiKey.Invoke(new()
        ///     {
        ///         ApiKeyId = testApiKey.Id,
        ///         BdsInstanceId = testBdsInstance.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetBdsInstanceApiKeysResult> InvokeAsync(GetBdsInstanceApiKeysArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetBdsInstanceApiKeysResult>("oci:BigDataService/getBdsInstanceApiKeys:getBdsInstanceApiKeys", args ?? new GetBdsInstanceApiKeysArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Bds Instance Api Key resource in Oracle Cloud Infrastructure Big Data Service service.
        /// 
        /// Returns the user's API key information for the given ID.
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
        ///     var testBdsInstanceApiKey = Oci.BigDataService.GetBdsInstanceApiKey.Invoke(new()
        ///     {
        ///         ApiKeyId = testApiKey.Id,
        ///         BdsInstanceId = testBdsInstance.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetBdsInstanceApiKeysResult> Invoke(GetBdsInstanceApiKeysInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetBdsInstanceApiKeysResult>("oci:BigDataService/getBdsInstanceApiKeys:getBdsInstanceApiKeys", args ?? new GetBdsInstanceApiKeysInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Bds Instance Api Key resource in Oracle Cloud Infrastructure Big Data Service service.
        /// 
        /// Returns the user's API key information for the given ID.
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
        ///     var testBdsInstanceApiKey = Oci.BigDataService.GetBdsInstanceApiKey.Invoke(new()
        ///     {
        ///         ApiKeyId = testApiKey.Id,
        ///         BdsInstanceId = testBdsInstance.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetBdsInstanceApiKeysResult> Invoke(GetBdsInstanceApiKeysInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetBdsInstanceApiKeysResult>("oci:BigDataService/getBdsInstanceApiKeys:getBdsInstanceApiKeys", args ?? new GetBdsInstanceApiKeysInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetBdsInstanceApiKeysArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the cluster.
        /// </summary>
        [Input("bdsInstanceId", required: true)]
        public string BdsInstanceId { get; set; } = null!;

        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetBdsInstanceApiKeysFilterArgs>? _filters;
        public List<Inputs.GetBdsInstanceApiKeysFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetBdsInstanceApiKeysFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The current status of the API key.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        /// <summary>
        /// The user OCID for which this API key was created.
        /// </summary>
        [Input("userId")]
        public string? UserId { get; set; }

        public GetBdsInstanceApiKeysArgs()
        {
        }
        public static new GetBdsInstanceApiKeysArgs Empty => new GetBdsInstanceApiKeysArgs();
    }

    public sealed class GetBdsInstanceApiKeysInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the cluster.
        /// </summary>
        [Input("bdsInstanceId", required: true)]
        public Input<string> BdsInstanceId { get; set; } = null!;

        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetBdsInstanceApiKeysFilterInputArgs>? _filters;
        public InputList<Inputs.GetBdsInstanceApiKeysFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetBdsInstanceApiKeysFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The current status of the API key.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The user OCID for which this API key was created.
        /// </summary>
        [Input("userId")]
        public Input<string>? UserId { get; set; }

        public GetBdsInstanceApiKeysInvokeArgs()
        {
        }
        public static new GetBdsInstanceApiKeysInvokeArgs Empty => new GetBdsInstanceApiKeysInvokeArgs();
    }


    [OutputType]
    public sealed class GetBdsInstanceApiKeysResult
    {
        /// <summary>
        /// The list of bds_api_keys.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBdsInstanceApiKeysBdsApiKeyResult> BdsApiKeys;
        public readonly string BdsInstanceId;
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetBdsInstanceApiKeysFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The current status of the API key.
        /// </summary>
        public readonly string? State;
        /// <summary>
        /// The user OCID for which this API key was created.
        /// </summary>
        public readonly string? UserId;

        [OutputConstructor]
        private GetBdsInstanceApiKeysResult(
            ImmutableArray<Outputs.GetBdsInstanceApiKeysBdsApiKeyResult> bdsApiKeys,

            string bdsInstanceId,

            string? displayName,

            ImmutableArray<Outputs.GetBdsInstanceApiKeysFilterResult> filters,

            string id,

            string? state,

            string? userId)
        {
            BdsApiKeys = bdsApiKeys;
            BdsInstanceId = bdsInstanceId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            State = state;
            UserId = userId;
        }
    }
}
