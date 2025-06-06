// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Apm
{
    public static class GetDataKeys
    {
        /// <summary>
        /// This data source provides the list of Data Keys in Oracle Cloud Infrastructure Apm service.
        /// 
        /// Lists all Data Keys for the specified APM domain. The caller may filter the list by specifying the 'dataKeyType'
        /// query parameter.
        /// 
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
        ///     var testDataKeys = Oci.Apm.GetDataKeys.Invoke(new()
        ///     {
        ///         ApmDomainId = testApmDomain.Id,
        ///         DataKeyType = dataKeyDataKeyType,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetDataKeysResult> InvokeAsync(GetDataKeysArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetDataKeysResult>("oci:Apm/getDataKeys:getDataKeys", args ?? new GetDataKeysArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Data Keys in Oracle Cloud Infrastructure Apm service.
        /// 
        /// Lists all Data Keys for the specified APM domain. The caller may filter the list by specifying the 'dataKeyType'
        /// query parameter.
        /// 
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
        ///     var testDataKeys = Oci.Apm.GetDataKeys.Invoke(new()
        ///     {
        ///         ApmDomainId = testApmDomain.Id,
        ///         DataKeyType = dataKeyDataKeyType,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDataKeysResult> Invoke(GetDataKeysInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetDataKeysResult>("oci:Apm/getDataKeys:getDataKeys", args ?? new GetDataKeysInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Data Keys in Oracle Cloud Infrastructure Apm service.
        /// 
        /// Lists all Data Keys for the specified APM domain. The caller may filter the list by specifying the 'dataKeyType'
        /// query parameter.
        /// 
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
        ///     var testDataKeys = Oci.Apm.GetDataKeys.Invoke(new()
        ///     {
        ///         ApmDomainId = testApmDomain.Id,
        ///         DataKeyType = dataKeyDataKeyType,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDataKeysResult> Invoke(GetDataKeysInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetDataKeysResult>("oci:Apm/getDataKeys:getDataKeys", args ?? new GetDataKeysInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDataKeysArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the APM domain
        /// </summary>
        [Input("apmDomainId", required: true)]
        public string ApmDomainId { get; set; } = null!;

        /// <summary>
        /// Data key type.
        /// </summary>
        [Input("dataKeyType")]
        public string? DataKeyType { get; set; }

        [Input("filters")]
        private List<Inputs.GetDataKeysFilterArgs>? _filters;
        public List<Inputs.GetDataKeysFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetDataKeysFilterArgs>());
            set => _filters = value;
        }

        public GetDataKeysArgs()
        {
        }
        public static new GetDataKeysArgs Empty => new GetDataKeysArgs();
    }

    public sealed class GetDataKeysInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the APM domain
        /// </summary>
        [Input("apmDomainId", required: true)]
        public Input<string> ApmDomainId { get; set; } = null!;

        /// <summary>
        /// Data key type.
        /// </summary>
        [Input("dataKeyType")]
        public Input<string>? DataKeyType { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetDataKeysFilterInputArgs>? _filters;
        public InputList<Inputs.GetDataKeysFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetDataKeysFilterInputArgs>());
            set => _filters = value;
        }

        public GetDataKeysInvokeArgs()
        {
        }
        public static new GetDataKeysInvokeArgs Empty => new GetDataKeysInvokeArgs();
    }


    [OutputType]
    public sealed class GetDataKeysResult
    {
        public readonly string ApmDomainId;
        public readonly string? DataKeyType;
        /// <summary>
        /// The list of data_keys.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDataKeysDataKeyResult> DataKeys;
        public readonly ImmutableArray<Outputs.GetDataKeysFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;

        [OutputConstructor]
        private GetDataKeysResult(
            string apmDomainId,

            string? dataKeyType,

            ImmutableArray<Outputs.GetDataKeysDataKeyResult> dataKeys,

            ImmutableArray<Outputs.GetDataKeysFilterResult> filters,

            string id)
        {
            ApmDomainId = apmDomainId;
            DataKeyType = dataKeyType;
            DataKeys = dataKeys;
            Filters = filters;
            Id = id;
        }
    }
}
