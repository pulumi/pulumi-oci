// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine
{
    public static class GetWorkRequestErrors
    {
        /// <summary>
        /// This data source provides the list of Work Request Errors in Oracle Cloud Infrastructure Container Engine service.
        /// 
        /// Get the errors of a work request.
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
        ///     var testWorkRequestErrors = Oci.ContainerEngine.GetWorkRequestErrors.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         WorkRequestId = oci_containerengine_work_request.Test_work_request.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetWorkRequestErrorsResult> InvokeAsync(GetWorkRequestErrorsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetWorkRequestErrorsResult>("oci:ContainerEngine/getWorkRequestErrors:getWorkRequestErrors", args ?? new GetWorkRequestErrorsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Work Request Errors in Oracle Cloud Infrastructure Container Engine service.
        /// 
        /// Get the errors of a work request.
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
        ///     var testWorkRequestErrors = Oci.ContainerEngine.GetWorkRequestErrors.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         WorkRequestId = oci_containerengine_work_request.Test_work_request.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetWorkRequestErrorsResult> Invoke(GetWorkRequestErrorsInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetWorkRequestErrorsResult>("oci:ContainerEngine/getWorkRequestErrors:getWorkRequestErrors", args ?? new GetWorkRequestErrorsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetWorkRequestErrorsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetWorkRequestErrorsFilterArgs>? _filters;
        public List<Inputs.GetWorkRequestErrorsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetWorkRequestErrorsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The OCID of the work request.
        /// </summary>
        [Input("workRequestId", required: true)]
        public string WorkRequestId { get; set; } = null!;

        public GetWorkRequestErrorsArgs()
        {
        }
        public static new GetWorkRequestErrorsArgs Empty => new GetWorkRequestErrorsArgs();
    }

    public sealed class GetWorkRequestErrorsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("filters")]
        private InputList<Inputs.GetWorkRequestErrorsFilterInputArgs>? _filters;
        public InputList<Inputs.GetWorkRequestErrorsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetWorkRequestErrorsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The OCID of the work request.
        /// </summary>
        [Input("workRequestId", required: true)]
        public Input<string> WorkRequestId { get; set; } = null!;

        public GetWorkRequestErrorsInvokeArgs()
        {
        }
        public static new GetWorkRequestErrorsInvokeArgs Empty => new GetWorkRequestErrorsInvokeArgs();
    }


    [OutputType]
    public sealed class GetWorkRequestErrorsResult
    {
        public readonly string CompartmentId;
        public readonly ImmutableArray<Outputs.GetWorkRequestErrorsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of work_request_errors.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetWorkRequestErrorsWorkRequestErrorResult> WorkRequestErrors;
        public readonly string WorkRequestId;

        [OutputConstructor]
        private GetWorkRequestErrorsResult(
            string compartmentId,

            ImmutableArray<Outputs.GetWorkRequestErrorsFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetWorkRequestErrorsWorkRequestErrorResult> workRequestErrors,

            string workRequestId)
        {
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
            WorkRequestErrors = workRequestErrors;
            WorkRequestId = workRequestId;
        }
    }
}