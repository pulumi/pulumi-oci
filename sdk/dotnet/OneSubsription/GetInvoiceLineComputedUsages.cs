// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OneSubsription
{
    public static class GetInvoiceLineComputedUsages
    {
        /// <summary>
        /// This data source provides the list of Invoice Line Computed Usages in Oracle Cloud Infrastructure Onesubscription service.
        /// 
        /// This is a collection API which returns a list of Invoiced Computed Usages for given Invoiceline id.
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
        ///     var testInvoiceLineComputedUsages = Oci.OneSubsription.GetInvoiceLineComputedUsages.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         InvoiceLineId = oci_onesubscription_invoice_line.Test_invoice_line.Id,
        ///         Fields = @var.Invoice_line_computed_usage_fields,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetInvoiceLineComputedUsagesResult> InvokeAsync(GetInvoiceLineComputedUsagesArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetInvoiceLineComputedUsagesResult>("oci:OneSubsription/getInvoiceLineComputedUsages:getInvoiceLineComputedUsages", args ?? new GetInvoiceLineComputedUsagesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Invoice Line Computed Usages in Oracle Cloud Infrastructure Onesubscription service.
        /// 
        /// This is a collection API which returns a list of Invoiced Computed Usages for given Invoiceline id.
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
        ///     var testInvoiceLineComputedUsages = Oci.OneSubsription.GetInvoiceLineComputedUsages.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         InvoiceLineId = oci_onesubscription_invoice_line.Test_invoice_line.Id,
        ///         Fields = @var.Invoice_line_computed_usage_fields,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetInvoiceLineComputedUsagesResult> Invoke(GetInvoiceLineComputedUsagesInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetInvoiceLineComputedUsagesResult>("oci:OneSubsription/getInvoiceLineComputedUsages:getInvoiceLineComputedUsages", args ?? new GetInvoiceLineComputedUsagesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetInvoiceLineComputedUsagesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the root compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("fields")]
        private List<string>? _fields;

        /// <summary>
        /// Partial response refers to an optimization technique offered by the RESTful web APIs to return only the information  (fields) required by the client. This parameter is used to control what fields to return.
        /// </summary>
        public List<string> Fields
        {
            get => _fields ?? (_fields = new List<string>());
            set => _fields = value;
        }

        [Input("filters")]
        private List<Inputs.GetInvoiceLineComputedUsagesFilterArgs>? _filters;
        public List<Inputs.GetInvoiceLineComputedUsagesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetInvoiceLineComputedUsagesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Invoice Line Identifier - Primary Key SPM
        /// </summary>
        [Input("invoiceLineId", required: true)]
        public string InvoiceLineId { get; set; } = null!;

        public GetInvoiceLineComputedUsagesArgs()
        {
        }
        public static new GetInvoiceLineComputedUsagesArgs Empty => new GetInvoiceLineComputedUsagesArgs();
    }

    public sealed class GetInvoiceLineComputedUsagesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the root compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("fields")]
        private InputList<string>? _fields;

        /// <summary>
        /// Partial response refers to an optimization technique offered by the RESTful web APIs to return only the information  (fields) required by the client. This parameter is used to control what fields to return.
        /// </summary>
        public InputList<string> Fields
        {
            get => _fields ?? (_fields = new InputList<string>());
            set => _fields = value;
        }

        [Input("filters")]
        private InputList<Inputs.GetInvoiceLineComputedUsagesFilterInputArgs>? _filters;
        public InputList<Inputs.GetInvoiceLineComputedUsagesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetInvoiceLineComputedUsagesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Invoice Line Identifier - Primary Key SPM
        /// </summary>
        [Input("invoiceLineId", required: true)]
        public Input<string> InvoiceLineId { get; set; } = null!;

        public GetInvoiceLineComputedUsagesInvokeArgs()
        {
        }
        public static new GetInvoiceLineComputedUsagesInvokeArgs Empty => new GetInvoiceLineComputedUsagesInvokeArgs();
    }


    [OutputType]
    public sealed class GetInvoiceLineComputedUsagesResult
    {
        public readonly string CompartmentId;
        public readonly ImmutableArray<string> Fields;
        public readonly ImmutableArray<Outputs.GetInvoiceLineComputedUsagesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string InvoiceLineId;
        /// <summary>
        /// The list of invoiceline_computed_usages.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetInvoiceLineComputedUsagesInvoicelineComputedUsageResult> InvoicelineComputedUsages;

        [OutputConstructor]
        private GetInvoiceLineComputedUsagesResult(
            string compartmentId,

            ImmutableArray<string> fields,

            ImmutableArray<Outputs.GetInvoiceLineComputedUsagesFilterResult> filters,

            string id,

            string invoiceLineId,

            ImmutableArray<Outputs.GetInvoiceLineComputedUsagesInvoicelineComputedUsageResult> invoicelineComputedUsages)
        {
            CompartmentId = compartmentId;
            Fields = fields;
            Filters = filters;
            Id = id;
            InvoiceLineId = invoiceLineId;
            InvoicelineComputedUsages = invoicelineComputedUsages;
        }
    }
}