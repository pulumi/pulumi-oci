// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Email
{
    public static class GetSuppression
    {
        /// <summary>
        /// This data source provides details about a specific Suppression resource in Oracle Cloud Infrastructure Email service.
        /// 
        /// Gets the details of a suppressed recipient email address for a given
        /// `suppressionId`. Each suppression is given a unique OCID.
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
        ///     var testSuppression = Oci.Email.GetSuppression.Invoke(new()
        ///     {
        ///         SuppressionId = testSuppressionOciEmailSuppression.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetSuppressionResult> InvokeAsync(GetSuppressionArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetSuppressionResult>("oci:Email/getSuppression:getSuppression", args ?? new GetSuppressionArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Suppression resource in Oracle Cloud Infrastructure Email service.
        /// 
        /// Gets the details of a suppressed recipient email address for a given
        /// `suppressionId`. Each suppression is given a unique OCID.
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
        ///     var testSuppression = Oci.Email.GetSuppression.Invoke(new()
        ///     {
        ///         SuppressionId = testSuppressionOciEmailSuppression.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetSuppressionResult> Invoke(GetSuppressionInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetSuppressionResult>("oci:Email/getSuppression:getSuppression", args ?? new GetSuppressionInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Suppression resource in Oracle Cloud Infrastructure Email service.
        /// 
        /// Gets the details of a suppressed recipient email address for a given
        /// `suppressionId`. Each suppression is given a unique OCID.
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
        ///     var testSuppression = Oci.Email.GetSuppression.Invoke(new()
        ///     {
        ///         SuppressionId = testSuppressionOciEmailSuppression.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetSuppressionResult> Invoke(GetSuppressionInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetSuppressionResult>("oci:Email/getSuppression:getSuppression", args ?? new GetSuppressionInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetSuppressionArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The unique OCID of the suppression.
        /// </summary>
        [Input("suppressionId", required: true)]
        public string SuppressionId { get; set; } = null!;

        public GetSuppressionArgs()
        {
        }
        public static new GetSuppressionArgs Empty => new GetSuppressionArgs();
    }

    public sealed class GetSuppressionInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The unique OCID of the suppression.
        /// </summary>
        [Input("suppressionId", required: true)]
        public Input<string> SuppressionId { get; set; } = null!;

        public GetSuppressionInvokeArgs()
        {
        }
        public static new GetSuppressionInvokeArgs Empty => new GetSuppressionInvokeArgs();
    }


    [OutputType]
    public sealed class GetSuppressionResult
    {
        /// <summary>
        /// The OCID of the compartment to contain the suppression. Since suppressions are at the customer level, this must be the tenancy OCID.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The email address of the suppression.
        /// </summary>
        public readonly string EmailAddress;
        /// <summary>
        /// The specific error message returned by a system that resulted in the suppression. This message is usually an SMTP error code with additional descriptive text. Not provided for all types of suppressions.
        /// </summary>
        public readonly string ErrorDetail;
        /// <summary>
        /// DNS name of the source of the error that caused the suppression. Will be set to either the remote-mta or reporting-mta field from a delivery status notification (RFC 3464) when available. Not provided for all types of suppressions, and not always known.
        /// </summary>
        public readonly string ErrorSource;
        /// <summary>
        /// The unique OCID of the suppression.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The value of the Message-ID header from the email that triggered a suppression. This value is as defined in RFC 5322 section 3.6.4, excluding angle-brackets. Not provided for all types of suppressions.
        /// </summary>
        public readonly string MessageId;
        /// <summary>
        /// The reason that the email address was suppressed. For more information on the types of bounces, see [Suppression List](https://docs.cloud.oracle.com/iaas/Content/Email/Concepts/overview.htm#components).
        /// </summary>
        public readonly string Reason;
        public readonly string SuppressionId;
        /// <summary>
        /// The date and time a recipient's email address was added to the suppression list, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The last date and time the suppression prevented submission in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        public readonly string TimeLastSuppressed;

        [OutputConstructor]
        private GetSuppressionResult(
            string compartmentId,

            string emailAddress,

            string errorDetail,

            string errorSource,

            string id,

            string messageId,

            string reason,

            string suppressionId,

            string timeCreated,

            string timeLastSuppressed)
        {
            CompartmentId = compartmentId;
            EmailAddress = emailAddress;
            ErrorDetail = errorDetail;
            ErrorSource = errorSource;
            Id = id;
            MessageId = messageId;
            Reason = reason;
            SuppressionId = suppressionId;
            TimeCreated = timeCreated;
            TimeLastSuppressed = timeLastSuppressed;
        }
    }
}
