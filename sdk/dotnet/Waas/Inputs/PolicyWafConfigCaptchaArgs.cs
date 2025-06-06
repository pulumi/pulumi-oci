// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waas.Inputs
{

    public sealed class PolicyWafConfigCaptchaArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The text to show when incorrect CAPTCHA text is entered. If unspecified, defaults to `The CAPTCHA was incorrect. Try again.`
        /// </summary>
        [Input("failureMessage", required: true)]
        public Input<string> FailureMessage { get; set; } = null!;

        /// <summary>
        /// (Updatable) The text to show in the footer when showing a CAPTCHA challenge. If unspecified, defaults to 'Enter the letters and numbers as they are shown in the image above.'
        /// </summary>
        [Input("footerText")]
        public Input<string>? FooterText { get; set; }

        /// <summary>
        /// (Updatable) The text to show in the header when showing a CAPTCHA challenge. If unspecified, defaults to 'We have detected an increased number of attempts to access this website. To help us keep this site secure, please let us know that you are not a robot by entering the text from the image below.'
        /// </summary>
        [Input("headerText")]
        public Input<string>? HeaderText { get; set; }

        /// <summary>
        /// (Updatable) The amount of time before the CAPTCHA expires, in seconds. If unspecified, defaults to `300`.
        /// </summary>
        [Input("sessionExpirationInSeconds", required: true)]
        public Input<int> SessionExpirationInSeconds { get; set; } = null!;

        /// <summary>
        /// (Updatable) The text to show on the label of the CAPTCHA challenge submit button. If unspecified, defaults to `Yes, I am human`.
        /// </summary>
        [Input("submitLabel", required: true)]
        public Input<string> SubmitLabel { get; set; } = null!;

        /// <summary>
        /// (Updatable) The title used when displaying a CAPTCHA challenge. If unspecified, defaults to `Are you human?`
        /// </summary>
        [Input("title", required: true)]
        public Input<string> Title { get; set; } = null!;

        /// <summary>
        /// (Updatable) The unique URL path at which to show the CAPTCHA challenge.
        /// </summary>
        [Input("url", required: true)]
        public Input<string> Url { get; set; } = null!;

        public PolicyWafConfigCaptchaArgs()
        {
        }
        public static new PolicyWafConfigCaptchaArgs Empty => new PolicyWafConfigCaptchaArgs();
    }
}
