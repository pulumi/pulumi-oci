// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waas.Outputs
{

    [OutputType]
    public sealed class GetWaasPoliciesWaasPolicyWafConfigJsChallengeChallengeSettingResult
    {
        /// <summary>
        /// If `action` is set to `BLOCK`, this specifies how the traffic is blocked when detected as malicious by a protection rule. If unspecified, defaults to `SET_RESPONSE_CODE`.
        /// </summary>
        public readonly string BlockAction;
        /// <summary>
        /// The error code to show on the error page when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_ERROR_PAGE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to `403`.
        /// </summary>
        public readonly string BlockErrorPageCode;
        /// <summary>
        /// The description text to show on the error page when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_ERROR_PAGE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to `Access blocked by website owner. Please contact support.`
        /// </summary>
        public readonly string BlockErrorPageDescription;
        /// <summary>
        /// The message to show on the error page when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_ERROR_PAGE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to 'Access to the website is blocked.'
        /// </summary>
        public readonly string BlockErrorPageMessage;
        /// <summary>
        /// The response code returned when `action` is set to `BLOCK`, `blockAction` is set to `SET_RESPONSE_CODE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to `403`. The list of available response codes: `400`, `401`, `403`, `405`, `409`, `411`, `412`, `413`, `414`, `415`, `416`, `500`, `501`, `502`, `503`, `504`, `507`.
        /// </summary>
        public readonly int BlockResponseCode;
        /// <summary>
        /// The text to show in the footer when showing a CAPTCHA challenge when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_CAPTCHA`, and the request is blocked. If unspecified, default to `Enter the letters and numbers as they are shown in image above`.
        /// </summary>
        public readonly string CaptchaFooter;
        /// <summary>
        /// The text to show in the header when showing a CAPTCHA challenge when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_CAPTCHA`, and the request is blocked. If unspecified, defaults to `We have detected an increased number of attempts to access this webapp. To help us keep this webapp secure, please let us know that you are not a robot by entering the text from captcha below.`
        /// </summary>
        public readonly string CaptchaHeader;
        /// <summary>
        /// The text to show on the label of the CAPTCHA challenge submit button when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_CAPTCHA`, and the request is blocked. If unspecified, defaults to `Yes, I am human`.
        /// </summary>
        public readonly string CaptchaSubmitLabel;
        /// <summary>
        /// The title used when showing a CAPTCHA challenge when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_CAPTCHA`, and the request is blocked. If unspecified, defaults to `Are you human?`
        /// </summary>
        public readonly string CaptchaTitle;

        [OutputConstructor]
        private GetWaasPoliciesWaasPolicyWafConfigJsChallengeChallengeSettingResult(
            string blockAction,

            string blockErrorPageCode,

            string blockErrorPageDescription,

            string blockErrorPageMessage,

            int blockResponseCode,

            string captchaFooter,

            string captchaHeader,

            string captchaSubmitLabel,

            string captchaTitle)
        {
            BlockAction = blockAction;
            BlockErrorPageCode = blockErrorPageCode;
            BlockErrorPageDescription = blockErrorPageDescription;
            BlockErrorPageMessage = blockErrorPageMessage;
            BlockResponseCode = blockResponseCode;
            CaptchaFooter = captchaFooter;
            CaptchaHeader = captchaHeader;
            CaptchaSubmitLabel = captchaSubmitLabel;
            CaptchaTitle = captchaTitle;
        }
    }
}
