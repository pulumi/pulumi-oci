// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsUserUrnietfparamsscimschemasoracleidcsextensionadaptiveUserArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Risk Level
        /// 
        /// **Added In:** 18.1.6
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: request
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("riskLevel")]
        public Input<string>? RiskLevel { get; set; }

        [Input("riskScores")]
        private InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionadaptiveUserRiskScoreArgs>? _riskScores;

        /// <summary>
        /// (Updatable) The risk score pertaining to the user.
        /// 
        /// **Added In:** 18.1.6
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsCompositeKey: [value]
        /// * multiValued: true
        /// * mutability: readWrite
        /// * required: false
        /// * returned: request
        /// * type: complex
        /// * uniqueness: none
        /// </summary>
        public InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionadaptiveUserRiskScoreArgs> RiskScores
        {
            get => _riskScores ?? (_riskScores = new InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionadaptiveUserRiskScoreArgs>());
            set => _riskScores = value;
        }

        public DomainsUserUrnietfparamsscimschemasoracleidcsextensionadaptiveUserArgs()
        {
        }
        public static new DomainsUserUrnietfparamsscimschemasoracleidcsextensionadaptiveUserArgs Empty => new DomainsUserUrnietfparamsscimschemasoracleidcsextensionadaptiveUserArgs();
    }
}
