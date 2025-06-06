// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsUserUrnietfparamsscimschemasoracleidcsextensionadaptiveUserGetArgs : global::Pulumi.ResourceArgs
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
        private InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionadaptiveUserRiskScoreGetArgs>? _riskScores;

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
        public InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionadaptiveUserRiskScoreGetArgs> RiskScores
        {
            get => _riskScores ?? (_riskScores = new InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionadaptiveUserRiskScoreGetArgs>());
            set => _riskScores = value;
        }

        public DomainsUserUrnietfparamsscimschemasoracleidcsextensionadaptiveUserGetArgs()
        {
        }
        public static new DomainsUserUrnietfparamsscimschemasoracleidcsextensionadaptiveUserGetArgs Empty => new DomainsUserUrnietfparamsscimschemasoracleidcsextensionadaptiveUserGetArgs();
    }
}
