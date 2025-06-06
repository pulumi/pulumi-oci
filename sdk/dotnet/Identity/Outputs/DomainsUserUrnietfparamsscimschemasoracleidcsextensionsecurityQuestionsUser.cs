// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Outputs
{

    [OutputType]
    public sealed class DomainsUserUrnietfparamsscimschemasoracleidcsextensionsecurityQuestionsUser
    {
        /// <summary>
        /// (Updatable) The schema used to mnage security question and answers provided by a user for account recovery and/or MFA. While setting up security questions, a user can also provide a hint for the answer.
        /// 
        /// **SCIM++ Properties:**
        /// * idcsCompositeKey: [value]
        /// * multiValued: true
        /// * mutability: readWrite
        /// * required: false
        /// * returned: request
        /// * type: complex
        /// * uniqueness: none
        /// </summary>
        public readonly ImmutableArray<Outputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionsecurityQuestionsUserSecQuestion> SecQuestions;

        [OutputConstructor]
        private DomainsUserUrnietfparamsscimschemasoracleidcsextensionsecurityQuestionsUser(ImmutableArray<Outputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionsecurityQuestionsUserSecQuestion> secQuestions)
        {
            SecQuestions = secQuestions;
        }
    }
}
