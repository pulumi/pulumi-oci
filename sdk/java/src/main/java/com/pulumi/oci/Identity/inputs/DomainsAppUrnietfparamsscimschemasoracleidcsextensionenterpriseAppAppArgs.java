// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Identity.inputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppAppAllowAuthzPolicyArgs;
import com.pulumi.oci.Identity.inputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppAppAppResourceArgs;
import com.pulumi.oci.Identity.inputs.DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppAppDenyAuthzPolicyArgs;
import java.lang.Integer;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppAppArgs extends com.pulumi.resources.ResourceArgs {

    public static final DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppAppArgs Empty = new DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppAppArgs();

    /**
     * (Updatable) Allow Authz policy decision expiry time in seconds.
     * 
     * **Added In:** 19.2.1
     * 
     * **SCIM++ Properties:**
     * * idcsMaxValue: 3600
     * * idcsMinValue: 0
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: integer
     * * uniqueness: none
     * 
     */
    @Import(name="allowAuthzDecisionTtl")
    private @Nullable Output<Integer> allowAuthzDecisionTtl;

    /**
     * @return (Updatable) Allow Authz policy decision expiry time in seconds.
     * 
     * **Added In:** 19.2.1
     * 
     * **SCIM++ Properties:**
     * * idcsMaxValue: 3600
     * * idcsMinValue: 0
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: integer
     * * uniqueness: none
     * 
     */
    public Optional<Output<Integer>> allowAuthzDecisionTtl() {
        return Optional.ofNullable(this.allowAuthzDecisionTtl);
    }

    /**
     * (Updatable) Allow Authz Policy.
     * 
     * **Added In:** 19.2.1
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: complex
     * 
     */
    @Import(name="allowAuthzPolicy")
    private @Nullable Output<DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppAppAllowAuthzPolicyArgs> allowAuthzPolicy;

    /**
     * @return (Updatable) Allow Authz Policy.
     * 
     * **Added In:** 19.2.1
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: complex
     * 
     */
    public Optional<Output<DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppAppAllowAuthzPolicyArgs>> allowAuthzPolicy() {
        return Optional.ofNullable(this.allowAuthzPolicy);
    }

    /**
     * (Updatable) A list of AppResources of this App.
     * 
     * **Added In:** 19.2.1
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsCompositeKey: [value]
     * * idcsSearchable: true
     * * multiValued: true
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: complex
     * 
     */
    @Import(name="appResources")
    private @Nullable Output<List<DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppAppAppResourceArgs>> appResources;

    /**
     * @return (Updatable) A list of AppResources of this App.
     * 
     * **Added In:** 19.2.1
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsCompositeKey: [value]
     * * idcsSearchable: true
     * * multiValued: true
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: complex
     * 
     */
    public Optional<Output<List<DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppAppAppResourceArgs>>> appResources() {
        return Optional.ofNullable(this.appResources);
    }

    /**
     * (Updatable) Deny Authz policy decision expiry time in seconds.
     * 
     * **Added In:** 19.2.1
     * 
     * **SCIM++ Properties:**
     * * idcsMaxValue: 3600
     * * idcsMinValue: 0
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: integer
     * * uniqueness: none
     * 
     */
    @Import(name="denyAuthzDecisionTtl")
    private @Nullable Output<Integer> denyAuthzDecisionTtl;

    /**
     * @return (Updatable) Deny Authz policy decision expiry time in seconds.
     * 
     * **Added In:** 19.2.1
     * 
     * **SCIM++ Properties:**
     * * idcsMaxValue: 3600
     * * idcsMinValue: 0
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: integer
     * * uniqueness: none
     * 
     */
    public Optional<Output<Integer>> denyAuthzDecisionTtl() {
        return Optional.ofNullable(this.denyAuthzDecisionTtl);
    }

    /**
     * (Updatable) Deny Authz Policy.
     * 
     * **Added In:** 19.2.1
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: complex
     * 
     */
    @Import(name="denyAuthzPolicy")
    private @Nullable Output<DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppAppDenyAuthzPolicyArgs> denyAuthzPolicy;

    /**
     * @return (Updatable) Deny Authz Policy.
     * 
     * **Added In:** 19.2.1
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: complex
     * 
     */
    public Optional<Output<DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppAppDenyAuthzPolicyArgs>> denyAuthzPolicy() {
        return Optional.ofNullable(this.denyAuthzPolicy);
    }

    private DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppAppArgs() {}

    private DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppAppArgs(DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppAppArgs $) {
        this.allowAuthzDecisionTtl = $.allowAuthzDecisionTtl;
        this.allowAuthzPolicy = $.allowAuthzPolicy;
        this.appResources = $.appResources;
        this.denyAuthzDecisionTtl = $.denyAuthzDecisionTtl;
        this.denyAuthzPolicy = $.denyAuthzPolicy;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppAppArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppAppArgs $;

        public Builder() {
            $ = new DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppAppArgs();
        }

        public Builder(DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppAppArgs defaults) {
            $ = new DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppAppArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param allowAuthzDecisionTtl (Updatable) Allow Authz policy decision expiry time in seconds.
         * 
         * **Added In:** 19.2.1
         * 
         * **SCIM++ Properties:**
         * * idcsMaxValue: 3600
         * * idcsMinValue: 0
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: integer
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder allowAuthzDecisionTtl(@Nullable Output<Integer> allowAuthzDecisionTtl) {
            $.allowAuthzDecisionTtl = allowAuthzDecisionTtl;
            return this;
        }

        /**
         * @param allowAuthzDecisionTtl (Updatable) Allow Authz policy decision expiry time in seconds.
         * 
         * **Added In:** 19.2.1
         * 
         * **SCIM++ Properties:**
         * * idcsMaxValue: 3600
         * * idcsMinValue: 0
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: integer
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder allowAuthzDecisionTtl(Integer allowAuthzDecisionTtl) {
            return allowAuthzDecisionTtl(Output.of(allowAuthzDecisionTtl));
        }

        /**
         * @param allowAuthzPolicy (Updatable) Allow Authz Policy.
         * 
         * **Added In:** 19.2.1
         * 
         * **SCIM++ Properties:**
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: complex
         * 
         * @return builder
         * 
         */
        public Builder allowAuthzPolicy(@Nullable Output<DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppAppAllowAuthzPolicyArgs> allowAuthzPolicy) {
            $.allowAuthzPolicy = allowAuthzPolicy;
            return this;
        }

        /**
         * @param allowAuthzPolicy (Updatable) Allow Authz Policy.
         * 
         * **Added In:** 19.2.1
         * 
         * **SCIM++ Properties:**
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: complex
         * 
         * @return builder
         * 
         */
        public Builder allowAuthzPolicy(DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppAppAllowAuthzPolicyArgs allowAuthzPolicy) {
            return allowAuthzPolicy(Output.of(allowAuthzPolicy));
        }

        /**
         * @param appResources (Updatable) A list of AppResources of this App.
         * 
         * **Added In:** 19.2.1
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsCompositeKey: [value]
         * * idcsSearchable: true
         * * multiValued: true
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: complex
         * 
         * @return builder
         * 
         */
        public Builder appResources(@Nullable Output<List<DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppAppAppResourceArgs>> appResources) {
            $.appResources = appResources;
            return this;
        }

        /**
         * @param appResources (Updatable) A list of AppResources of this App.
         * 
         * **Added In:** 19.2.1
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsCompositeKey: [value]
         * * idcsSearchable: true
         * * multiValued: true
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: complex
         * 
         * @return builder
         * 
         */
        public Builder appResources(List<DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppAppAppResourceArgs> appResources) {
            return appResources(Output.of(appResources));
        }

        /**
         * @param appResources (Updatable) A list of AppResources of this App.
         * 
         * **Added In:** 19.2.1
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsCompositeKey: [value]
         * * idcsSearchable: true
         * * multiValued: true
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: complex
         * 
         * @return builder
         * 
         */
        public Builder appResources(DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppAppAppResourceArgs... appResources) {
            return appResources(List.of(appResources));
        }

        /**
         * @param denyAuthzDecisionTtl (Updatable) Deny Authz policy decision expiry time in seconds.
         * 
         * **Added In:** 19.2.1
         * 
         * **SCIM++ Properties:**
         * * idcsMaxValue: 3600
         * * idcsMinValue: 0
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: integer
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder denyAuthzDecisionTtl(@Nullable Output<Integer> denyAuthzDecisionTtl) {
            $.denyAuthzDecisionTtl = denyAuthzDecisionTtl;
            return this;
        }

        /**
         * @param denyAuthzDecisionTtl (Updatable) Deny Authz policy decision expiry time in seconds.
         * 
         * **Added In:** 19.2.1
         * 
         * **SCIM++ Properties:**
         * * idcsMaxValue: 3600
         * * idcsMinValue: 0
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: integer
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder denyAuthzDecisionTtl(Integer denyAuthzDecisionTtl) {
            return denyAuthzDecisionTtl(Output.of(denyAuthzDecisionTtl));
        }

        /**
         * @param denyAuthzPolicy (Updatable) Deny Authz Policy.
         * 
         * **Added In:** 19.2.1
         * 
         * **SCIM++ Properties:**
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: complex
         * 
         * @return builder
         * 
         */
        public Builder denyAuthzPolicy(@Nullable Output<DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppAppDenyAuthzPolicyArgs> denyAuthzPolicy) {
            $.denyAuthzPolicy = denyAuthzPolicy;
            return this;
        }

        /**
         * @param denyAuthzPolicy (Updatable) Deny Authz Policy.
         * 
         * **Added In:** 19.2.1
         * 
         * **SCIM++ Properties:**
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: complex
         * 
         * @return builder
         * 
         */
        public Builder denyAuthzPolicy(DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppAppDenyAuthzPolicyArgs denyAuthzPolicy) {
            return denyAuthzPolicy(Output.of(denyAuthzPolicy));
        }

        public DomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppAppArgs build() {
            return $;
        }
    }

}