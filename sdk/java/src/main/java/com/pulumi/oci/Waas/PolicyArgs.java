// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waas;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Waas.inputs.PolicyOriginArgs;
import com.pulumi.oci.Waas.inputs.PolicyOriginGroupArgs;
import com.pulumi.oci.Waas.inputs.PolicyPolicyConfigArgs;
import com.pulumi.oci.Waas.inputs.PolicyWafConfigArgs;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class PolicyArgs extends com.pulumi.resources.ResourceArgs {

    public static final PolicyArgs Empty = new PolicyArgs();

    /**
     * (Updatable) An array of additional domains for the specified web application.
     * 
     */
    @Import(name="additionalDomains")
    private @Nullable Output<List<String>> additionalDomains;

    /**
     * @return (Updatable) An array of additional domains for the specified web application.
     * 
     */
    public Optional<Output<List<String>>> additionalDomains() {
        return Optional.ofNullable(this.additionalDomains);
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the WAAS policy.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the WAAS policy.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) A user-friendly name for the WAAS policy. The name can be changed and does not need to be unique.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name for the WAAS policy. The name can be changed and does not need to be unique.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * (Updatable) The domain for which the cookie is set, defaults to WAAS policy domain.
     * 
     */
    @Import(name="domain", required=true)
    private Output<String> domain;

    /**
     * @return (Updatable) The domain for which the cookie is set, defaults to WAAS policy domain.
     * 
     */
    public Output<String> domain() {
        return this.domain;
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) The map of origin groups and their keys used to associate origins to the `wafConfig`. Origin groups allow you to apply weights to groups of origins for load balancing purposes. Origins with higher weights will receive larger proportions of client requests. To add additional origins to your WAAS policy, update the `origins` field of a `UpdateWaasPolicy` request.
     * 
     */
    @Import(name="originGroups")
    private @Nullable Output<List<PolicyOriginGroupArgs>> originGroups;

    /**
     * @return (Updatable) The map of origin groups and their keys used to associate origins to the `wafConfig`. Origin groups allow you to apply weights to groups of origins for load balancing purposes. Origins with higher weights will receive larger proportions of client requests. To add additional origins to your WAAS policy, update the `origins` field of a `UpdateWaasPolicy` request.
     * 
     */
    public Optional<Output<List<PolicyOriginGroupArgs>>> originGroups() {
        return Optional.ofNullable(this.originGroups);
    }

    /**
     * (Updatable) A map of host to origin for the web application. The key should be a customer friendly name for the host, ex. primary, secondary, etc.
     * 
     */
    @Import(name="origins")
    private @Nullable Output<List<PolicyOriginArgs>> origins;

    /**
     * @return (Updatable) A map of host to origin for the web application. The key should be a customer friendly name for the host, ex. primary, secondary, etc.
     * 
     */
    public Optional<Output<List<PolicyOriginArgs>>> origins() {
        return Optional.ofNullable(this.origins);
    }

    /**
     * (Updatable) The configuration details for the WAAS policy.
     * 
     */
    @Import(name="policyConfig")
    private @Nullable Output<PolicyPolicyConfigArgs> policyConfig;

    /**
     * @return (Updatable) The configuration details for the WAAS policy.
     * 
     */
    public Optional<Output<PolicyPolicyConfigArgs>> policyConfig() {
        return Optional.ofNullable(this.policyConfig);
    }

    /**
     * (Updatable) The Web Application Firewall configuration for the WAAS policy creation.
     * 
     */
    @Import(name="wafConfig")
    private @Nullable Output<PolicyWafConfigArgs> wafConfig;

    /**
     * @return (Updatable) The Web Application Firewall configuration for the WAAS policy creation.
     * 
     */
    public Optional<Output<PolicyWafConfigArgs>> wafConfig() {
        return Optional.ofNullable(this.wafConfig);
    }

    private PolicyArgs() {}

    private PolicyArgs(PolicyArgs $) {
        this.additionalDomains = $.additionalDomains;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.domain = $.domain;
        this.freeformTags = $.freeformTags;
        this.originGroups = $.originGroups;
        this.origins = $.origins;
        this.policyConfig = $.policyConfig;
        this.wafConfig = $.wafConfig;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(PolicyArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private PolicyArgs $;

        public Builder() {
            $ = new PolicyArgs();
        }

        public Builder(PolicyArgs defaults) {
            $ = new PolicyArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param additionalDomains (Updatable) An array of additional domains for the specified web application.
         * 
         * @return builder
         * 
         */
        public Builder additionalDomains(@Nullable Output<List<String>> additionalDomains) {
            $.additionalDomains = additionalDomains;
            return this;
        }

        /**
         * @param additionalDomains (Updatable) An array of additional domains for the specified web application.
         * 
         * @return builder
         * 
         */
        public Builder additionalDomains(List<String> additionalDomains) {
            return additionalDomains(Output.of(additionalDomains));
        }

        /**
         * @param additionalDomains (Updatable) An array of additional domains for the specified web application.
         * 
         * @return builder
         * 
         */
        public Builder additionalDomains(String... additionalDomains) {
            return additionalDomains(List.of(additionalDomains));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the WAAS policy.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the WAAS policy.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName (Updatable) A user-friendly name for the WAAS policy. The name can be changed and does not need to be unique.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A user-friendly name for the WAAS policy. The name can be changed and does not need to be unique.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param domain (Updatable) The domain for which the cookie is set, defaults to WAAS policy domain.
         * 
         * @return builder
         * 
         */
        public Builder domain(Output<String> domain) {
            $.domain = domain;
            return this;
        }

        /**
         * @param domain (Updatable) The domain for which the cookie is set, defaults to WAAS policy domain.
         * 
         * @return builder
         * 
         */
        public Builder domain(String domain) {
            return domain(Output.of(domain));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param originGroups (Updatable) The map of origin groups and their keys used to associate origins to the `wafConfig`. Origin groups allow you to apply weights to groups of origins for load balancing purposes. Origins with higher weights will receive larger proportions of client requests. To add additional origins to your WAAS policy, update the `origins` field of a `UpdateWaasPolicy` request.
         * 
         * @return builder
         * 
         */
        public Builder originGroups(@Nullable Output<List<PolicyOriginGroupArgs>> originGroups) {
            $.originGroups = originGroups;
            return this;
        }

        /**
         * @param originGroups (Updatable) The map of origin groups and their keys used to associate origins to the `wafConfig`. Origin groups allow you to apply weights to groups of origins for load balancing purposes. Origins with higher weights will receive larger proportions of client requests. To add additional origins to your WAAS policy, update the `origins` field of a `UpdateWaasPolicy` request.
         * 
         * @return builder
         * 
         */
        public Builder originGroups(List<PolicyOriginGroupArgs> originGroups) {
            return originGroups(Output.of(originGroups));
        }

        /**
         * @param originGroups (Updatable) The map of origin groups and their keys used to associate origins to the `wafConfig`. Origin groups allow you to apply weights to groups of origins for load balancing purposes. Origins with higher weights will receive larger proportions of client requests. To add additional origins to your WAAS policy, update the `origins` field of a `UpdateWaasPolicy` request.
         * 
         * @return builder
         * 
         */
        public Builder originGroups(PolicyOriginGroupArgs... originGroups) {
            return originGroups(List.of(originGroups));
        }

        /**
         * @param origins (Updatable) A map of host to origin for the web application. The key should be a customer friendly name for the host, ex. primary, secondary, etc.
         * 
         * @return builder
         * 
         */
        public Builder origins(@Nullable Output<List<PolicyOriginArgs>> origins) {
            $.origins = origins;
            return this;
        }

        /**
         * @param origins (Updatable) A map of host to origin for the web application. The key should be a customer friendly name for the host, ex. primary, secondary, etc.
         * 
         * @return builder
         * 
         */
        public Builder origins(List<PolicyOriginArgs> origins) {
            return origins(Output.of(origins));
        }

        /**
         * @param origins (Updatable) A map of host to origin for the web application. The key should be a customer friendly name for the host, ex. primary, secondary, etc.
         * 
         * @return builder
         * 
         */
        public Builder origins(PolicyOriginArgs... origins) {
            return origins(List.of(origins));
        }

        /**
         * @param policyConfig (Updatable) The configuration details for the WAAS policy.
         * 
         * @return builder
         * 
         */
        public Builder policyConfig(@Nullable Output<PolicyPolicyConfigArgs> policyConfig) {
            $.policyConfig = policyConfig;
            return this;
        }

        /**
         * @param policyConfig (Updatable) The configuration details for the WAAS policy.
         * 
         * @return builder
         * 
         */
        public Builder policyConfig(PolicyPolicyConfigArgs policyConfig) {
            return policyConfig(Output.of(policyConfig));
        }

        /**
         * @param wafConfig (Updatable) The Web Application Firewall configuration for the WAAS policy creation.
         * 
         * @return builder
         * 
         */
        public Builder wafConfig(@Nullable Output<PolicyWafConfigArgs> wafConfig) {
            $.wafConfig = wafConfig;
            return this;
        }

        /**
         * @param wafConfig (Updatable) The Web Application Firewall configuration for the WAAS policy creation.
         * 
         * @return builder
         * 
         */
        public Builder wafConfig(PolicyWafConfigArgs wafConfig) {
            return wafConfig(Output.of(wafConfig));
        }

        public PolicyArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.domain = Objects.requireNonNull($.domain, "expected parameter 'domain' to be non-null");
            return $;
        }
    }

}