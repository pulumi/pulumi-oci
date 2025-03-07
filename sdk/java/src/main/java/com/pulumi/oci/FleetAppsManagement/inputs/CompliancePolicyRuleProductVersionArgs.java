// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class CompliancePolicyRuleProductVersionArgs extends com.pulumi.resources.ResourceArgs {

    public static final CompliancePolicyRuleProductVersionArgs Empty = new CompliancePolicyRuleProductVersionArgs();

    /**
     * (Updatable) Is rule applicable to all higher versions also
     * 
     */
    @Import(name="isApplicableForAllHigherVersions")
    private @Nullable Output<Boolean> isApplicableForAllHigherVersions;

    /**
     * @return (Updatable) Is rule applicable to all higher versions also
     * 
     */
    public Optional<Output<Boolean>> isApplicableForAllHigherVersions() {
        return Optional.ofNullable(this.isApplicableForAllHigherVersions);
    }

    /**
     * (Updatable) Product version the rule is applicable.
     * 
     */
    @Import(name="version", required=true)
    private Output<String> version;

    /**
     * @return (Updatable) Product version the rule is applicable.
     * 
     */
    public Output<String> version() {
        return this.version;
    }

    private CompliancePolicyRuleProductVersionArgs() {}

    private CompliancePolicyRuleProductVersionArgs(CompliancePolicyRuleProductVersionArgs $) {
        this.isApplicableForAllHigherVersions = $.isApplicableForAllHigherVersions;
        this.version = $.version;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(CompliancePolicyRuleProductVersionArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private CompliancePolicyRuleProductVersionArgs $;

        public Builder() {
            $ = new CompliancePolicyRuleProductVersionArgs();
        }

        public Builder(CompliancePolicyRuleProductVersionArgs defaults) {
            $ = new CompliancePolicyRuleProductVersionArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param isApplicableForAllHigherVersions (Updatable) Is rule applicable to all higher versions also
         * 
         * @return builder
         * 
         */
        public Builder isApplicableForAllHigherVersions(@Nullable Output<Boolean> isApplicableForAllHigherVersions) {
            $.isApplicableForAllHigherVersions = isApplicableForAllHigherVersions;
            return this;
        }

        /**
         * @param isApplicableForAllHigherVersions (Updatable) Is rule applicable to all higher versions also
         * 
         * @return builder
         * 
         */
        public Builder isApplicableForAllHigherVersions(Boolean isApplicableForAllHigherVersions) {
            return isApplicableForAllHigherVersions(Output.of(isApplicableForAllHigherVersions));
        }

        /**
         * @param version (Updatable) Product version the rule is applicable.
         * 
         * @return builder
         * 
         */
        public Builder version(Output<String> version) {
            $.version = version;
            return this;
        }

        /**
         * @param version (Updatable) Product version the rule is applicable.
         * 
         * @return builder
         * 
         */
        public Builder version(String version) {
            return version(Output.of(version));
        }

        public CompliancePolicyRuleProductVersionArgs build() {
            if ($.version == null) {
                throw new MissingRequiredPropertyException("CompliancePolicyRuleProductVersionArgs", "version");
            }
            return $;
        }
    }

}
