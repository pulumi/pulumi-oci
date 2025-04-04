// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;


public final class NamespaceIngestTimeRulesManagementArgs extends com.pulumi.resources.ResourceArgs {

    public static final NamespaceIngestTimeRulesManagementArgs Empty = new NamespaceIngestTimeRulesManagementArgs();

    /**
     * (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="enableIngestTimeRule", required=true)
    private Output<Boolean> enableIngestTimeRule;

    /**
     * @return (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<Boolean> enableIngestTimeRule() {
        return this.enableIngestTimeRule;
    }

    /**
     * Unique ocid of the ingest time rule.
     * 
     */
    @Import(name="ingestTimeRuleId", required=true)
    private Output<String> ingestTimeRuleId;

    /**
     * @return Unique ocid of the ingest time rule.
     * 
     */
    public Output<String> ingestTimeRuleId() {
        return this.ingestTimeRuleId;
    }

    /**
     * The Logging Analytics namespace used for the request.
     * 
     */
    @Import(name="namespace", required=true)
    private Output<String> namespace;

    /**
     * @return The Logging Analytics namespace used for the request.
     * 
     */
    public Output<String> namespace() {
        return this.namespace;
    }

    private NamespaceIngestTimeRulesManagementArgs() {}

    private NamespaceIngestTimeRulesManagementArgs(NamespaceIngestTimeRulesManagementArgs $) {
        this.enableIngestTimeRule = $.enableIngestTimeRule;
        this.ingestTimeRuleId = $.ingestTimeRuleId;
        this.namespace = $.namespace;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(NamespaceIngestTimeRulesManagementArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private NamespaceIngestTimeRulesManagementArgs $;

        public Builder() {
            $ = new NamespaceIngestTimeRulesManagementArgs();
        }

        public Builder(NamespaceIngestTimeRulesManagementArgs defaults) {
            $ = new NamespaceIngestTimeRulesManagementArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param enableIngestTimeRule (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder enableIngestTimeRule(Output<Boolean> enableIngestTimeRule) {
            $.enableIngestTimeRule = enableIngestTimeRule;
            return this;
        }

        /**
         * @param enableIngestTimeRule (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder enableIngestTimeRule(Boolean enableIngestTimeRule) {
            return enableIngestTimeRule(Output.of(enableIngestTimeRule));
        }

        /**
         * @param ingestTimeRuleId Unique ocid of the ingest time rule.
         * 
         * @return builder
         * 
         */
        public Builder ingestTimeRuleId(Output<String> ingestTimeRuleId) {
            $.ingestTimeRuleId = ingestTimeRuleId;
            return this;
        }

        /**
         * @param ingestTimeRuleId Unique ocid of the ingest time rule.
         * 
         * @return builder
         * 
         */
        public Builder ingestTimeRuleId(String ingestTimeRuleId) {
            return ingestTimeRuleId(Output.of(ingestTimeRuleId));
        }

        /**
         * @param namespace The Logging Analytics namespace used for the request.
         * 
         * @return builder
         * 
         */
        public Builder namespace(Output<String> namespace) {
            $.namespace = namespace;
            return this;
        }

        /**
         * @param namespace The Logging Analytics namespace used for the request.
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            return namespace(Output.of(namespace));
        }

        public NamespaceIngestTimeRulesManagementArgs build() {
            if ($.enableIngestTimeRule == null) {
                throw new MissingRequiredPropertyException("NamespaceIngestTimeRulesManagementArgs", "enableIngestTimeRule");
            }
            if ($.ingestTimeRuleId == null) {
                throw new MissingRequiredPropertyException("NamespaceIngestTimeRulesManagementArgs", "ingestTimeRuleId");
            }
            if ($.namespace == null) {
                throw new MissingRequiredPropertyException("NamespaceIngestTimeRulesManagementArgs", "namespace");
            }
            return $;
        }
    }

}
