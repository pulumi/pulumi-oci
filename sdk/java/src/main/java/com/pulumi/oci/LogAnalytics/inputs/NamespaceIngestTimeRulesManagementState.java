// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class NamespaceIngestTimeRulesManagementState extends com.pulumi.resources.ResourceArgs {

    public static final NamespaceIngestTimeRulesManagementState Empty = new NamespaceIngestTimeRulesManagementState();

    /**
     * (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="enableIngestTimeRule")
    private @Nullable Output<Boolean> enableIngestTimeRule;

    /**
     * @return (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<Boolean>> enableIngestTimeRule() {
        return Optional.ofNullable(this.enableIngestTimeRule);
    }

    /**
     * Unique ocid of the ingest time rule.
     * 
     */
    @Import(name="ingestTimeRuleId")
    private @Nullable Output<String> ingestTimeRuleId;

    /**
     * @return Unique ocid of the ingest time rule.
     * 
     */
    public Optional<Output<String>> ingestTimeRuleId() {
        return Optional.ofNullable(this.ingestTimeRuleId);
    }

    /**
     * The Logging Analytics namespace used for the request.
     * 
     */
    @Import(name="namespace")
    private @Nullable Output<String> namespace;

    /**
     * @return The Logging Analytics namespace used for the request.
     * 
     */
    public Optional<Output<String>> namespace() {
        return Optional.ofNullable(this.namespace);
    }

    private NamespaceIngestTimeRulesManagementState() {}

    private NamespaceIngestTimeRulesManagementState(NamespaceIngestTimeRulesManagementState $) {
        this.enableIngestTimeRule = $.enableIngestTimeRule;
        this.ingestTimeRuleId = $.ingestTimeRuleId;
        this.namespace = $.namespace;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(NamespaceIngestTimeRulesManagementState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private NamespaceIngestTimeRulesManagementState $;

        public Builder() {
            $ = new NamespaceIngestTimeRulesManagementState();
        }

        public Builder(NamespaceIngestTimeRulesManagementState defaults) {
            $ = new NamespaceIngestTimeRulesManagementState(Objects.requireNonNull(defaults));
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
        public Builder enableIngestTimeRule(@Nullable Output<Boolean> enableIngestTimeRule) {
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
        public Builder ingestTimeRuleId(@Nullable Output<String> ingestTimeRuleId) {
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
        public Builder namespace(@Nullable Output<String> namespace) {
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

        public NamespaceIngestTimeRulesManagementState build() {
            return $;
        }
    }

}
