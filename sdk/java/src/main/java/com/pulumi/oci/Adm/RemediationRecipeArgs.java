// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Adm;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Adm.inputs.RemediationRecipeDetectConfigurationArgs;
import com.pulumi.oci.Adm.inputs.RemediationRecipeNetworkConfigurationArgs;
import com.pulumi.oci.Adm.inputs.RemediationRecipeScmConfigurationArgs;
import com.pulumi.oci.Adm.inputs.RemediationRecipeVerifyConfigurationArgs;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class RemediationRecipeArgs extends com.pulumi.resources.ResourceArgs {

    public static final RemediationRecipeArgs Empty = new RemediationRecipeArgs();

    /**
     * (Updatable) The compartment Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the remediation recipe.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The compartment Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the remediation recipe.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) A configuration to define the constraints when detecting vulnerable dependencies.
     * 
     */
    @Import(name="detectConfiguration", required=true)
    private Output<RemediationRecipeDetectConfigurationArgs> detectConfiguration;

    /**
     * @return (Updatable) A configuration to define the constraints when detecting vulnerable dependencies.
     * 
     */
    public Output<RemediationRecipeDetectConfigurationArgs> detectConfiguration() {
        return this.detectConfiguration;
    }

    /**
     * (Updatable) The name of the remediation recipe.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) The name of the remediation recipe.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) Boolean indicating if a run should be automatically triggered once the knowledge base is updated.
     * 
     */
    @Import(name="isRunTriggeredOnKbChange", required=true)
    private Output<Boolean> isRunTriggeredOnKbChange;

    /**
     * @return (Updatable) Boolean indicating if a run should be automatically triggered once the knowledge base is updated.
     * 
     */
    public Output<Boolean> isRunTriggeredOnKbChange() {
        return this.isRunTriggeredOnKbChange;
    }

    /**
     * (Updatable) The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the knowledge base.
     * 
     */
    @Import(name="knowledgeBaseId", required=true)
    private Output<String> knowledgeBaseId;

    /**
     * @return (Updatable) The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the knowledge base.
     * 
     */
    public Output<String> knowledgeBaseId() {
        return this.knowledgeBaseId;
    }

    /**
     * (Updatable) A network configuration defines the required network characteristics for an ADM remediation recipe. A network configuration is required if the build service is one of: GitHub Actions, GitLab Pipeline, or Jenkins Pipeline.
     * 
     */
    @Import(name="networkConfiguration", required=true)
    private Output<RemediationRecipeNetworkConfigurationArgs> networkConfiguration;

    /**
     * @return (Updatable) A network configuration defines the required network characteristics for an ADM remediation recipe. A network configuration is required if the build service is one of: GitHub Actions, GitLab Pipeline, or Jenkins Pipeline.
     * 
     */
    public Output<RemediationRecipeNetworkConfigurationArgs> networkConfiguration() {
        return this.networkConfiguration;
    }

    /**
     * (Updatable) A configuration for the Source Code Management tool/platform used by a remediation recipe.
     * 
     */
    @Import(name="scmConfiguration", required=true)
    private Output<RemediationRecipeScmConfigurationArgs> scmConfiguration;

    /**
     * @return (Updatable) A configuration for the Source Code Management tool/platform used by a remediation recipe.
     * 
     */
    public Output<RemediationRecipeScmConfigurationArgs> scmConfiguration() {
        return this.scmConfiguration;
    }

    /**
     * (Updatable) The target state for the Remediation Recipe. Could be set to `ACTIVE` or `INACTIVE`.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return (Updatable) The target state for the Remediation Recipe. Could be set to `ACTIVE` or `INACTIVE`.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * (Updatable) The Verify stage configuration specifies a build service to run a pipeline for the recommended code changes. The build pipeline will be initiated to ensure that there is no breaking change after the dependency versions have been updated in source to avoid vulnerabilities.
     * 
     */
    @Import(name="verifyConfiguration", required=true)
    private Output<RemediationRecipeVerifyConfigurationArgs> verifyConfiguration;

    /**
     * @return (Updatable) The Verify stage configuration specifies a build service to run a pipeline for the recommended code changes. The build pipeline will be initiated to ensure that there is no breaking change after the dependency versions have been updated in source to avoid vulnerabilities.
     * 
     */
    public Output<RemediationRecipeVerifyConfigurationArgs> verifyConfiguration() {
        return this.verifyConfiguration;
    }

    private RemediationRecipeArgs() {}

    private RemediationRecipeArgs(RemediationRecipeArgs $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.detectConfiguration = $.detectConfiguration;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.isRunTriggeredOnKbChange = $.isRunTriggeredOnKbChange;
        this.knowledgeBaseId = $.knowledgeBaseId;
        this.networkConfiguration = $.networkConfiguration;
        this.scmConfiguration = $.scmConfiguration;
        this.state = $.state;
        this.verifyConfiguration = $.verifyConfiguration;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(RemediationRecipeArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private RemediationRecipeArgs $;

        public Builder() {
            $ = new RemediationRecipeArgs();
        }

        public Builder(RemediationRecipeArgs defaults) {
            $ = new RemediationRecipeArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) The compartment Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the remediation recipe.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The compartment Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the remediation recipe.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param detectConfiguration (Updatable) A configuration to define the constraints when detecting vulnerable dependencies.
         * 
         * @return builder
         * 
         */
        public Builder detectConfiguration(Output<RemediationRecipeDetectConfigurationArgs> detectConfiguration) {
            $.detectConfiguration = detectConfiguration;
            return this;
        }

        /**
         * @param detectConfiguration (Updatable) A configuration to define the constraints when detecting vulnerable dependencies.
         * 
         * @return builder
         * 
         */
        public Builder detectConfiguration(RemediationRecipeDetectConfigurationArgs detectConfiguration) {
            return detectConfiguration(Output.of(detectConfiguration));
        }

        /**
         * @param displayName (Updatable) The name of the remediation recipe.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) The name of the remediation recipe.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param isRunTriggeredOnKbChange (Updatable) Boolean indicating if a run should be automatically triggered once the knowledge base is updated.
         * 
         * @return builder
         * 
         */
        public Builder isRunTriggeredOnKbChange(Output<Boolean> isRunTriggeredOnKbChange) {
            $.isRunTriggeredOnKbChange = isRunTriggeredOnKbChange;
            return this;
        }

        /**
         * @param isRunTriggeredOnKbChange (Updatable) Boolean indicating if a run should be automatically triggered once the knowledge base is updated.
         * 
         * @return builder
         * 
         */
        public Builder isRunTriggeredOnKbChange(Boolean isRunTriggeredOnKbChange) {
            return isRunTriggeredOnKbChange(Output.of(isRunTriggeredOnKbChange));
        }

        /**
         * @param knowledgeBaseId (Updatable) The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the knowledge base.
         * 
         * @return builder
         * 
         */
        public Builder knowledgeBaseId(Output<String> knowledgeBaseId) {
            $.knowledgeBaseId = knowledgeBaseId;
            return this;
        }

        /**
         * @param knowledgeBaseId (Updatable) The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the knowledge base.
         * 
         * @return builder
         * 
         */
        public Builder knowledgeBaseId(String knowledgeBaseId) {
            return knowledgeBaseId(Output.of(knowledgeBaseId));
        }

        /**
         * @param networkConfiguration (Updatable) A network configuration defines the required network characteristics for an ADM remediation recipe. A network configuration is required if the build service is one of: GitHub Actions, GitLab Pipeline, or Jenkins Pipeline.
         * 
         * @return builder
         * 
         */
        public Builder networkConfiguration(Output<RemediationRecipeNetworkConfigurationArgs> networkConfiguration) {
            $.networkConfiguration = networkConfiguration;
            return this;
        }

        /**
         * @param networkConfiguration (Updatable) A network configuration defines the required network characteristics for an ADM remediation recipe. A network configuration is required if the build service is one of: GitHub Actions, GitLab Pipeline, or Jenkins Pipeline.
         * 
         * @return builder
         * 
         */
        public Builder networkConfiguration(RemediationRecipeNetworkConfigurationArgs networkConfiguration) {
            return networkConfiguration(Output.of(networkConfiguration));
        }

        /**
         * @param scmConfiguration (Updatable) A configuration for the Source Code Management tool/platform used by a remediation recipe.
         * 
         * @return builder
         * 
         */
        public Builder scmConfiguration(Output<RemediationRecipeScmConfigurationArgs> scmConfiguration) {
            $.scmConfiguration = scmConfiguration;
            return this;
        }

        /**
         * @param scmConfiguration (Updatable) A configuration for the Source Code Management tool/platform used by a remediation recipe.
         * 
         * @return builder
         * 
         */
        public Builder scmConfiguration(RemediationRecipeScmConfigurationArgs scmConfiguration) {
            return scmConfiguration(Output.of(scmConfiguration));
        }

        /**
         * @param state (Updatable) The target state for the Remediation Recipe. Could be set to `ACTIVE` or `INACTIVE`.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state (Updatable) The target state for the Remediation Recipe. Could be set to `ACTIVE` or `INACTIVE`.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param verifyConfiguration (Updatable) The Verify stage configuration specifies a build service to run a pipeline for the recommended code changes. The build pipeline will be initiated to ensure that there is no breaking change after the dependency versions have been updated in source to avoid vulnerabilities.
         * 
         * @return builder
         * 
         */
        public Builder verifyConfiguration(Output<RemediationRecipeVerifyConfigurationArgs> verifyConfiguration) {
            $.verifyConfiguration = verifyConfiguration;
            return this;
        }

        /**
         * @param verifyConfiguration (Updatable) The Verify stage configuration specifies a build service to run a pipeline for the recommended code changes. The build pipeline will be initiated to ensure that there is no breaking change after the dependency versions have been updated in source to avoid vulnerabilities.
         * 
         * @return builder
         * 
         */
        public Builder verifyConfiguration(RemediationRecipeVerifyConfigurationArgs verifyConfiguration) {
            return verifyConfiguration(Output.of(verifyConfiguration));
        }

        public RemediationRecipeArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.detectConfiguration = Objects.requireNonNull($.detectConfiguration, "expected parameter 'detectConfiguration' to be non-null");
            $.isRunTriggeredOnKbChange = Objects.requireNonNull($.isRunTriggeredOnKbChange, "expected parameter 'isRunTriggeredOnKbChange' to be non-null");
            $.knowledgeBaseId = Objects.requireNonNull($.knowledgeBaseId, "expected parameter 'knowledgeBaseId' to be non-null");
            $.networkConfiguration = Objects.requireNonNull($.networkConfiguration, "expected parameter 'networkConfiguration' to be non-null");
            $.scmConfiguration = Objects.requireNonNull($.scmConfiguration, "expected parameter 'scmConfiguration' to be non-null");
            $.verifyConfiguration = Objects.requireNonNull($.verifyConfiguration, "expected parameter 'verifyConfiguration' to be non-null");
            return $;
        }
    }

}