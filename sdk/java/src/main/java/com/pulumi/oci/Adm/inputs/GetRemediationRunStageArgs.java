// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Adm.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetRemediationRunStageArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetRemediationRunStageArgs Empty = new GetRemediationRunStageArgs();

    /**
     * Unique Remediation Run identifier path parameter.
     * 
     */
    @Import(name="remediationRunId", required=true)
    private Output<String> remediationRunId;

    /**
     * @return Unique Remediation Run identifier path parameter.
     * 
     */
    public Output<String> remediationRunId() {
        return this.remediationRunId;
    }

    /**
     * The type of Remediation Run Stage, as a URL path parameter.
     * 
     */
    @Import(name="stageType", required=true)
    private Output<String> stageType;

    /**
     * @return The type of Remediation Run Stage, as a URL path parameter.
     * 
     */
    public Output<String> stageType() {
        return this.stageType;
    }

    private GetRemediationRunStageArgs() {}

    private GetRemediationRunStageArgs(GetRemediationRunStageArgs $) {
        this.remediationRunId = $.remediationRunId;
        this.stageType = $.stageType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetRemediationRunStageArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetRemediationRunStageArgs $;

        public Builder() {
            $ = new GetRemediationRunStageArgs();
        }

        public Builder(GetRemediationRunStageArgs defaults) {
            $ = new GetRemediationRunStageArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param remediationRunId Unique Remediation Run identifier path parameter.
         * 
         * @return builder
         * 
         */
        public Builder remediationRunId(Output<String> remediationRunId) {
            $.remediationRunId = remediationRunId;
            return this;
        }

        /**
         * @param remediationRunId Unique Remediation Run identifier path parameter.
         * 
         * @return builder
         * 
         */
        public Builder remediationRunId(String remediationRunId) {
            return remediationRunId(Output.of(remediationRunId));
        }

        /**
         * @param stageType The type of Remediation Run Stage, as a URL path parameter.
         * 
         * @return builder
         * 
         */
        public Builder stageType(Output<String> stageType) {
            $.stageType = stageType;
            return this;
        }

        /**
         * @param stageType The type of Remediation Run Stage, as a URL path parameter.
         * 
         * @return builder
         * 
         */
        public Builder stageType(String stageType) {
            return stageType(Output.of(stageType));
        }

        public GetRemediationRunStageArgs build() {
            $.remediationRunId = Objects.requireNonNull($.remediationRunId, "expected parameter 'remediationRunId' to be non-null");
            $.stageType = Objects.requireNonNull($.stageType, "expected parameter 'stageType' to be non-null");
            return $;
        }
    }

}