// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Adm.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Adm.inputs.GetRemediationRunStagesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetRemediationRunStagesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetRemediationRunStagesArgs Empty = new GetRemediationRunStagesArgs();

    @Import(name="filters")
    private @Nullable Output<List<GetRemediationRunStagesFilterArgs>> filters;

    public Optional<Output<List<GetRemediationRunStagesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

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
     * A filter to return only Stages that match the specified status.
     * 
     */
    @Import(name="status")
    private @Nullable Output<String> status;

    /**
     * @return A filter to return only Stages that match the specified status.
     * 
     */
    public Optional<Output<String>> status() {
        return Optional.ofNullable(this.status);
    }

    /**
     * A filter to return only Stages that match the specified type.
     * 
     */
    @Import(name="type")
    private @Nullable Output<String> type;

    /**
     * @return A filter to return only Stages that match the specified type.
     * 
     */
    public Optional<Output<String>> type() {
        return Optional.ofNullable(this.type);
    }

    private GetRemediationRunStagesArgs() {}

    private GetRemediationRunStagesArgs(GetRemediationRunStagesArgs $) {
        this.filters = $.filters;
        this.remediationRunId = $.remediationRunId;
        this.status = $.status;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetRemediationRunStagesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetRemediationRunStagesArgs $;

        public Builder() {
            $ = new GetRemediationRunStagesArgs();
        }

        public Builder(GetRemediationRunStagesArgs defaults) {
            $ = new GetRemediationRunStagesArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable Output<List<GetRemediationRunStagesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetRemediationRunStagesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetRemediationRunStagesFilterArgs... filters) {
            return filters(List.of(filters));
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
         * @param status A filter to return only Stages that match the specified status.
         * 
         * @return builder
         * 
         */
        public Builder status(@Nullable Output<String> status) {
            $.status = status;
            return this;
        }

        /**
         * @param status A filter to return only Stages that match the specified status.
         * 
         * @return builder
         * 
         */
        public Builder status(String status) {
            return status(Output.of(status));
        }

        /**
         * @param type A filter to return only Stages that match the specified type.
         * 
         * @return builder
         * 
         */
        public Builder type(@Nullable Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type A filter to return only Stages that match the specified type.
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        public GetRemediationRunStagesArgs build() {
            $.remediationRunId = Objects.requireNonNull($.remediationRunId, "expected parameter 'remediationRunId' to be non-null");
            return $;
        }
    }

}