// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.ContainerEngine.inputs.GetWorkRequestLogEntriesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetWorkRequestLogEntriesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetWorkRequestLogEntriesArgs Empty = new GetWorkRequestLogEntriesArgs();

    /**
     * The OCID of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The OCID of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable Output<List<GetWorkRequestLogEntriesFilterArgs>> filters;

    public Optional<Output<List<GetWorkRequestLogEntriesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The OCID of the work request.
     * 
     */
    @Import(name="workRequestId", required=true)
    private Output<String> workRequestId;

    /**
     * @return The OCID of the work request.
     * 
     */
    public Output<String> workRequestId() {
        return this.workRequestId;
    }

    private GetWorkRequestLogEntriesArgs() {}

    private GetWorkRequestLogEntriesArgs(GetWorkRequestLogEntriesArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.workRequestId = $.workRequestId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetWorkRequestLogEntriesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetWorkRequestLogEntriesArgs $;

        public Builder() {
            $ = new GetWorkRequestLogEntriesArgs();
        }

        public Builder(GetWorkRequestLogEntriesArgs defaults) {
            $ = new GetWorkRequestLogEntriesArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public Builder filters(@Nullable Output<List<GetWorkRequestLogEntriesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetWorkRequestLogEntriesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetWorkRequestLogEntriesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param workRequestId The OCID of the work request.
         * 
         * @return builder
         * 
         */
        public Builder workRequestId(Output<String> workRequestId) {
            $.workRequestId = workRequestId;
            return this;
        }

        /**
         * @param workRequestId The OCID of the work request.
         * 
         * @return builder
         * 
         */
        public Builder workRequestId(String workRequestId) {
            return workRequestId(Output.of(workRequestId));
        }

        public GetWorkRequestLogEntriesArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.workRequestId = Objects.requireNonNull($.workRequestId, "expected parameter 'workRequestId' to be non-null");
            return $;
        }
    }

}