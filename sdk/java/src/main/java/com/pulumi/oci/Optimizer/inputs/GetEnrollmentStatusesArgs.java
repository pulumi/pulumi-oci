// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Optimizer.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Optimizer.inputs.GetEnrollmentStatusesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetEnrollmentStatusesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetEnrollmentStatusesArgs Empty = new GetEnrollmentStatusesArgs();

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
    private @Nullable Output<List<GetEnrollmentStatusesFilterArgs>> filters;

    public Optional<Output<List<GetEnrollmentStatusesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter that returns results that match the lifecycle state specified.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return A filter that returns results that match the lifecycle state specified.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * A filter that returns results that match the Cloud Advisor enrollment status specified.
     * 
     */
    @Import(name="status")
    private @Nullable Output<String> status;

    /**
     * @return A filter that returns results that match the Cloud Advisor enrollment status specified.
     * 
     */
    public Optional<Output<String>> status() {
        return Optional.ofNullable(this.status);
    }

    private GetEnrollmentStatusesArgs() {}

    private GetEnrollmentStatusesArgs(GetEnrollmentStatusesArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.state = $.state;
        this.status = $.status;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetEnrollmentStatusesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetEnrollmentStatusesArgs $;

        public Builder() {
            $ = new GetEnrollmentStatusesArgs();
        }

        public Builder(GetEnrollmentStatusesArgs defaults) {
            $ = new GetEnrollmentStatusesArgs(Objects.requireNonNull(defaults));
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

        public Builder filters(@Nullable Output<List<GetEnrollmentStatusesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetEnrollmentStatusesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetEnrollmentStatusesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param state A filter that returns results that match the lifecycle state specified.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state A filter that returns results that match the lifecycle state specified.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param status A filter that returns results that match the Cloud Advisor enrollment status specified.
         * 
         * @return builder
         * 
         */
        public Builder status(@Nullable Output<String> status) {
            $.status = status;
            return this;
        }

        /**
         * @param status A filter that returns results that match the Cloud Advisor enrollment status specified.
         * 
         * @return builder
         * 
         */
        public Builder status(String status) {
            return status(Output.of(status));
        }

        public GetEnrollmentStatusesArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetEnrollmentStatusesArgs", "compartmentId");
            }
            return $;
        }
    }

}
