// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Optimizer.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetEnrollmentStatusArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetEnrollmentStatusArgs Empty = new GetEnrollmentStatusArgs();

    /**
     * The unique OCID associated with the enrollment status.
     * 
     */
    @Import(name="enrollmentStatusId", required=true)
    private Output<String> enrollmentStatusId;

    /**
     * @return The unique OCID associated with the enrollment status.
     * 
     */
    public Output<String> enrollmentStatusId() {
        return this.enrollmentStatusId;
    }

    private GetEnrollmentStatusArgs() {}

    private GetEnrollmentStatusArgs(GetEnrollmentStatusArgs $) {
        this.enrollmentStatusId = $.enrollmentStatusId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetEnrollmentStatusArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetEnrollmentStatusArgs $;

        public Builder() {
            $ = new GetEnrollmentStatusArgs();
        }

        public Builder(GetEnrollmentStatusArgs defaults) {
            $ = new GetEnrollmentStatusArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param enrollmentStatusId The unique OCID associated with the enrollment status.
         * 
         * @return builder
         * 
         */
        public Builder enrollmentStatusId(Output<String> enrollmentStatusId) {
            $.enrollmentStatusId = enrollmentStatusId;
            return this;
        }

        /**
         * @param enrollmentStatusId The unique OCID associated with the enrollment status.
         * 
         * @return builder
         * 
         */
        public Builder enrollmentStatusId(String enrollmentStatusId) {
            return enrollmentStatusId(Output.of(enrollmentStatusId));
        }

        public GetEnrollmentStatusArgs build() {
            $.enrollmentStatusId = Objects.requireNonNull($.enrollmentStatusId, "expected parameter 'enrollmentStatusId' to be non-null");
            return $;
        }
    }

}