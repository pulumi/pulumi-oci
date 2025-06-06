// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseMigration.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetJobOutputPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetJobOutputPlainArgs Empty = new GetJobOutputPlainArgs();

    /**
     * The OCID of the job
     * 
     */
    @Import(name="jobId", required=true)
    private String jobId;

    /**
     * @return The OCID of the job
     * 
     */
    public String jobId() {
        return this.jobId;
    }

    private GetJobOutputPlainArgs() {}

    private GetJobOutputPlainArgs(GetJobOutputPlainArgs $) {
        this.jobId = $.jobId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetJobOutputPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetJobOutputPlainArgs $;

        public Builder() {
            $ = new GetJobOutputPlainArgs();
        }

        public Builder(GetJobOutputPlainArgs defaults) {
            $ = new GetJobOutputPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param jobId The OCID of the job
         * 
         * @return builder
         * 
         */
        public Builder jobId(String jobId) {
            $.jobId = jobId;
            return this;
        }

        public GetJobOutputPlainArgs build() {
            if ($.jobId == null) {
                throw new MissingRequiredPropertyException("GetJobOutputPlainArgs", "jobId");
            }
            return $;
        }
    }

}
