// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataFlow.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetInvokeRunPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetInvokeRunPlainArgs Empty = new GetInvokeRunPlainArgs();

    /**
     * The unique ID for the run
     * 
     */
    @Import(name="runId", required=true)
    private String runId;

    /**
     * @return The unique ID for the run
     * 
     */
    public String runId() {
        return this.runId;
    }

    private GetInvokeRunPlainArgs() {}

    private GetInvokeRunPlainArgs(GetInvokeRunPlainArgs $) {
        this.runId = $.runId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetInvokeRunPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetInvokeRunPlainArgs $;

        public Builder() {
            $ = new GetInvokeRunPlainArgs();
        }

        public Builder(GetInvokeRunPlainArgs defaults) {
            $ = new GetInvokeRunPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param runId The unique ID for the run
         * 
         * @return builder
         * 
         */
        public Builder runId(String runId) {
            $.runId = runId;
            return this;
        }

        public GetInvokeRunPlainArgs build() {
            if ($.runId == null) {
                throw new MissingRequiredPropertyException("GetInvokeRunPlainArgs", "runId");
            }
            return $;
        }
    }

}
