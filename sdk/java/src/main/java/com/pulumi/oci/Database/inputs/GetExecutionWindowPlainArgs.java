// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetExecutionWindowPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetExecutionWindowPlainArgs Empty = new GetExecutionWindowPlainArgs();

    /**
     * The execution window [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="executionWindowId", required=true)
    private String executionWindowId;

    /**
     * @return The execution window [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public String executionWindowId() {
        return this.executionWindowId;
    }

    private GetExecutionWindowPlainArgs() {}

    private GetExecutionWindowPlainArgs(GetExecutionWindowPlainArgs $) {
        this.executionWindowId = $.executionWindowId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetExecutionWindowPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetExecutionWindowPlainArgs $;

        public Builder() {
            $ = new GetExecutionWindowPlainArgs();
        }

        public Builder(GetExecutionWindowPlainArgs defaults) {
            $ = new GetExecutionWindowPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param executionWindowId The execution window [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder executionWindowId(String executionWindowId) {
            $.executionWindowId = executionWindowId;
            return this;
        }

        public GetExecutionWindowPlainArgs build() {
            if ($.executionWindowId == null) {
                throw new MissingRequiredPropertyException("GetExecutionWindowPlainArgs", "executionWindowId");
            }
            return $;
        }
    }

}
